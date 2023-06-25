#define _POSIX_C_SOURCE 200112L
#include <stdio.h>		/* for perror		*/
#include <strings.h>		/* for bzero		*/
#include <sys/select.h>		/* for select		*/
#include <sys/socket.h>		/* for socket		*/
#include <unistd.h>		/* for close		*/
#include <signal.h>		/* for sigaction	*/

#include "../include/socket_utils.h"
#include "../include/vpn_utils.h"
#include "../include/vpn.h"
#include "../include/vpn_dtls.h"

typedef struct sockaddr_in sai_t;
typedef struct sockaddr sa_t;

#define BUFFER_SIZE    (1<<16)
#define CMD_LINE	256
#define MAX_RETRY	10
#define TIMEOUT		2
#define MAX(a, b) ((a) > (b) ? (a) : (b))

sig_atomic_t g_run = 1;

/*
 * reviewer:	Nave Tahar
 * status:	Approved
 */
void HandleSig(int signo)
{
	if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM)
	{
		printf("exiting...");
		g_run = 0;
	}
}

void SetSigHandler()
{
	struct sigaction sa = { 0 };
	sa.sa_handler	= &HandleSig;
	sigfillset(&sa.sa_mask);

	if (0 > sigaction(SIGHUP, &sa, NULL)) {
		perror("Cannot handle SIGHUP");
	}
	if (0 > sigaction(SIGINT, &sa, NULL)) {
		perror("Cannot handle SIGINT");
	}
	if (0 > sigaction(SIGTERM, &sa, NULL)) {
		perror("Cannot handle SIGTERM");
	}
}

static void EventLoop(pass_info_t *info)
{
	fd_set readset	= { 0 };
	char buff[MTU]	= { 0 };
	int n_bytes	= 0;
	int bio_fd	= info->udp_fd;

	info->max_fd = MAX(info->udp_fd, info->tun_fd);
	while (g_run)
	{
		FD_ZERO(&readset);
		FD_SET(bio_fd, &readset);
		FD_SET(info->tun_fd, &readset);
		Select(info->max_fd + 1, &readset, NULL, NULL, NULL);
		if (FD_ISSET(bio_fd, &readset))
		{
			bzero(buff, sizeof(buff));
			ESSL_read(info->ssl, buff, sizeof(buff), &n_bytes);
			n_bytes = Write(info->tun_fd, buff, n_bytes);
		}
		if (FD_ISSET(info->tun_fd, &readset))
		{
			bzero(buff, sizeof(buff));
			n_bytes = Read(info->tun_fd, buff, sizeof(buff));	
			/* encrypt */
			ESSL_write(info->ssl, buff, &n_bytes);
		}
	}
}

void VPNClient(char *srv_host, long srv_port, int verbose)
{
	pass_info_t info = { 0 };

/*	create dtls 	*/
	StartClient(srv_host, srv_port, &info, verbose);

	info.tun_fd = AllocTUN(TUN_NAME);
	ConfigTUN(TUN_CLI_ADDR, TUN_NAME, MTU);
	ConfigRoutes(CLI_E, ADD_E, NULL, srv_host, TUN_NAME);
	RunCmd("echo '1' > /proc/sys/net/ipv4/ip_forward");

	SetSigHandler();
	EventLoop(&info);

	ShutdownDtlsClient(&info);
	ConfigRoutes(CLI_E, DEL_E, NULL, srv_host, TUN_NAME);
	close(info.tun_fd);
}

void VPNSrver(long srv_port, int verbose)
{
	pass_info_t info = { 0 };

/*	create dtls 	*/
	StartServer(srv_port, &info, verbose);

	info.tun_fd = AllocTUN(TUN_NAME);
	ConfigTUN(TUN_SRV_ADDR, TUN_NAME, MTU);
	ConfigNAT('I', TUN_NET_ADDR);
	RunCmd("echo '1' > /proc/sys/net/ipv4/ip_forward");
	SetSigHandler();

	EventLoop(&info);
	
	ShutDownDtlsServer(&info);
	fputs("client FIN", stdout);
	ConfigRoutes(SRV_E, DEL_E, TUN_NET_ADDR, NULL, TUN_NAME);
	ConfigNAT('D', TUN_NET_ADDR);

	close(info.tun_fd);
}

