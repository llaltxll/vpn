#include <linux/if.h>		/* for ifreq		*/
#include <linux/if_tun.h>	/* for IFF_TUN		*/
#include <fcntl.h>		/* for O_RFWR		*/
#include <strings.h>		/* for bzero		*/
#include <string.h>		/* for strncpy		*/
#include <sys/ioctl.h>		/* for ioctl		*/
#include <stdlib.h>		/* for system		*/
#include <stdio.h>		/* for perror		*/
#include <sys/signal.h>		/* for sighandling	*/

#include "../include/socket_utils.h"
#include "../include/vpn_utils.h"

#define CMD_LINE	256

int AllocTUN(char *tun_name)
{
	struct ifreq ifr;
	int fd;

	fd = Open("/dev/net/tun", O_RDWR);
	bzero(&ifr, sizeof(ifr));

	/* TUN interface with IPV4/6 deduction */
	ifr.ifr_flags	= IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, tun_name, IFNAMSIZ);
	Ioctl(fd, TUNSETIFF, (void *)&ifr);

	return fd;	
}

void RunCmd(char *cmd)
{
	if (system(cmd))
	{
		perror(cmd);
/* 		exit(-1); */
	}
}

void ConfigTUN(char *tun_addr, char *tun_name, int mtu)
{
	char cmd[CMD_LINE] = { 0 };

	sprintf(cmd, "ip link set %s mtu %d up", tun_name, mtu);
	RunCmd(cmd);
	sprintf(cmd, "ip address add %s dev %s", tun_addr, tun_name);
	RunCmd(cmd);
}

void ConfigNAT(char action, char *tun_net_addr)
{
	char cmd[CMD_LINE] = { 0 };

	sprintf(cmd, "iptables -t nat -%c POSTROUTING -s %s ! -d %s -m comment "
		"--comment 'cr4vpn' -j MASQUERADE", action, tun_net_addr,
		tun_net_addr);
	RunCmd(cmd);
}
void ConfigRoutes(agen_e_t agent, action_e_t action, char* gw,
			 char *srv_addr, char * tun_name)
{
	char cmd[CMD_LINE] = { 0 };
	char *del	= "del";
	char *add	= "add";
	char *act_str	= NULL;

	switch (action) 
	{
		case ADD_E:
			act_str = add;	
			break;
		case DEL_E:
			act_str = del; break;
	}
	switch (agent) 
	{
		case SRV_E:
			sprintf(cmd, "ip route %s %s dev %s", act_str,
			   gw, tun_name);
			RunCmd(cmd);
			break;
		case CLI_E:
			sprintf(cmd, "ip route %s 0/1 dev %s", act_str, tun_name);
			RunCmd(cmd);
			sprintf(cmd, "ip route %s 128/1 dev %s", act_str, tun_name);
			RunCmd(cmd);
			sprintf(cmd, "ip route %s %s via %s", act_str, srv_addr,
			"$(ip route show 0/0 | awk '{print $3}' | head -n 1)");
			RunCmd(cmd);
			break;
	}
}

