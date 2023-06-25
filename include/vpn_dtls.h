#ifndef __VPN_DTLS_H_CR4__
#define __VPN_DTLS_H_CR4__

#include <sys/socket.h>			/* for sockaddr_storage	*/
#include <openssl/ssl.h>		/* for SSL		*/

#define CLI_CERT_FILE	"certs/client-cert.pem"
#define CLI_KEY_FILE	"certs/client-key.pem"
#define SRV_CERT_FILE	"certs/server-cert.pem"
#define SRV_KEY_FILE	"certs/server-key.pem"

typedef struct pass_info 
{
	struct sockaddr_storage server_addr;
	struct sockaddr_storage client_addr;
	SSL *ssl;
	int tun_fd;
	int udp_fd;
	int max_fd;
} pass_info_t;

/*
 * reviewer:	Nave Tahar
 * status:	Approved
 */

void StartServer(int port, pass_info_t *info, int verb);
void ShutDownDtlsServer(pass_info_t *info);

void StartClient(char *remote_address, int port,
		 pass_info_t *info, int verb);
void ShutdownDtlsClient(pass_info_t *info);

void ESSL_read(SSL *ssl, void *buf, int num, int *n_bytes);
void ESSL_write(SSL *ssl, void *buf, int *n_bytes);

#endif /*__VPN_DTLS_H_CR4__*/
