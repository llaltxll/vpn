
#include <netinet/in.h>			/* for sockaddr_in	*/
#include <sys/socket.h>			/* for socket		*/
#include <arpa/inet.h>			/* for inet_pton	*/
#include <unistd.h>			/* for close		*/
#include <strings.h>			/* for bzero		*/


#include <openssl/ssl.h>		/* for SSL		*/
#include <openssl/rand.h>		/* for RAND_bytes	*/
#include <openssl/err.h>		/* for ERR_error_string	*/

#include "../include/socket_utils.h"
#include "../include/vpn_dtls.h"

#define COOKIE_SECRET_LENGTH 16
#define BUFFER_SIZE          (1<<16)

typedef struct sockaddr_in sai_t;
typedef struct sockaddr sa_t;

unsigned char g_cookie_secret[COOKIE_SECRET_LENGTH] = { 0 };
int g_verbose			= 0;
int g_cookie_initialized	= 0;

/*
 * reviewer:	Nave Tahar
 * status:	Approved
 */
static int ESSL_connect(SSL *ssl)
{
	int retval	= 0;

	retval = SSL_connect(ssl);
	if (retval <= 0) {
		switch (SSL_get_error(ssl, retval)) {
			case SSL_ERROR_ZERO_RETURN:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_ZERO_RETURN\n");
				break;
			case SSL_ERROR_WANT_READ:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_READ\n");
				break;
			case SSL_ERROR_WANT_WRITE:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_WRITE\n");
				break;
			case SSL_ERROR_WANT_CONNECT:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_CONNECT\n");
				break;
			case SSL_ERROR_WANT_ACCEPT:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_ACCEPT\n");
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_X509_LOOKUP\n");
				break;
			case SSL_ERROR_SYSCALL:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_SYSCALL\n");
				break;
			case SSL_ERROR_SSL:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_SSL\n");
				break;
			default:
				fprintf(stderr, "SSL_connect failed with unknown error\n");
				break;
		}
		exit(EXIT_FAILURE);
	}

	return retval;
}
static void DryCookie(SSL *ssl, unsigned char *buffer, unsigned char *result, unsigned int *resultlength)
{
    unsigned int length                     = 0;
    sai_t peer                              = { 0 };

    /* Read peer information */
    BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length  = 0;
    length += sizeof(struct in_addr);
    length += sizeof(in_port_t);
    buffer  = (unsigned char*) OPENSSL_malloc(length);
    if (!buffer)
    {
        printf("out of memory\n");
        exit(-1);
    }

    memcpy(buffer, &peer.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.sin_port), &peer.sin_addr, sizeof(struct in_addr));

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) g_cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char*) buffer, length, result, resultlength);

    OPENSSL_free(buffer);
}

static int GenerateCookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned char result[EVP_MAX_MD_SIZE]   = { 0 };
    unsigned char *buffer                   = NULL;
    unsigned int resultlength               = 0;

    /* Initialize a random secret */
    if (!g_cookie_initialized)
    {
        if (!RAND_bytes(g_cookie_secret, COOKIE_SECRET_LENGTH))
        {
            printf("error setting random cookie secret\n");
            return 0;
        }
        g_cookie_initialized = 1;
    }
    DryCookie(ssl, buffer, result, &resultlength);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

static int VerifyCookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    unsigned char result[EVP_MAX_MD_SIZE]   = { 0 };
    unsigned char *buffer                   = NULL;
    unsigned int resultlength               = 0;

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!g_cookie_initialized)
    {
        return 0;
    }
    DryCookie(ssl, buffer, result, &resultlength);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
    {
        return 1;
    }

    return 0;
}
static void ReadCreds(char *cert_file, char *key_file, SSL_CTX *ctx)
{
	if (!SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");
}
static void PrintInfo(pass_info_t *info)
{
	char addrbuf[INET_ADDRSTRLEN]	= { 0 };

	if (g_verbose) 
	{
		printf ("\naccepted connection from %s:%d\n",
				inet_ntop(AF_INET,
				&((sai_t*)&(info->client_addr))->sin_addr,
				addrbuf, INET_ADDRSTRLEN),
				ntohs(((sai_t*)&(info->client_addr))->sin_port));
	}
}

pass_info_t *ConnectionHandle(pass_info_t *info) {
	char buf[BUFFER_SIZE]		= { 0 };
	int fd				= 0;
	int ret				= 0;
	const int on			= 1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));

	if (bind(fd, (const struct sockaddr *) &info->server_addr, sizeof(struct sockaddr_in))) {
		perror("bind");
	}
	if (connect(fd, (struct sockaddr *) &info->client_addr, sizeof(struct sockaddr_in))) {
		perror("connect");
	}

	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(info->ssl), fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(info->ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &info->client_addr);

	/* Finish handshake */
	do 
	{
		ret = SSL_accept(info->ssl); 
	}
	while (ret == 0);
	if (ret < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
	}

	PrintInfo(info);

	info->udp_fd = fd;
	return info;
}
void StartServer(int port, pass_info_t *info, int verb) 
{
	int fd			= 0;
	sai_t server_addr	= { 0 };	
	sai_t client_addr	= { 0 };	
	SSL_CTX *ctx		= NULL;
	SSL *ssl		= NULL;
	BIO *bio		= NULL;
	const int on		= 1;

	g_verbose = verb;

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htons(INADDR_ANY);
	server_addr.sin_port = htons(port);

	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLS_server_method());

	ReadCreds(SRV_CERT_FILE, SRV_KEY_FILE, ctx);

	SSL_CTX_set_cookie_generate_cb(ctx, GenerateCookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &VerifyCookie);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (0 > fd) 
	{
		perror("socket");
		exit(-1);
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on,
	    (socklen_t)sizeof(on));

	if (bind(fd, (const struct sockaddr *) &server_addr,
	  sizeof(struct sockaddr_in)))
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}
	bzero(&client_addr, sizeof(client_addr));

	bio = BIO_new_dgram(fd, BIO_NOCLOSE);
	ssl = SSL_new(ctx);

	SSL_set_bio(ssl, bio, bio);

	while (0 >= DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr));

	memcpy(&info->server_addr, &server_addr, sizeof(server_addr));
	memcpy(&info->client_addr, &client_addr, sizeof(client_addr));

	info->ssl = ssl;
	ConnectionHandle(info);

}
void ESSL_read(SSL *ssl, void *buf, int num, int *n_bytes)
{
	*n_bytes = SSL_read(ssl, buf, num);

	switch (SSL_get_error(ssl, *n_bytes)) {
		case SSL_ERROR_NONE:
			if (g_verbose) 
			{
				printf("read %d bytes\n", *n_bytes);
			}
			break;
		case SSL_ERROR_WANT_READ:
			/* Handle socket timeouts */
			if (BIO_ctrl(SSL_get_rbio(ssl),
				BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) 
			{
				printf("Timeout! No response received.\n");
			}
			break;
		case SSL_ERROR_ZERO_RETURN:
			break;
		case SSL_ERROR_SYSCALL:
			printf("Socket read error: ");
			HandleSocketError();
			break;
		case SSL_ERROR_SSL:
			printf("SSL read error: ");
			printf("%s (%d)\n",
				ERR_error_string(ERR_get_error(), buf),
				SSL_get_error(ssl, *n_bytes));
			break;
		default:
			printf("Unexpected error while reading!\n");
			break;
	}
}
void ESSL_write(SSL *ssl, void *buf, int *n_bytes)
{
	*n_bytes = SSL_write(ssl, buf, *n_bytes);

	switch (SSL_get_error(ssl, *n_bytes)) {
		case SSL_ERROR_NONE:
			if (g_verbose) 
			{
				printf("wrote %d bytes\n", *n_bytes);
			}
			break;
		case SSL_ERROR_WANT_WRITE:
			 /* retry sending
			 */
			break;
		case SSL_ERROR_WANT_READ:
			/* continue with reading */
			break;
		case SSL_ERROR_SYSCALL:
			printf("Socket write error: ");
			HandleSocketError();
			break;
		case SSL_ERROR_SSL:
			printf("SSL write error: ");
			printf("%s (%d)\n",
				ERR_error_string(ERR_get_error(), buf),
				SSL_get_error(ssl, *n_bytes));
			break;
		default:
			printf("Unexpected error while writing!\n");
			break;
	}
}
void ShutDownDtlsServer(pass_info_t *info)
{
	SSL_shutdown(info->ssl);
	close(info->udp_fd);
	SSL_free(info->ssl);
	if (g_verbose)
	{
		printf("done, connection closed.\n");
	}
}
void StartClient(char *remote_address, int port, pass_info_t *info, int verb) 
{
	int fd				= 0;
	sai_t remote_addr		= { 0 };	
	SSL_CTX *ctx			= NULL;
	SSL *ssl			= NULL;
	BIO *bio			= NULL;

	g_verbose = verb;

	bzero(&remote_addr, sizeof(remote_addr));
	bzero(&remote_addr, sizeof(remote_addr));

	if (1 == inet_pton(AF_INET, remote_address, &remote_addr.sin_addr)) 
	{
		remote_addr.sin_family = AF_INET;
		remote_addr.sin_port = htons(port);
	} else 
	{
		return;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (0 > fd) 
	{
		perror("socket");
		exit(-1);
	}

	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLS_client_method());
	
	ReadCreds(CLI_CERT_FILE, CLI_KEY_FILE, ctx);

	SSL_CTX_set_verify_depth(ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);

	ssl = SSL_new(ctx);

	bio = BIO_new_dgram(fd, BIO_CLOSE);
	if (connect(fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in))) 
	{
		perror("connect");
	}
	
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr);

	SSL_set_bio(ssl, bio, bio);
	ESSL_connect(ssl);

	info->udp_fd = fd;

	PrintInfo(info);

	info->ssl = ssl;
}
void ShutdownDtlsClient(pass_info_t *info)
{
	SSL_shutdown(info->ssl);
	close(info->udp_fd);
	if (g_verbose)
	{
		printf("Connection closed.\n");
	}
}
