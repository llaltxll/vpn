
#ifndef __SOCK_USTILS_H_CR4__ 
#define __SOCK_USTILS_H_CR4__ 

#include <sys/socket.h> /* for sockaddr */
#include <sys/select.h> /* for fd_set	*/
#include <sys/types.h>
#include <unistd.h>
typedef struct addrinfo addrinfo_t;

/*
 * takes sockaddr and returns  ipv4 or ipv6 address according to sa_family
 * sa member.
 */
void *GetInAddr(struct sockaddr *sa);
/*
 * opens a socket file descriptor
 * arguments: i_addr_str - string ip address - or NULL for passive selection
 *            port - string port number
 *            sock_type - SOCK_STREAM or SOCK_DGRAM            
 * return: file descriptor or -1 on error.
 */
int InitSocket(char *i_addr_str, char *port, int sock_type);

int InitAddr(char *ip_address, char *port, addrinfo_t **srv_addr,
		int sock_type);
/*
 * open wrapper, handles errors by printing message and exiting with -1
 */
int Open(const char *path, int oflag, ...);

ssize_t Write(int fd, const void *buf, size_t n);

ssize_t Read(int fd, void *buf, size_t n);

int Ioctl(int fd, unsigned long request, ...);

int Inet_pton(int af, const char *cp, void *buf);

int Socket(int domain, int type, int protocol);

ssize_t Sendto(int fd, const void *buf, size_t n, int flags, 
	       const struct sockaddr *addr, socklen_t addr_len);

ssize_t Recvfrom(int fd, void *buf, size_t n, int flags,
		 struct sockaddr *addr, socklen_t *addr_len);

int Bind(int fd, const struct sockaddr *addr, socklen_t len);

int Select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	   struct timeval *timeout);

int HandleSocketError(void);

#endif /*__SOCK_USTILS_H_CR4__*/
