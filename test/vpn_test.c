#define  _POSIX_C_SOURCE 2
#include <string.h>
#include <strings.h>
#include <stdio.h>	/* for fprintf	*/
#include <stdlib.h>	/* for NULL	*/
#include <unistd.h>	/* for getopt	*/

#include "../include/vpn.h"

/* #define SRV_HOST	"192.168.122.177" */
#define SRV_HOST	"127.0.0.1"
#define PORT		55555
#define SRV_ADDR_LEN	128

int main(int argc, char *argv[])
{
	char srv_addr[SRV_ADDR_LEN] = { 0 };
	int option = 0;
	int runserver = 1;
	int verbose = 0;

	strncpy(srv_addr, SRV_HOST, SRV_ADDR_LEN - 1);
	while (0 < (option = getopt(argc, argv, "sc:v")))
	{
		switch (option) 
		{
			case 's':
				break;
			case 'c':
				runserver = 0;
				bzero(srv_addr, SRV_ADDR_LEN);
				strncpy(srv_addr, optarg, SRV_ADDR_LEN - 1);
				break;
			case 'v':
				verbose = 1;
				break;
			default:
				fprintf(stderr, "Unknown option %c\n", option);
				exit(1);
				break;
		}
	}

	if (runserver)
	{
		VPNSrver(PORT, verbose);
	} else 
	{
		VPNClient(srv_addr, PORT, verbose);	
	}

	return 0;
}
