#ifndef __VPN_H_CR4__
#define __VPN_H_CR4__

#define TUN_CLI_ADDR	"10.9.0.2/24"
#define TUN_SRV_ADDR	"10.9.0.1/24"
#define TUN_NET_ADDR	"10.9.0.0/24"
#define TUN_NAME	"tun0"
#define MTU		1400

/*
 * reviewer:	Nave Tahar
 * status:	Approved
 */

void VPNClient(char *srv_host, long srv_port, int verbose);

void VPNSrver(long srv_port, int verbose);

#endif /*__VPN_H_CR4__*/

