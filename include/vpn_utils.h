#ifndef __VPN_UTILS_H_CR4__
#define __VPN_UTILS_H_CR4__

typedef enum
{
	SRV_E,
	CLI_E
} agen_e_t;

typedef enum 
{
	ADD_E,
	DEL_E
} action_e_t;

int AllocTUN(char *tun_name);
void RunCmd(char *cmd);
void ConfigTUN(char *tun_addr, char *tun_name, int mtu);
void ConfigNAT(char action, char *tun_net_addr);
void ConfigRoutes(agen_e_t agent, action_e_t action, char* gw,
			 char *srv_addr, char * tun_name);

#endif /*__VPN_UTILS_H_CR4__*/
