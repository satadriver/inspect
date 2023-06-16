

#ifndef LIST_H_H_H
#define LIST_H_H_H


#pragma once

#include "packet_pool.h"

#define DOMAIN_LIMIT_SIZE	256

#define BOXNAME_SIZE		34

#define IOCTL_WFP_SDWS_ADD_SERVER	CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_ADD_DNS		CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_ADD_PORT		CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_ADD_IPV4		CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_ADD_IPV6		CTL_CODE(FILE_DEVICE_UNKNOWN,0x805,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_ADD_URL		CTL_CODE(FILE_DEVICE_UNKNOWN,0x806,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_ADD_PROCESS	CTL_CODE(FILE_DEVICE_UNKNOWN,0x807,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_ADD_INTRANET	CTL_CODE(FILE_DEVICE_UNKNOWN,0x808,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)

#define IOCTL_WFP_SDWS_CLEAR_DNS		CTL_CODE(FILE_DEVICE_UNKNOWN,0x809,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_CLEAR_IPPORT		CTL_CODE(FILE_DEVICE_UNKNOWN,0x80A,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_CLEAR_PROCESS	CTL_CODE(FILE_DEVICE_UNKNOWN,0x80B,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)

#define IOCTL_WFP_SDWS_ADD_TCP		CTL_CODE(FILE_DEVICE_UNKNOWN,0x80C,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_ADD_UDP		CTL_CODE(FILE_DEVICE_UNKNOWN,0x80D,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_CLEAR_TCP		CTL_CODE(FILE_DEVICE_UNKNOWN,0x80E,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)
#define IOCTL_WFP_SDWS_CLEAR_UDP		CTL_CODE(FILE_DEVICE_UNKNOWN,0x80F,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS|FILE_ANY_ACCESS)

#pragma pack(1)

typedef struct _DNS_ATTACK_LIST		DNS_ATTACK_LIST;

typedef struct _IPPORT_ATTACK_LIST	IPPORT_ATTACK_LIST;

typedef struct _PROCESS_NAME_LIST	PROCESS_NAME_LIST;

struct _PROCESS_NAME_LIST {
	PROCESS_NAME_LIST* prev;
	PROCESS_NAME_LIST* next;
	char pname[DOMAIN_LIMIT_SIZE];
	char boxname[BOXNAME_SIZE];
	int enable;
};

struct _DNS_ATTACK_LIST
{
	DNS_ATTACK_LIST* prev;
	DNS_ATTACK_LIST* next;

	int type;
	char host[DOMAIN_LIMIT_SIZE];
	char boxname[BOXNAME_SIZE];
	int enable;
};

typedef struct
{
	DWORD type;

	UCHAR direction;

	DWORD ip;

	DWORD mask;

	USHORT port;

	UCHAR protocol;

	char host[DOMAIN_LIMIT_SIZE];

	char boxname[BOXNAME_SIZE];

	int enable;

	// 	DWORD localIp;
	// 	DWORD localPort;
}NETWORK_FILTER_PARAMS;





typedef struct _NETWORK_FILTER_PARAMS_LIST NETWORK_FILTER_PARAMS_LIST;

struct _NETWORK_FILTER_PARAMS_LIST
{
	NETWORK_FILTER_PARAMS_LIST* prev;
	NETWORK_FILTER_PARAMS_LIST* next;

	DWORD type;

	UCHAR direction;

	DWORD ip;

	DWORD mask;

	USHORT port;

	UCHAR protocol;

	char host[DOMAIN_LIMIT_SIZE];

	char boxname[BOXNAME_SIZE];

	int enable;
	// 	DWORD localIp;
	// 	DWORD localPort;
};


struct _IPPORT_ATTACK_LIST
{
	IPPORT_ATTACK_LIST* prev;
	IPPORT_ATTACK_LIST* next;

	unsigned int type;
	unsigned char direction;

	unsigned long ipv4;
	unsigned long ipv4mask;

	unsigned char ipv6[16];

	unsigned short port;

	char boxname[BOXNAME_SIZE];
	int enable;
};


typedef struct _PORT_PARAMS PORT_PARAMS;

struct _PORT_PARAMS
{
	unsigned int type;
	unsigned short port;
	unsigned char dir;
	char boxname[BOXNAME_SIZE];
	int enable;
};


typedef struct _IPV4_PARAMS IPV4_PARAMS;

struct _IPV4_PARAMS
{
	unsigned int type;
	unsigned long ipv4;
	unsigned long mask;
	unsigned char dir;
	char boxname[BOXNAME_SIZE];
	int enable;
};

typedef struct _IPV6_PARAMS IPV6_PARAMS;

struct _IPV6_PARAMS
{
	unsigned int type;
	unsigned char ipv6[16];
	unsigned char dir;
	char boxname[BOXNAME_SIZE];
	int enable;
};




#pragma pack()


extern DNS_ATTACK_LIST* g_dnsAttackList;

extern IPPORT_ATTACK_LIST* g_ipportAttackList;

//extern BOOLEAN g_intranet;

void initAttackList();

int clearDnsList();
int clearProcessList();
int clearIPPortList();

BOOL isIntranetEnable();

void setIntranet(BOOL enable);

int addDnsRule(char* data, int size);
int delDnsRule(char* data, int size);
DNS_ATTACK_LIST* searchDnslist(char* dnsname, int type);

IPPORT_ATTACK_LIST* searchIPPortList(char* data, int type);
int delIPPortRule(char* data, int type);
int addIPPortRule(char* data, int type);

int addProcessRule(char* data, int type);
PROCESS_NAME_LIST* searchProcesslist(char* procname);

int socketFilter(packet_t* packet);

int addFilterRule(NETWORK_FILTER_PARAMS* filter);

int delFilterRule();

NETWORK_FILTER_PARAMS_LIST* searchFilterList(NETWORK_FILTER_PARAMS* filter);

int isTargetSocketPacket(NETWORK_FILTER_PARAMS* filter, DWORD localip, DWORD localport);

#endif
