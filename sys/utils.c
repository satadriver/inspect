
#include "utils.h"
#include "netioapi.h"
#include "packet_pool.h"
#include "ws2def.h"

#pragma comment(lib,"Iphlpapi.lib")



int upperstr(char* str) {
	int len = (int)strlen(str);
	for (int i = 0; i < len; i++)
	{
		if (str[i] >= 'a' && str[i] <= 'z')
		{
			str[i] -= 0x20;
		}
	}
	return len;
}


int lowerstr(char* str) {
	int len = (int)strlen(str);
	for (int i = 0; i < len; i++)
	{
		if (str[i] >= 'A' && str[i] <= 'Z')
		{
			str[i] += 0x20;
		}
	}
	return len;
}


unsigned short __ntohs(unsigned short v) {
	return ((v & 0xff) << 8) + ((v & 0xff00) >> 8);
}


unsigned int __ntohl(unsigned int v) {
	return ((v & 0xff) << 24) + ((v & 0xff00) << 8) + ((v & 0xff0000) >> 8) + ((v & 0xff000000) >> 24);
}

char* mystrstr(char* data, int datalen, char* section, int sectionlen) {

	for (int i = 0; i < datalen - sectionlen; i++)
	{
		if (memcmp(data + i, section, sectionlen) == 0)
		{
			return data + i;
		}
	}
	return FALSE;
}



unsigned long getLocalIP() {
	ADDRESS_FAMILY Family;
	PMIB_UNICASTIPADDRESS_TABLE  Table = NULL;
	NETIOAPI_API  NetIoApi;
	SOCKADDR_INET  sockaddr_inet;
	SOCKADDR_IN    Ipv4;
	Family = AF_INET;
	//GetUnicastIpAddressTable(Family, (PMIB_UNICASTIPADDRESS_TABLE*)&(Table));

	sockaddr_inet = Table->Table[0].Address;
	Ipv4 = sockaddr_inet.Ipv4;
	return Ipv4.sin_addr.S_un.S_addr;
}


int formatPacketByte(unsigned char* packet, int packet_len, char* buf) {
	char* output = buf;
	int offset = 0;
	for (int i = 0; i < packet_len; i++)
	{
		int least_len = packet_len - offset;
		if (least_len - 2 > 0)
		{
			offset += sprintf_s(buf + offset, (int)(least_len - 2), "%02x ", packet[i]);
		}
		else {
			break;
		}
	}
	buf[offset] = 0;
	return offset;
}


//A类地址：10.0.0.0--10.255.255.255
//B类地址：172.16.0.0--172.31.255.255
//C类地址：192.168.0.0--192.168.255.255
//169.254.0.0/16
//127.0.0.1
BOOLEAN isIntranet(unsigned long ip) {
	unsigned long ipv4 = __ntohl(ip);
	if (ipv4 > 0x0a000000 && ipv4 <= 0x0affffff)
	{
		return TRUE;
	}
	else if (ipv4 > 0xac100000 && ipv4 <= 0xac1fffff)
	{
		return TRUE;
	}
	else if (ipv4 > 0xc0a80000 && ipv4 <= 0xc0a8ffff)
	{
		return TRUE;
	}
	else if (ipv4 > 0xa9fe0000 && ipv4 <= 0xa9feffff)
	{
		return TRUE;
	}
	else if (ipv4 > 0x7f000000 && ipv4 <= 0x7fffffff)
	{
		return TRUE;
	}
	return FALSE;
}





int getHostFromDns(unsigned char* data, char* name) {
	char* lpname = name;
	unsigned char* d = (unsigned char*)data;
	while (1)
	{
		unsigned int size = *d;
		if (size > 0 && size < 64)
		{
			d++;
			RtlCopyMemory(lpname, d, size);
			d += size;

			lpname += size;

			*lpname = '.';
			lpname++;
		}
		else if (size == 0)
		{
			if (lpname - name > 0)
			{
				lpname--;
				*lpname = 0;
			}
			else {
				*name = 0;
			}

			break;
		}
		else {
			*name = 0;
			break;
		}
	}

	return (int)(lpname - name);
}


int isHttp(char* http) {
	if (memcmp(http, "GET ", 4) == 0 ||
		memcmp(http, "POST ", 5) == 0
		// 		||
		// 		memcmp(http, "CONNECT ", 8) == 0 ||
		// 		memcmp(http, "HEAD ", 5) == 0 ||
		// 		memcmp(http, "PUT ", 4) == 0 ||
		// 		memcmp(http, "DELETE ", 7) == 0 ||
		// 		memcmp(http, "TRACE ", 6) == 0 ||
		// 		memcmp(http, "OPTIONS ", 8) == 0 
		)
	{
		return TRUE;
	}

	return FALSE;
}


char* stripHttpMethod(char* http) {
	if (memcmp(http, "GET ", 4) == 0) {
		return http + 4;
	}
	else if (memcmp(http, "POST ", 5) == 0)
	{
		return http + 5;
	}
	// 	else if (memcmp(http, "CONNECT ", 8) == 0)
	// 	{
	// 		return http + 8;
	// 	}
	// 	else if (memcmp(http, "HEAD ", 5) == 0)
	// 	{
	// 		return http + 5;
	// 	}
	// 	else if (memcmp(http, "PUT ", 4) == 0)
	// 	{
	// 		return http + 4;
	// 	}
	// 	else if (memcmp(http, "DELETE ", 7) == 0)
	// 	{
	// 		return http + 7;
	// 	}
	// 	else if (memcmp(http, "TRACE ", 6) == 0)
	// 	{
	// 		return http + 6;
	// 	}
	// 	else if (memcmp(http, "OPTIONS ", 8) == 0)
	// 	{
	// 		return http + 8;
	// 	}

	return FALSE;
}





int getUrlFromHttpPacket(char* pack, int packlen, char* url) {

	char* http = stripHttpMethod(pack);
	int httplen = packlen - (int)(http - pack);
	char* flag = " HTTP/1.";
	char* urlend = mystrstr(http, httplen, flag, (int)strlen(flag));
	if (urlend)
	{
		int urllen = (int)(urlend - http);
		if (urllen < URL_LIMIT_SIZE)
		{
			RtlCopyMemory(url, http, urllen);
			*(url + urllen) = 0;
			return urllen;
		}
	}
	return FALSE;
}

int getHostFromHttpPacket(char* pack, int packlen, char* host) {
	char* flag = "\r\nHost: ";
	int flaglen = (int)strlen(flag);
	char* hdr = mystrstr(pack, packlen, flag, flaglen);
	if (hdr)
	{
		hdr += flaglen;
		int contentlen = (int)(packlen - (hdr - pack));
		char* end = mystrstr(hdr, contentlen, "\r\n", 2);
		if (end)
		{
			int hostlen = (int)(end - hdr);
			if (hostlen < DOMAIN_LIMIT_SIZE)
			{
				RtlCopyMemory(host, hdr, hostlen);
				*(host + hostlen) = 0;
				return hostlen;
			}
		}
	}
	return FALSE;
}