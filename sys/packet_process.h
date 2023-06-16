#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include "packet_pool.h"

#define HOST_NAME_MAX_LEN   255
#define MAX_POINTERS        10
#define MAX_ANSWERS         32
#define MAX_CNAMES          8

#pragma pack(1)

typedef struct {
	char name[HOST_NAME_MAX_LEN + 1];
	UINT16 namelen;
	char alias[HOST_NAME_MAX_LEN + 1];
	UINT16 aliaslen;
} cname_t;

#pragma pack()

void ProcessPacket(packet_t* packet);

BOOL ParseHttpPacket(const UINT8* data,
	SIZE_T len,
	const UINT8** method,
	SIZE_T* methodlen,
	const UINT8** path,
	SIZE_T* pathlen,
	const UINT8** host,
	SIZE_T* hostlen);


static void LogHttp(packet_t* packet,
	const char* local,
	const char* remote,
	const char* str);

static void LogHttps(packet_t* packet,
	const char* local,
	const char* remote,
	const char* str);

static void LogDns(packet_t* packet,
	const char* local,
	const char* remote);

BOOL ParseHttpPacket(const UINT8* data,
	SIZE_T len,
	const UINT8** method,
	SIZE_T* methodlen,
	const UINT8** path,
	SIZE_T* pathlen,
	const UINT8** host,
	SIZE_T* hostlen);

static BOOL ParseDns(LARGE_INTEGER* system_time, const UINT8* data, SIZE_T len);
static BOOL SkipDnsQuestions(const UINT8* end,
	UINT16 qdcount,
	const UINT8** ptr);

static BOOL SkipDnsName(const UINT8* end, const UINT8** ptr);
static BOOL ParseDnsName(const UINT8* data,
	const UINT8* end,
	const UINT8** ptr,
	char* hostname,
	UINT16* hostnamelen);

static const char* FindHostname(const cname_t* cnames,
	unsigned ncnames,
	const char* name,
	UINT16 namelen,
	UINT16* len);


#endif /* PACKET_PROCESSOR_H */
