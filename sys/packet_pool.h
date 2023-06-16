#ifndef PACKET_POOL_H
#define PACKET_POOL_H

#pragma warning(push)
#pragma warning(disable:4201) 

#include <fwpsk.h>

#pragma warning(pop)

#define ETHERNET_PACKET_LIMIT	1518
#define MIN_PACKETS				16
#define MAX_PACKETS				1024
#define MAX_PACKET_SIZE			(sizeof(packet_t) + ETHERNET_PACKET_LIMIT + 16)

#define PACKET_POOL_TAG			'kcuf'

#pragma pack(1)

typedef struct {
	UINT8 ip_version;
	UINT8 protocol;

	UINT8 local_ip[16];
	UINT8 remote_ip[16];

	UINT16 local_port;
	UINT16 remote_port;

	UINT8 direction;

	LARGE_INTEGER timestamp;

	UINT8* lppayload;

	UINT32 payloadlen;
	UINT8 payload[1];
} packet_t;


typedef struct {
	packet_t** packets;
	unsigned max_packets;
	unsigned count;

	KSPIN_LOCK spin_lock;
} packet_pool_t;

#pragma pack()

BOOL InitPacketPool(unsigned max_packets, unsigned max_packet_size);
void FreePacketPool();

void PushPacket(packet_t* packet);
packet_t* PopPacket();

#endif /* PACKET_POOL_H */
