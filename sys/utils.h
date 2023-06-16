
#pragma once

#ifndef UTILS_H
#define UTILS_H

#include <ntddk.h>
#include "packet_pool.h"
#include <guiddef.h>
#include <stdio.h>

#define URL_LIMIT_SIZE		1024

#define DOMAIN_LIMIT_SIZE	256

int upperstr(char* str);

int lowerstr(char* str);

unsigned short __ntohs(unsigned short v);

unsigned int __ntohl(unsigned int v);

unsigned long getLocalIP();

char* mystrstr(char* data, int datalen, char* section, int sectionlen);


int getHostFromDns(unsigned char* data, char* name);

int getHostFromHttpPacket(char* pack, int packlen, char* host);

int getUrlFromHttpPacket(char* pack, int packlen, char* url);
BOOLEAN isIntranet(unsigned long ipv4);

void setDnsTarget(DWORD ip);

int isHttp(char* http);

char* stripHttpMethod(char* http);

__inline ADDRESS_FAMILY getFamilyForLayer(_In_ UINT16 layerId)
{
	switch (layerId)
	{
	case FWPS_LAYER_STREAM_V4:
	case FWPS_LAYER_DATAGRAM_DATA_V4:
	case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4:
	case FWPS_LAYER_INBOUND_TRANSPORT_V4:

		return AF_INET;
	case FWPS_LAYER_STREAM_V6:
	case FWPS_LAYER_DATAGRAM_DATA_V6:
	case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6:
	case FWPS_LAYER_INBOUND_TRANSPORT_V6:

		return AF_INET6;
	default:
		return AF_UNSPEC;
	}
}

__inline BOOL getTupleIdxForLayer(_In_ UINT16 layerId, _Out_ UINT* localAddressIndex, _Out_ UINT* remoteAddressIndex,
	_Out_ UINT* localPortIndex, _Out_ UINT* remotePortIndex, UINT* protocolIdx, UINT* directionIndex)
{
	switch (layerId)
	{
	case FWPS_LAYER_STREAM_V4:
		*localAddressIndex = FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS;
		*remoteAddressIndex = FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS;
		*localPortIndex = FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT;
		*remotePortIndex = FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT;
		*protocolIdx = IPPROTO_TCP;
		*directionIndex = FWPS_FIELD_STREAM_V4_DIRECTION;
		return TRUE;
	case FWPS_LAYER_STREAM_V6:
		*localAddressIndex = FWPS_FIELD_STREAM_V6_IP_LOCAL_ADDRESS;
		*remoteAddressIndex = FWPS_FIELD_STREAM_V6_IP_REMOTE_ADDRESS;
		*localPortIndex = FWPS_FIELD_STREAM_V6_IP_LOCAL_PORT;
		*remotePortIndex = FWPS_FIELD_STREAM_V6_IP_REMOTE_PORT;
		*protocolIdx = IPPROTO_TCP;
		*directionIndex = FWPS_FIELD_STREAM_V6_DIRECTION;
		return TRUE;
	case FWPS_LAYER_DATAGRAM_DATA_V4:
		*localAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS;
		*remoteAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS;
		*localPortIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT;
		*remotePortIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT;
		*protocolIdx = IPPROTO_UDP;
		*directionIndex = FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION;
		return TRUE;
	case FWPS_LAYER_DATAGRAM_DATA_V6:
		*localAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS;
		*remoteAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS;
		*localPortIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT;
		*remotePortIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT;
		*protocolIdx = IPPROTO_UDP;
		*directionIndex = FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION;
		return TRUE;
	case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4:
		*localAddressIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_ADDRESS;
		*remoteAddressIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_ADDRESS;
		*localPortIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_PORT;
		*remotePortIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_PORT;
		*protocolIdx = IPPROTO_TCP;
		*directionIndex = 0;
		return TRUE;
	case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6:
		*localAddressIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_LOCAL_ADDRESS;
		*remoteAddressIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_REMOTE_ADDRESS;
		*localPortIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_LOCAL_PORT;
		*remotePortIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_REMOTE_PORT;
		*protocolIdx = IPPROTO_TCP;
		*directionIndex = 0;
		return TRUE;

	case FWPS_LAYER_INBOUND_TRANSPORT_V4:
		*localAddressIndex = FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS;
		*remoteAddressIndex = FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS;
		*localPortIndex = FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT;
		*remotePortIndex = FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT;
		*protocolIdx = IPPROTO_ICMP;
		*directionIndex = FWPS_FIELD_STREAM_V4_DIRECTION;
		return TRUE;

	default:
		return FALSE;
	}
}

#endif /* UTILS_H */
