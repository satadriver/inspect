
#include "packetFilter.h"
#include "inspect.h"
#include "packet_process.h"
#include "packet.h"

#include "list.h"
#include <ntstrsafe.h>
#include "callback.h"
#include "utils.h"

#define _SANDBOX_NETWORK

NTSYSAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);




BOOL getPacket(_In_ const FWPS_INCOMING_VALUES* inFixedValues, _Inout_opt_ void* layerData, _Out_ packet_t* packet)
{
	const FWPS_INCOMING_VALUE* values;
	UINT localAddrIndex;
	UINT remoteAddrIndex;
	UINT localPortIndex;
	UINT remotePortIndex;
	UINT directionIndex;
	UINT protocolIdx;
	UINT32 addr;
	NET_BUFFER* nb;
	UINT8* payload;
	NTSTATUS status;

	if (packet == 0 || layerData == 0 || inFixedValues == 0)
	{
		DbgPrint("[liujinguang]layerdata:%p packet:%p inFixedValues:%p null", layerData, packet, inFixedValues);
		return FALSE;
	}

	status = getTupleIdxForLayer(inFixedValues->layerId, &localAddrIndex, &remoteAddrIndex, &localPortIndex, &remotePortIndex, &protocolIdx, &directionIndex);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}


	values = inFixedValues->incomingValue;
	//FWP_DIRECTION_INBOUND == 1 or FWP_DIRECTION_OUTBOUND == 0
	packet->direction = values[directionIndex].value.int8;
	packet->local_port = values[localPortIndex].value.uint16;
	packet->remote_port = values[remotePortIndex].value.uint16;
	//packet->protocol = values[protocolIdx].value.uint8;
	packet->protocol = (UCHAR)protocolIdx;

	if (getFamilyForLayer(inFixedValues->layerId) == AF_INET) {
		packet->ip_version = 4;

		addr = RtlUlongByteSwap(values[localAddrIndex].value.uint32);
		memcpy(packet->local_ip, &addr, 4);

		addr = RtlUlongByteSwap(values[remoteAddrIndex].value.uint32);
		memcpy(packet->remote_ip, &addr, 4);
	}
	else {
		packet->ip_version = 6;

		memcpy(packet->local_ip, values[localAddrIndex].value.byteArray16->byteArray16, 16);

		memcpy(packet->remote_ip, values[remoteAddrIndex].value.byteArray16->byteArray16, 16);
	}

	KeQuerySystemTime(&packet->timestamp);

	switch (packet->protocol)
	{
	case IPPROTO_TCP:
	{
		//if (packet->direction == FWP_DIRECTION_OUTBOUND)
		{
			FWPS_STREAM_CALLOUT_IO_PACKET0* fwps_scip = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;

			if (fwps_scip->streamData && fwps_scip->streamData->netBufferListChain)
			{
				nb = NET_BUFFER_LIST_FIRST_NB(fwps_scip->streamData->netBufferListChain);
				if (nb)
				{
					payload = NdisGetDataBuffer(nb, nb->DataLength, NULL, 1, 0);
					if (payload == NULL) {
						DbgPrint("[liujinguang]IPPROTO_TCP payload null");
						return FALSE;
					}

					packet->payloadlen = nb->DataLength;
					if (packet->payloadlen > MAX_PAYLOAD_SIZE)
					{
						DbgPrint("[liujinguang]nb->DataLength size:%u error\r\n", nb->DataLength);
					}

					packet->lppayload = payload;

					return TRUE;
				}
				else {
					DbgPrint("[liujinguang]NET_BUFFER_LIST_FIRST_NB(fwps_scip->streamData->netBufferListChain) null\r\n");
					return FALSE;
				}
			}
			else {
				DbgPrint("[liujinguang]fwps_scip->streamData:%p,fwps_scip->streamData->netBufferListChain:0\r\n",
					fwps_scip->streamData);
				return FALSE;
			}
		}
		break;
	}
	case IPPROTO_ICMP:
	{

		break;
	}
	case IPPROTO_UDP:
	{

		//if (packet->direction == FWP_DIRECTION_INBOUND )
		{
			nb = NET_BUFFER_LIST_FIRST_NB((NET_BUFFER_LIST*)layerData);
			if (nb)
			{
				payload = NdisGetDataBuffer(nb, nb->DataLength, NULL, 1, 0);
				if (payload == NULL) {
					DbgPrint("[liujinguang]IPPROTO_UDP payload null");
					return FALSE;
				}

				packet->payloadlen = nb->DataLength;
				if (packet->payloadlen > MAX_PAYLOAD_SIZE)
				{
					DbgPrint("[liujinguang]nb->DataLength size:%u error\r\n", nb->DataLength);
				}

				packet->lppayload = payload;

				// 				if (packet->direction == FWP_DIRECTION_OUTBOUND && packet->remote_port == 53)
				// 				{
				// 					//__debugbreak();
				// 					inFixedValues->incomingValue[remoteAddrIndex].value.uint32 = 0x08080808;
				// 					DbgPrint("[liujinguang]attack dns query ok\r\n");
				// 				}

				return TRUE;
			}
			else {
				DbgPrint("[liujinguang]NET_BUFFER_LIST_FIRST_NB(layerData) null\r\n");
				return FALSE;
			}
		}
		break;
	}
	default:
	{
		break;
	}
	}

	return FALSE;
}



int processHttpPacket(packet_t* packet) {

	int result = 0;
	char* pack = (char*)(packet->lppayload);
	int packlen = packet->payloadlen;
	//"GET / HTTP/0.9\r\n" 16 bytes
	//"GET / HTTP/1.0\r\n\r\n" 18 bytes
	if (packlen > 32)
	{
		result = isHttp(pack);
		if (result)
		{
			char host[DOMAIN_LIMIT_SIZE];
			int hostlen = getHostFromHttpPacket(pack, packlen, host);

			char url[URL_LIMIT_SIZE];
			int urllen = getUrlFromHttpPacket(pack, packlen, url);

			DNS_ATTACK_LIST* list = searchDnslist(url, IOCTL_WFP_SDWS_ADD_URL);
			if (list) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

int deviateDnsPacket(packet_t* packet) {

	DNS_REQUEST* req = (DNS_REQUEST*)(packet->lppayload);
	int packlen = packet->payloadlen;
	if (packlen > sizeof(DNS_REQUEST) + 4 + sizeof(DNS_REQUEST_TYPECLASS) + sizeof(DNS_ANSWER_ADDRESS))
	{
	}

	return 0;
}


int processDnsPacket(packet_t* packet) {

	DNS_REQUEST* req = (DNS_REQUEST*)(packet->lppayload);
	int packlen = packet->payloadlen;
	if (packlen > sizeof(DNS_REQUEST) + 4 + sizeof(DNS_REQUEST_TYPECLASS) + sizeof(DNS_ANSWER_ADDRESS))
	{
		char name[DOMAIN_LIMIT_SIZE];

		int hostlen = getHostFromDns(req->queries, name);
		if (hostlen <= 0)
		{
			return FALSE;
		}

		// 		DNS_ATTACK_LIST* list = searchDnslist(name, IOCTL_WFP_SDWS_ADD_DNS);
		// 		if (list) 
		{
			if (packet->ip_version == 4)
			{
				int reqsize = sizeof(DNS_REQUEST) + hostlen + 2 + sizeof(DNS_REQUEST_TYPECLASS);
				int answersize = packlen - reqsize;

				DNS_ANSWER_HEAD* answer = (DNS_ANSWER_HEAD*)(packet->lppayload + reqsize);

				int cnt = __ntohs(req->answerRRS);
				for (int i = 0; i < cnt; i++)
				{
					if (answer->type == 0x0500)	//cname
					{

					}
					else if (answer->type == 0x0100)
					{
						DNS_ANSWER_ADDRESS* addr = (DNS_ANSWER_ADDRESS*)answer;

						//RtlCopyMemory((char*)answer, (char*)&g_dstDsnAnswer, sizeof(DNS_ANSWER_ADDRESS));
						//47.116.51.29
						addr->address = 0xc0a8657a;
					}
					answer = (DNS_ANSWER_HEAD*)((unsigned char*)answer + sizeof(DNS_ANSWER_HEAD) + __ntohs(answer->datelen));
				}
			}
			else if (packet->ip_version == 6)
			{

			}
		}
	}
	return FALSE;
}








int packetFilter(const FWPS_INCOMING_VALUES* inFixedValues, void* layerData) {


	int result = 0;
#ifndef _SANDBOX_NETWORK
	if (isIntranetEnable())
#endif
	{
		UCHAR tmpdata[MAX_PACKET_SIZE + 16];

		packet_t* mypacket = (packet_t*)tmpdata;

		result = getPacket(inFixedValues, layerData, mypacket);
		if (result)
		{
			/*
			PEPROCESS peproc = PsGetCurrentProcess();
			UCHAR* pefp = PsGetProcessImageFileName(peproc);
			if (pefp && *pefp)
			{
				upperstr((char*)pefp);
				PROCESS_NAME_LIST* proclist = searchProcesslist((char*)pefp);
				if (proclist)
				{
					DbgPrint("find blacklist process:%s", pefp);
					return TRUE;
				}
			}
			if (mypacket->ip_version == 4)
			{
				DWORD localip = *(DWORD*)mypacket->local_ip;
				DWORD remoteip = *(DWORD*)mypacket->remote_ip;
				DWORD localport = mypacket->local_port;
				DWORD remoteport = mypacket->remote_port;
				DWORD protocol = mypacket->protocol;

				NETWORK_FILTER_PARAMS filter;
				filter.ip = *(DWORD*)mypacket->remote_ip;
				filter.port = mypacket->remote_port;
				filter.direction = mypacket->direction;
				filter.protocol = mypacket->protocol;
				//__debugbreak();
				result = isTargetSocketPacket(&filter, *(DWORD*)mypacket->local_ip, mypacket->local_port);
				if (result == 1)
				{
					return FALSE;
				}
				else if (result == 2) {

					DbgPrint("src ip:%02d.%02d.%02d.%02d,src port:%d,dst ip:%02d.%02d.%02d.%02d,dst port:%u,ipversion:%u,protocol:%u",
						mypacket->local_ip[0], mypacket->local_ip[1], mypacket->local_ip[2], mypacket->local_ip[3],
						localport,
						mypacket->remote_ip[0], mypacket->remote_ip[1], mypacket->remote_ip[2], mypacket->remote_ip[3],
						remoteport, mypacket->ip_version, protocol);

					return TRUE;
				}

				DWORD remoteip = *(DWORD*)mypacket->remote_ip;
#ifndef _SANDBOX_NETWORK
				if (isIntranet(remoteip) == FALSE)
#else
				if (isIntranetEnable() && isIntranet(remoteip) == FALSE)
#endif
				{
					DbgPrint("src ip:%02d.%02d.%02d.%02d,src port:%d,dst ip:%02d.%02d.%02d.%02d,dst port:%u,ipversion:%u,protocol:%u",
						mypacket->local_ip[0], mypacket->local_ip[1], mypacket->local_ip[2], mypacket->local_ip[3],
						localport,
						mypacket->remote_ip[0], mypacket->remote_ip[1], mypacket->remote_ip[2], mypacket->remote_ip[3],
						remoteport, mypacket->ip_version, protocol);

					return TRUE;
				}

				if (mypacket->protocol == IPPROTO_ICMP)
				{
					char data[1024];
					int strpack_len = formatPacketByte(mypacket->payload, mypacket->payloadlen, data);
					DbgPrint(data);
					return TRUE;
				}

				return TRUE;
			}
		}
		*/


			if (mypacket->ip_version == 4)
			{
				if (FWP_DIRECTION_INBOUND == mypacket->direction && mypacket->protocol == IPPROTO_UDP)
				{
					if (mypacket->remote_port == 53)
					{
						result = processDnsPacket(mypacket);
						return result;
					}
				}
				// 			else if (FWP_DIRECTION_OUTBOUND == mypacket->direction && mypacket->protocol == IPPROTO_TCP)
				// 			{
				// 				result = socketFilter(mypacket);
				// 				if (result)
				// 				{
				// 					return result;
				// 				}
				// 				result = processHttpPacket(mypacket);
				// 				if (result)
				// 				{
				// 					return result;
				// 				}
				// 			}
			}
		}
	}
	return FALSE;
}