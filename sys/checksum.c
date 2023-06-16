

#include <ntifs.h>
#include <fwpsk.h>
#include <fwpmk.h>

#include "Packet.h"
#include "utils.h"



WORD checksum(WORD* buffer, int size)
{
	unsigned long cksum = 0;
	while (1 < size)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (0 < size)
		cksum += *(UCHAR*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return(unsigned short)(~cksum);
}


USHORT subPackChecksum(char* lpCheckSumData, WORD wCheckSumSize, DWORD dwSrcIP, DWORD dwDstIP, unsigned int wProtocol)
{
	char szCheckSumBuf[0x1000];
	LPCHECKSUMFAKEHEADER lpFakeHdr = (LPCHECKSUMFAKEHEADER)szCheckSumBuf;
	lpFakeHdr->dwSrcIP = dwSrcIP;
	lpFakeHdr->dwDstIP = dwDstIP;
	lpFakeHdr->Protocol = __ntohs(wProtocol);
	lpFakeHdr->usLen = __ntohs(wCheckSumSize);

	memcpy(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER), (char*)lpCheckSumData, wCheckSumSize);

	*(DWORD*)(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER) + wCheckSumSize) = 0;

	unsigned short nCheckSum = checksum((WORD*)szCheckSumBuf, wCheckSumSize + sizeof(CHECKSUMFAKEHEADER));
	return nCheckSum;
}






unsigned short IPV6subPackCheckSum(char* lpdata, int size, unsigned char pSrcIP[16], unsigned char pDstIP[16], unsigned short protocol)
{
	char szCheckSumBuf[0x1000];
	LPIPV6FAKEHEADER pUdpFake = (LPIPV6FAKEHEADER)szCheckSumBuf;
	memcpy(pUdpFake->SrcIP, pSrcIP, IPV6_IP_SIZE);
	memcpy(pUdpFake->DstIP, pDstIP, IPV6_IP_SIZE);

	pUdpFake->Protocol = __ntohs(protocol);
	pUdpFake->PackLen = __ntohs(size);

	memcpy(szCheckSumBuf + sizeof(IPV6FAKEHEADER), (char*)lpdata, size);

	unsigned short nCheckSum = checksum((WORD*)szCheckSumBuf, size + sizeof(IPV6FAKEHEADER));
	return nCheckSum;
}