
#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>

#include "inspect.h"
#include "list.h"
#include "configfile.h"



void processData(char* buf, int size) {

	char* data = buf;
	while (data < buf + size)
	{
		DWORD type = *(DWORD*)data;
		if (type == IOCTL_WFP_SDWS_ADD_IPV4)
		{
			addIPPortRule(data, IOCTL_WFP_SDWS_ADD_IPV4);
			data += sizeof(IPV4_PARAMS);

		}
		else if (type == IOCTL_WFP_SDWS_ADD_PORT)
		{
			addIPPortRule(data, IOCTL_WFP_SDWS_ADD_PORT);
			data += sizeof(PORT_PARAMS);

		}
		else if (type == IOCTL_WFP_SDWS_ADD_DNS)
		{
			int len = strlen(data);

			addIPPortRule(data, len);
			data += (ULONGLONG)(4 + len + 1);
		}
		else {
			break;
		}
	}
}






BOOLEAN readConfig(LPCWSTR lpFile)
{
	HANDLE				hFile;
	NTSTATUS			status;
	OBJECT_ATTRIBUTES	Oa;
	UNICODE_STRING		ufile_name;
	PCHAR				lpBuf = NULL;
	INT					nMax = 0;
	int					nLen = 0;
	IO_STATUS_BLOCK		io_status = { 0 };
	LARGE_INTEGER		offset = { 0 };
	FILE_STANDARD_INFORMATION file_standard_info = { 0 };

	if (lpFile == NULL) {
		return FALSE;
	}

	RtlInitUnicodeString(&ufile_name, (PCWSTR)lpFile);
	InitializeObjectAttributes(&Oa, &ufile_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(&hFile, GENERIC_READ, &Oa, &io_status, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
		FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}

	status = ZwQueryInformationFile(
		hFile,
		&io_status,
		&file_standard_info,
		sizeof(file_standard_info),
		FileStandardInformation);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return FALSE;
	}

	if (file_standard_info.EndOfFile.QuadPart > 0x10000)
	{
		ZwClose(hFile);
		return FALSE;
	}

	nMax = (INT)file_standard_info.EndOfFile.QuadPart;
	lpBuf = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, nMax + 16, PACKET_POOL_TAG);
	if (!lpBuf)
	{
		ZwClose(hFile);
		return FALSE;
	}

	nLen = 0;
	while (nLen < nMax)
	{
		io_status.Information = 0;
		status = ZwReadFile(hFile, NULL, NULL, NULL, &io_status, lpBuf + nLen, nMax - nLen, &offset, NULL);
		if (!NT_SUCCESS(status))
		{
			ZwClose(hFile);
			ExFreePool(lpBuf);
			return FALSE;
		}

		nLen += (int)io_status.Information;
		offset.QuadPart = nLen;
	}

	ZwClose(hFile);
	if (nLen != nMax)
	{
		ExFreePool(lpBuf);
		return FALSE;
	}

	lpBuf[nLen] = '\0';
	lpBuf[nLen + 1] = '\0';

	processData(lpBuf, nLen);

	ExFreePool(lpBuf);

	ZwDeleteFile(&Oa);

	return TRUE;
}



void* mainloop(void* param) {
	__debugbreak();
	int result = 0;
	while (1)
	{
		result = readConfig(L"\\??\\C:\\Windows\\config.txt");
		if (result == FALSE)
		{
			break;
		}
		LARGE_INTEGER li;
		li.QuadPart = 10 * 1000 * 1000 * 3;
		KeDelayExecutionThread(KernelMode, 0, &li);
	}

	return 0;
}
