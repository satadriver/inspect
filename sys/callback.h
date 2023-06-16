#pragma once

#ifndef INSPECT_H
#define INSPECT_H

#include <ntddk.h>
#include <wdf.h>

#include <fwpsk.h>

#include <fwpmk.h>

#define INITGUID
#include <guiddef.h>

#include "packet_pool.h"

#define NUMBER_BUCKETS		127
#define MAX_DNS_ENTRIES		1024
#define WFP_DEVICE_NAME		L"\\device\\inspect"
#define WFP_DEVICE_SYMBOL	L"\\DosDevices\\inspect"

void NTAPI WfpTransportSendClassify(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN OUT void* layerData,
#if(NTDDI_VERSION >= NTDDI_WIN7)
	_In_opt_ const void* classifyContext,
#endif
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	IN OUT FWPS_CLASSIFY_OUT* classifyOut
);

NTSTATUS StreamNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter);

void StreamClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
#if (NTDDI_VERSION >= NTDDI_WIN7)
	_In_opt_ const void* classifyContext,
#endif
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut);

NTSTATUS DatagramNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter);

void DatagramClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
#if (NTDDI_VERSION >= NTDDI_WIN7)
	_In_opt_ const void* classifyContext,
#endif
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut);

NTSTATUS AleClosureNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter);

void AleClosureClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
#if (NTDDI_VERSION >= NTDDI_WIN7)
	_In_opt_ const void* classifyContext,
#endif
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut);

//#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - offsetof(packet_t, payload))



#endif /* INSPECT_H */
