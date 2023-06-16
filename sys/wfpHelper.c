

#include <ntifs.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "wfpHelper.h"

#include "callback.h"




HANDLE hEngine;
UINT32 layerStreamV4, layerStreamV6;
UINT32 layerDatagramV4, layerDatagramV6;
UINT32 layerIcmpV4;
UINT32 layerInBoundIPV4;
//static UINT32 layerAleClosureV4, layerAleClosureV6;
UINT32 IPInBoundIPV4;
UINT32 IPOutBoundIPV4;

callout_t callouts[] = {

  {
	&FWPM_LAYER_STREAM_V4,
	&TL_LAYER_STREAM_V4,
	StreamNotify,
	StreamClassify,
	L"StreamLayerV4",
	L"Intercepts the first ipv4 outbound packet with payload of each connection.",
	&layerStreamV4
  },
  {
	&FWPM_LAYER_STREAM_V6,
	&TL_LAYER_STREAM_V6,
	StreamNotify,
	StreamClassify,
	L"StreamLayerV6",
	L"Intercepts the first ipv6 outbound packet with payload of each connection.",
	&layerStreamV6
  },
  {
	&FWPM_LAYER_DATAGRAM_DATA_V4,
	&TL_LAYER_DATAGRAM_V4,
	DatagramNotify,
	DatagramClassify,
	//WfpTransportSendClassify,
	L"DatagramLayerV4",
	L"Intercepts inbound ipv4 UDP data.",
	&layerDatagramV4
  },
  {
	&FWPM_LAYER_DATAGRAM_DATA_V6,
	&TL_LAYER_DATAGRAM_V6,
	DatagramNotify,
	DatagramClassify,
	//WfpTransportSendClassify,
	L"DatagramLayerV6",
	L"Intercepts inbound ipv6 UDP data.",
	&layerDatagramV6
  }


	/*
	,
	{
		&FWPM_LAYER_INBOUND_TRANSPORT_V4,
		&TL_LAYER_INBOUND_TRANSPORT_V4,
		DatagramNotify,
		DatagramClassify,
		L"IcmpLayerV4",
		L"Intercepts inbound ipv4 Icmp data.",
		&layerIcmpV4
	}
  ,
	  {
		  &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		  &TL_LAYER_OUTBOUND_TRANSPORT_V4,
		  DatagramNotify,
		  DatagramClassify,
		  L"IcmpLayerV4",
		  L"Intercepts inbound ipv4 Icmp data.",
		  &layerIcmpV4
	  }
	  ,*/

	  /*
	{
		&FWPM_LAYER_INBOUND_IPPACKET_V4,
		&TL_LAYER_INBOUND_IPPACKET_V4,
		  StreamNotify,
		  StreamClassify,
			L"InBoundIPV4",
			L"Intercepts inbound IPV4 data.",
			&IPInBoundIPV4
	},

	{
		&FWPM_LAYER_OUTBOUND_IPPACKET_V4,
		&TL_LAYER_OUTBOUND_IPPACKET_V4,
		  StreamNotify,
		  StreamClassify,
			L"OutBoundIPV4",
			L"Intercepts outbound IPV4 data.",
			&IPOutBoundIPV4
	}
	*/
	/*
	,
	  {
		  //This filtering layer allows for tracking de-activation of connected TCP flow or UDP sockets
		&FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,
		&TL_LAYER_ALE_EP_CLOSURE_V4,
		AleClosureNotify,
		AleClosureClassify,
		L"AleLayerEndpointClosureV4",
		L"Intercepts ipv4 connection close",
		&layerAleClosureV4
	  },
	  {
		&FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
		&TL_LAYER_ALE_EP_CLOSURE_V6,
		AleClosureNotify,
		AleClosureClassify,
		L"AleLayerEndpointClosureV6",
		L"Intercepts ipv6 connection close",
		&layerAleClosureV6
	  }
	  */
};



NTSTATUS AddFilter(_In_ const wchar_t* filterName,
	_In_ const wchar_t* filterDesc,
	_In_ UINT64 context,
	_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey)
{
	NTSTATUS status;
	FWPM_FILTER filter = { 0 };

	filter.displayData.name = (wchar_t*)filterName;
	filter.displayData.description = (wchar_t*)filterDesc;

	filter.rawContext = context;

	filter.layerKey = *layerKey;
	filter.action.calloutKey = *calloutKey;

	filter.weight.type = FWP_EMPTY; //Indicates no data.

	//filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;

	filter.subLayerKey = TL_INSPECT_SUBLAYER;

	FWPM_FILTER_CONDITION FilterCondition[1] = { 0 };
	filter.filterCondition = FilterCondition;
	filter.numFilterConditions = ARRAYSIZE(FilterCondition);

	if (memcmp(layerKey, &FWPM_LAYER_STREAM_V4, sizeof(GUID)) == 0
		/*||memcmp(layerKey, &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4, sizeof(GUID)) == 0*/)
	{
		FilterCondition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		FilterCondition[0].matchType = FWP_MATCH_EQUAL;
		FilterCondition[0].conditionValue.type = FWP_V4_ADDR_MASK;
		//in host order
		FWP_V4_ADDR_AND_MASK AddrAndMask = { 0 };
		FilterCondition[0].conditionValue.v4AddrMask = &AddrAndMask;
	}
	else if (memcmp(layerKey, &FWPM_LAYER_INBOUND_IPPACKET_V4, sizeof(GUID)) == 0)
	{
		FWPM_FILTER_CONDITION FilterCondition[1] = { 0 };
		filter.filterCondition = FilterCondition;
		filter.numFilterConditions = ARRAYSIZE(FilterCondition);

		FilterCondition[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
		FilterCondition[0].matchType = FWP_MATCH_EQUAL;
		FilterCondition[0].conditionValue.type = FWP_UINT8;
		FilterCondition[0].conditionValue.uint8 = IPPROTO_IP;
	}
	else if (memcmp(layerKey, &FWPM_LAYER_STREAM_V6, sizeof(GUID)) == 0
		/*||memcmp(layerKey, &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6, sizeof(GUID)) == 0*/)
	{
		FilterCondition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		FilterCondition[0].matchType = FWP_MATCH_EQUAL;
		FilterCondition[0].conditionValue.type = FWP_V6_ADDR_MASK;
		//in host order,if both mask and ip are 0 ,then each remote ip AND operator with mask will be equal to target ip
		FWP_V6_ADDR_AND_MASK AddrAndMask = { 0 };
		FilterCondition[0].conditionValue.v6AddrMask = &AddrAndMask;
	}
	//也可以合并在FWPM_LAYER_STREAM_V4或者FWPM_LAYER_STREAM_V6中
	else if (memcmp(layerKey, &FWPM_LAYER_DATAGRAM_DATA_V6, sizeof(GUID)) == 0 || memcmp(layerKey, &FWPM_LAYER_DATAGRAM_DATA_V4, sizeof(GUID)) == 0) {
		FilterCondition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		FilterCondition[0].matchType = FWP_MATCH_GREATER;
		FilterCondition[0].conditionValue.type = FWP_UINT16;
		FilterCondition[0].conditionValue.uint16 = 0;
	}
	else if (memcmp(layerKey, &FWPM_LAYER_INBOUND_TRANSPORT_V4, sizeof(GUID)) == 0)
	{

		FWPM_FILTER_CONDITION FilterCondition[2] = { 0 };
		filter.filterCondition = FilterCondition;
		filter.numFilterConditions = ARRAYSIZE(FilterCondition);

		FilterCondition[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
		FilterCondition[0].matchType = FWP_MATCH_EQUAL;
		FilterCondition[0].conditionValue.type = FWP_UINT8;
		FilterCondition[0].conditionValue.uint8 = IPPROTO_ICMP;

		FilterCondition[1].fieldKey = FWPM_CONDITION_ICMP_TYPE;
		//FilterCondition[1].matchType = FWP_MATCH_EQUAL;
		FilterCondition[1].matchType = FWP_MATCH_GREATER_OR_EQUAL;
		FilterCondition[1].conditionValue.type = FWP_UINT16;
		FilterCondition[1].conditionValue.uint16 = 0;			//echo reply
	//	Condition[1].conditionValue.uint16 = 8;					//echo request

		filter.weight.type = FWP_UINT8;
		filter.weight.uint8 = 0x0A;
		//filter.action.type = FWP_ACTION_BLOCK;
	}
	else {
		//return -1;
	}

	status = FwpmFilterAdd(hEngine, &filter, NULL, NULL);
	DbgPrint("[liujinguang]FwpmFilterAdd filterName:%ws filterDesc:%ws result:%d\r\n", filterName, filterDesc, status);
	return status;
}





NTSTATUS RegisterCallout(_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey,
	_Inout_ void* deviceObject,
	_In_ FWPS_CALLOUT_NOTIFY_FN notifyFn,
	_In_ FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	_In_ wchar_t* calloutName,
	_In_ wchar_t* calloutDescription,
	_Out_ UINT32* calloutId)
{
	//Management (FWPM) and Callout (FWPS) Data Types
	//Most FWPM data types, which are used for management tasks such as addingfilters or callouts from an application or driver,have FWPS counterparts.
	//The FWPS data types are used during the actual filtering of network traffic,in the context of a callout routine for classification.
	FWPS_CALLOUT sCallout = { 0 };
	FWPM_CALLOUT mCallout = { 0 };
	NTSTATUS status;

	/* Register callout with the filter engine. */
	sCallout.calloutKey = *calloutKey;
	sCallout.notifyFn = notifyFn;
	sCallout.classifyFn = classifyFn;
	status = FwpsCalloutRegister(deviceObject, &sCallout, calloutId);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	/* Add callout. */
	mCallout.applicableLayer = *layerKey;
	mCallout.calloutKey = *calloutKey;
	mCallout.displayData.name = calloutName;
	mCallout.displayData.description = calloutDescription;
	status = FwpmCalloutAdd(hEngine, &mCallout, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		FwpsCalloutUnregisterById(*calloutId);
		*calloutId = 0;
		return status;
	}

	/* Add filter. */
	status = AddFilter(L"TCP/UDP", L"Filter TCP/UDP", 0, layerKey, calloutKey);
	if (!NT_SUCCESS(status)) {
		FwpsCalloutUnregisterById(*calloutId);
		*calloutId = 0;
		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegisterCallouts(_Inout_ void* deviceObject)
{

	FWPM_SESSION session = { 0 };
	FWPM_SUBLAYER TLInspectSubLayer;	// FWPM_LAYER:The WFP layer identifiers are each represented by a GUID
	NTSTATUS status;

	/* If session.flags is set to FWPM_SESSION_FLAG_DYNAMIC, any WFP objects
	* added during the session are automatically deleted when the session ends.
	*/
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	/* Open session to the filter engine. */
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &hEngine);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	/* Begin transaction with the current session. */
	status = FwpmTransactionBegin(hEngine, 0);
	if (!NT_SUCCESS(status)) {
		FwpmEngineClose(hEngine);
		hEngine = NULL;
		return status;
	}

	/* Add sublayer to the system. */
	RtlZeroMemory(&TLInspectSubLayer, sizeof(FWPM_SUBLAYER));
	TLInspectSubLayer.subLayerKey = TL_INSPECT_SUBLAYER;	//define by self
	TLInspectSubLayer.displayData.name = L"Transport Inspect Sub-Layer";
	TLInspectSubLayer.displayData.description = L"Sub-Layer for use by Transport Inspect callouts";
	TLInspectSubLayer.flags = 0;
	TLInspectSubLayer.weight = 0;
	status = FwpmSubLayerAdd(hEngine, &TLInspectSubLayer, NULL);
	if (!NT_SUCCESS(status)) {
		FwpmTransactionAbort(hEngine);
		_Analysis_assume_lock_not_held_(hEngine);
		FwpmEngineClose(hEngine);
		hEngine = NULL;
		return status;
	}

	int arraysize = sizeof(callouts) / sizeof(callouts[0]);
	for (size_t i = 0; i < arraysize; i++) {
		status = RegisterCallout(callouts[i].layerKey,
			callouts[i].calloutKey,
			deviceObject,
			callouts[i].notifyFn,
			callouts[i].classifyFn,
			callouts[i].name,
			callouts[i].description,
			callouts[i].calloutId);
		if (!NT_SUCCESS(status)) {
			FwpmTransactionAbort(hEngine);
			_Analysis_assume_lock_not_held_(hEngine);
			FwpmEngineClose(hEngine);
			hEngine = NULL;
			return status;
		}
	}

	//icmpfilter();

	status = FwpmTransactionCommit(hEngine);
	if (!NT_SUCCESS(status)) {
		FwpmTransactionAbort(hEngine);
		_Analysis_assume_lock_not_held_(hEngine);
		FwpmEngineClose(hEngine);
		hEngine = NULL;
		return status;
	}

	return STATUS_SUCCESS;
}

void UnregisterCallouts()
{
	FwpsCalloutUnregisterById(layerStreamV4);
	FwpsCalloutUnregisterById(layerStreamV6);
	FwpsCalloutUnregisterById(layerDatagramV4);
	FwpsCalloutUnregisterById(layerDatagramV6);
	FwpsCalloutUnregisterById(layerIcmpV4);
	// 	FwpsCalloutUnregisterById(layerAleClosureV4);
	// 	FwpsCalloutUnregisterById(layerAleClosureV6);

	FwpmEngineClose(hEngine);
	hEngine = NULL;
}