#include <stddef.h>
#include <ndis.h>
#include <fwpsk.h>
#include "inspect.h"
#include "worker_thread.h"
#include "packet_pool.h"
#include "utils.h"

#include "packetFilter.h"




HANDLE gInjectionHandle;

void
NTAPI
InjectionCompletionFn(
	IN void* context,
	IN OUT NET_BUFFER_LIST* netBufferList,
	IN BOOLEAN dispatchLevel
)
{
	FWPS_TRANSPORT_SEND_PARAMS0* tlSendArgs
		= (FWPS_TRANSPORT_SEND_PARAMS0*)context;

	//
	// TODO: Free tlSendArgs and embedded allocations.
	//

	//
	// TODO: Check netBufferList->Status for injection result
	//

	FwpsFreeCloneNetBufferList0(netBufferList, 0);
}


void StreamClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
#if(NTDDI_VERSION >= NTDDI_WIN7)
	_In_opt_ const void* classifyContext,
#endif
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut);

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
)
{
	NTSTATUS status;

	NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerData;
	NET_BUFFER_LIST* clonedNetBufferList = NULL;
	FWPS_PACKET_INJECTION_STATE injectionState;
	FWPS_TRANSPORT_SEND_PARAMS0* tlSendArgs = NULL;
	ADDRESS_FAMILY af = AF_UNSPEC;

	injectionState = FwpsQueryPacketInjectionState0(
		gInjectionHandle,
		netBufferList,
		NULL);
	if (injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
		injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
	{
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto Exit;
	}

	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		//
		// Cannot alter the action.
		//
		goto Exit;
	}

	//
	// TODO: Allocate and populate tlSendArgs by using information from
	// inFixedValues and inMetaValues.
	// Note: 1) Remote address and controlData (if not NULL) must
	// be deep-copied.
	//       2) IPv4 address must be converted to network order.
	//       3) Handle allocation errors.

	ASSERT(tlSendArgs != NULL);

	status = FwpsAllocateCloneNetBufferList0(
		netBufferList,
		NULL,
		NULL,
		0,
		&clonedNetBufferList);

	if (!NT_SUCCESS(status))
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

		goto Exit;
	}

	// 
	// TODO: Perform modification to the cloned net buffer list here.
	//

	//
	// TODO: Set af based on inFixedValues->layerId.
	//
	ASSERT(af == AF_INET || af == AF_INET6);

	//
	// Note: For TCP traffic, FwpsInjectTransportReceiveAsync0 and
	// FwpsInjectTransportSendAsync0 must be queued and run by a DPC.
	//

	status = FwpsInjectTransportSendAsync0(
		gInjectionHandle,
		NULL,
		inMetaValues->transportEndpointHandle,
		0,
		tlSendArgs,
		af,
		inMetaValues->compartmentId,
		clonedNetBufferList,
		InjectionCompletionFn,
		tlSendArgs);

	if (!NT_SUCCESS(status))
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

		goto Exit;
	}
	classifyOut->actionType = FWP_ACTION_PERMIT;
	//classifyOut->actionType = FWP_ACTION_BLOCK;
	classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

	//
	// Ownership of clonedNetBufferList and tlSendArgs
	// now transferred to InjectionCompletionFn.
	//
	clonedNetBufferList = NULL;
	tlSendArgs = NULL;

Exit:

	if (clonedNetBufferList != NULL)
	{
		FwpsFreeCloneNetBufferList0(clonedNetBufferList, 0);
	}
	if (tlSendArgs != NULL)
	{
		//
		// TODO: Free tlSendArgs and embedded allocations.
		//
	}

	return;
}



NTSTATUS StreamNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

#if DEBUG
	DbgPrint("StreamNotify() value:%d", notifyType);
#endif

	return STATUS_SUCCESS;
}



void StreamClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
#if(NTDDI_VERSION >= NTDDI_WIN7)
	_In_opt_ const void* classifyContext,
#endif
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
	packet_t* packet;

	UNREFERENCED_PARAMETER(inMetaValues);

#if(NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(classifyContext);
#endif

	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

#if DEBUG
	DbgPrint("StreamClassify()");
#endif

	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		return;
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;
	int result = packetFilter(inFixedValues, layerData);
	if (result)
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
	}

	if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
	{
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}
	return;

	/* Get packet from the packet pool. */
	if ((packet = PopPacket()) != NULL) {
		if (getPacket(inFixedValues, layerData, packet)) {
			if (!GivePacketToWorkerThread(packet)) {
				/* Return packet to packet pool. */
				PushPacket(packet);
			}
		}
		else {
			/* Return packet to packet pool. */
			PushPacket(packet);
		}
	}

	FWPS_STREAM_CALLOUT_IO_PACKET0* pkt =
		(FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;

	/* If we want to get all the data, use:
	* pkt-> streamAction = FWP_ACTION_CONTINUE;
	*/
	pkt->streamAction = FWPS_STREAM_ACTION_ALLOW_CONNECTION;
	pkt->countBytesEnforced = 0;
	pkt->countBytesRequired = 0;

	classifyOut->actionType = FWP_ACTION_CONTINUE;

}



//The filter engine calls a callout's notifyFn1 callout function to notify the callout driver about events that are associated with the callout.
NTSTATUS DatagramNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

#if DEBUG
	DbgPrint("DatagramNotify() value:%d", notifyType);
#endif

	return STATUS_SUCCESS;
}


//The filter engine calls a callout's classifyFn0 callout function whenever there is data to be processed by the callout.
void DatagramClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
#if(NTDDI_VERSION >= NTDDI_WIN7)
	_In_opt_ const void* classifyContext,
#endif
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
	packet_t* packet;

#if(NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(classifyContext);
#endif

	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

#if DEBUG
	DbgPrint("DatagramClassify()");
#endif

	int result = 0;

	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		return;
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;

	result = packetFilter(inFixedValues, layerData);
	if (result)
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
	}

	if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
	{
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}

	return;

	/* ipHeaderSize is not applicable to the outbound path at the
	* FWPS_LAYER_DATAGRAM_DATA_V4/FWPS_LAYER_DATAGRAM_DATA_V6
	* layers.
	*/
	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_IP_HEADER_SIZE)) {
		/* Get packet from the packet pool. */
		if ((packet = PopPacket()) != NULL) {
			if (getPacket(inFixedValues, layerData, packet)) {
				if (!GivePacketToWorkerThread(packet)) {
					/* Return packet to packet pool. */
					PushPacket(packet);
				}
			}
			else {
				/* Return packet to packet pool. */
				PushPacket(packet);
			}
		}
	}

	classifyOut->actionType = FWP_ACTION_CONTINUE;
}




NTSTATUS AleClosureNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

#if DEBUG
	DbgPrint("AleClosureNotify() value:%d", notifyType);
#endif

	return STATUS_SUCCESS;
}

void AleClosureClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
#if (NTDDI_VERSION >= NTDDI_WIN7)
	_In_opt_ const void* classifyContext,
#endif
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
	return;

	packet_t* packet;

	UNREFERENCED_PARAMETER(inMetaValues);

#if(NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(classifyContext);
#endif

	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

#if DEBUG
	DbgPrint("AleClosureClassify()");
#endif

	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		return;
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;

	int result = packetFilter(inFixedValues, layerData);
	if (result)
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
	}

	if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
	{
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}
	return;

	/* Get packet from the packet pool. */
	if ((packet = PopPacket()) != NULL) {
		if (getPacket(inFixedValues, layerData, packet)) {
			if (!GivePacketToWorkerThread(packet)) {
				/* Return packet to packet pool. */
				PushPacket(packet);
			}
		}
		else {
			/* Return packet to packet pool. */
			PushPacket(packet);
		}
	}

	classifyOut->actionType = FWP_ACTION_CONTINUE;
}
