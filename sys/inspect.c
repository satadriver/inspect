
#include <ntifs.h>
#include <fwpsk.h>
#include <fwpmk.h>

#include "inspect.h"
#include "worker_thread.h"
#include "packet_pool.h"
#include "dnscache.h"
#include "logfile.h"
#include "packetFilter.h"
#include "list.h"
#include "configfile.h"
#include "callback.h"
#include "utils.h"

#include <ntstrsafe.h>
#include <ip2string.h>

#include "wfpHelper.h"



_Function_class_(EVT_WDF_DRIVER_UNLOAD)

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;

EVT_WDF_DEVICE_FILE_CREATE EvtDeviceFileCreate;

EVT_WDF_FILE_CLOSE EvtFileClose;

EVT_WDF_DRIVER_DEVICE_ADD EvtWdfDriverDeviceAdd;



#pragma alloc_text(PAGE, EvtWdfDriverDeviceAdd)


extern NTSTATUS RegisterCallouts(_Inout_ void* deviceObject);

extern void UnregisterCallouts();



_IRQL_requires_same_ _IRQL_requires_max_(PASSIVE_LEVEL) void EvtDriverUnload(_In_ WDFDRIVER driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);

	UnregisterCallouts();
	// 	StopWorkerThread();
	// 	FreeWorkerThread();
	// 	CloseLogFile();
	// 	FreeDnsCache();
	// 	FreePacketPool();

// 	IoDeleteDevice(g_ctrldev);
// 	UNICODE_STRING symbol;
// 	RtlInitUnicodeString(&symbol, WFP_DEVICE_SYMBOL);
// 	IoDeleteSymbolicLink(&symbol);
}




NTSTATUS EvtWdfDriverDeviceAdd(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit) {

	return STATUS_SUCCESS;
}

VOID EvtDeviceFileCreate(__in WDFDEVICE Device, __in WDFREQUEST Request, __in WDFFILEOBJECT FileObject)
{
	KdPrint(("EvtDeviceFileCreate"));

	WdfRequestComplete(Request, STATUS_SUCCESS);
}

VOID EvtFileClose(__in  WDFFILEOBJECT FileObject)
{
	KdPrint(("EvtFileClose"));
}

NTSTATUS EvtWdfdeviceWdmIrpDispatch(WDFDEVICE Device, UCHAR MajorFunction, UCHAR MinorFunction, ULONG Code,
	WDFCONTEXT DriverContext, PIRP Irp, WDFCONTEXT DispatchContext
)
{
	return 0;
}

//EVT_WDFDEVICE_WDM_IRP_DISPATCH EvtWdfdeviceWdmIrpDispatch;


NTSTATUS WfpCtrlIRPDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	//__debugbreak();

	PIO_STACK_LOCATION	IrpStack = 0;
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	if (Irp == NULL)
	{
		return nStatus;
	}

	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	if (IrpStack == NULL)
	{
		return nStatus;
	}

	if (IrpStack->MajorFunction != IRP_MJ_DEVICE_CONTROL)
	{
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	UNREFERENCED_PARAMETER(DeviceObject);

	switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_WFP_SDWS_ADD_TCP:
	{
		PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG uInLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
		nStatus = addFilterRule((NETWORK_FILTER_PARAMS*)pSystemBuffer);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WFP_SDWS_CLEAR_TCP: {
		delFilterRule();
		break;
	}
	case IOCTL_WFP_SDWS_ADD_DNS:
	{
		PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG uInLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
		nStatus = addDnsRule(pSystemBuffer, uInLen);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WFP_SDWS_ADD_URL:
	{
		PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG uInLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
		nStatus = addDnsRule(pSystemBuffer, uInLen);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WFP_SDWS_ADD_SERVER:
	{
		PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		DWORD ipv4 = *(DWORD*)pSystemBuffer;
		setDnsTarget(ipv4);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WFP_SDWS_ADD_PORT:
	{
		PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		addIPPortRule(pSystemBuffer, IOCTL_WFP_SDWS_ADD_PORT);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WFP_SDWS_ADD_IPV4:
	{
		PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		addIPPortRule(pSystemBuffer, IOCTL_WFP_SDWS_ADD_IPV4);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WFP_SDWS_ADD_IPV6:
	{
		PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		addIPPortRule(pSystemBuffer, IOCTL_WFP_SDWS_ADD_IPV6);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WFP_SDWS_ADD_PROCESS:
	{
		PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		addProcessRule(pSystemBuffer, IOCTL_WFP_SDWS_ADD_PROCESS);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WFP_SDWS_ADD_INTRANET:
	{
		PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		BOOL enable = *(BOOL*)pSystemBuffer;
		setIntranet(enable);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_WFP_SDWS_CLEAR_DNS:
	{
		clearDnsList();
		break;
	}
	case IOCTL_WFP_SDWS_CLEAR_IPPORT:
	{
		clearIPPortList();
	}
	case IOCTL_WFP_SDWS_CLEAR_PROCESS:
	{
		clearProcessList();
	}
	default:
	{
		nStatus = STATUS_UNSUCCESSFUL;
	}
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = nStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return nStatus;
}


static NTSTATUS InitDriverObjects(_Inout_ DRIVER_OBJECT* driverObject, _In_ const UNICODE_STRING* registryPath, _Out_ WDFDRIVER* pDriver, _Out_ WDFDEVICE* pDevice)
{
	NTSTATUS status;

	WDF_DRIVER_CONFIG config;

	WDF_FILEOBJECT_CONFIG f_cfg;

	//KdBreakPoint();

	WDF_DRIVER_CONFIG_INIT(&config, 0);
	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = EvtDriverUnload;

	status = WdfDriverCreate(driverObject, registryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, pDriver);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	PWDFDEVICE_INIT pInit = WdfControlDeviceInitAllocate(*pDriver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX);
	if (!pInit) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	UNICODE_STRING devname;
	RtlInitUnicodeString(&devname, WFP_DEVICE_NAME);

	status = WdfDeviceInitAssignName(pInit, &devname);  //status = WdfDeviceInitUpdateName(pInit, &devname);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[liujinguang]WdfDeviceInitAssignName %Z error", &devname);
		return status;
	}

	WdfDeviceInitSetDeviceType(pInit, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(pInit, FILE_DEVICE_SECURE_OPEN, FALSE);
	//WdfDeviceInitSetCharacteristics(pInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

	WDF_OBJECT_ATTRIBUTES object_attribs;
	WDF_OBJECT_ATTRIBUTES_INIT(&object_attribs);

	WDF_FILEOBJECT_CONFIG_INIT(&f_cfg, EvtDeviceFileCreate, EvtFileClose, NULL);
	WdfDeviceInitSetFileObjectConfig(pInit, &f_cfg, WDF_NO_OBJECT_ATTRIBUTES);

	status = WdfDeviceCreate(&pInit, &object_attribs, pDevice);
	if (!NT_SUCCESS(status)) {
		WdfDeviceInitFree(pInit);
		return status;
	}

	//WDM drivers do not name device objectsand therefore should not use this routine.
	// Instead, a WDM driver should call IoRegisterDeviceInterface to set up a symbolic link.
	//A named device object has a name of the form \Device\DeviceName. This is known as the NT device name of the device object.
	// WDF drivers do not need to name their PnP device in order to create a symbolic link using WdfDeviceCreateSymbolicLink.

	UNICODE_STRING symbol;
	RtlInitUnicodeString(&symbol, WFP_DEVICE_SYMBOL);
	status = WdfDeviceCreateSymbolicLink(*pDevice, &symbol);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[liujinguang]WdfDeviceCreateSymbolicLink %Z error\r\n", &symbol);
	}

	DRIVER_OBJECT* wfpdriver = WdfDriverWdmGetDriverObject(*pDriver);
	wfpdriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WfpCtrlIRPDispatch;

	//status = WdfDeviceConfigureWdmIrpDispatchCallback(*pDevice, *pDriver, IRP_MJ_DEVICE_CONTROL, WfpCtrlIRPDispatch, 0);

	WdfControlFinishInitializing(*pDevice);

	return STATUS_SUCCESS;
}



NTSTATUS DriverEntry(DRIVER_OBJECT* driverObject, UNICODE_STRING* registryPath)
{
	WDFDRIVER driver;
	WDFDEVICE device;
	DEVICE_OBJECT* wdmDevice;
	WDFKEY parametersKey;
	NTSTATUS status;

	//KdBreakPoint();
	//DbgBreakPoint();

	initAttackList();

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	//     if (!InitPacketPool(MAX_PACKETS, MAX_PACKET_SIZE)) {
	// 		DbgPrint("Error initializing packet pool.");
	// 		return STATUS_NO_MEMORY;
	//     }


	//     if (!InitDnsCache(NUMBER_BUCKETS, MAX_DNS_ENTRIES)) {
	// 		DbgPrint("Error initializing DNS cache.");
	// 		FreePacketPool();
	// 		return STATUS_NO_MEMORY;
	//     }


	//   status = OpenLogFile(LOG_BUFFER_SIZE);
	//   if (!NT_SUCCESS(status)) {
	//     DbgPrint("Error opening log file.");
	//     FreeDnsCache();
	//     FreePacketPool();
	//     return status;
	//   }


	//     if (!InitWorkerThread(MAX_PACKETS)) {
	//         DbgPrint("Error initializing worker thread.");
	//         CloseLogFile();
	//         FreeDnsCache();
	//         FreePacketPool();
	//         return STATUS_NO_MEMORY;
	//     }


	//     status = StartWorkerThread();
	//     if (!NT_SUCCESS(status)) {
	// 		DbgPrint("Error starting worker thread.");
	// 		FreeWorkerThread();
	// 		CloseLogFile();
	// 		FreeDnsCache();
	// 		FreePacketPool();
	// 		return status;
	//     }


	status = InitDriverObjects(driverObject, registryPath, &driver, &device);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = WdfDriverOpenParametersRegistryKey(driver, KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &parametersKey);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	wdmDevice = WdfDeviceWdmGetDeviceObject(device);

	WCHAR wdmname[1024];
	ULONG outlen = 0;
	status = ObQueryNameString(wdmDevice, (POBJECT_NAME_INFORMATION)wdmname, sizeof(wdmname), &outlen);
	PUNICODE_STRING devicename = (PUNICODE_STRING)wdmname;
	DbgPrint("[liujinguang]wdm device name:%ws NTDDI_VERSION:%x\r\n", devicename->Buffer, NTDDI_VERSION);

	// 	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	// 	{
	// 		driverObject->MajorFunction[i] = WfpCtrlIRPDispatch;
	// 	}

	// 	//driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WfpCtrlIRPDispatch;
	//      __debugbreak();
	//     GUID mydevguid = { 0x01234567,0x89ab,0xcdef,0,1,2,3,4,5,6,7 };
	//     UNICODE_STRING devname;
	//     RtlInitUnicodeString(&devname, L"\\device\\inspectnt");
	//     UNICODE_STRING sddl;
	//     RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;WD)");
	//     status = IoCreateDeviceSecure(driverObject, 0, &devname, FILE_DEVICE_UNKNOWN, 0, 0,&sddl, & mydevguid, &g_ctrldev);
	//     //status = IoCreateDevice(driverObject, 0, &devname, FILE_DEVICE_UNKNOWN, OBJ_CASE_INSENSITIVE, 0,  &g_pctrldev);
	//     if (NT_SUCCESS(status))
	//     {
	// 		UNICODE_STRING symbol;
	// 		RtlInitUnicodeString(&symbol, L"\\DosDevices\\inspectnt");
	// 		status = IoCreateSymbolicLink(&symbol, &devname);
	// 		if (NT_SUCCESS(status))
	// 		{
	// 			g_ctrldev->Flags |= DO_BUFFERED_IO;
	// 			g_ctrldev->Flags |= DO_DIRECT_IO;
	// 			g_ctrldev->Flags &= (~DO_DEVICE_INITIALIZING);		
	// 		}
	//         else {
	//             DbgPrint("IoCreateSymbolicLink %Z error\r\n", &symbol);
	//         }
	//     }
	//     else {
	//         DbgPrint("IoCreateDevice error\r\n");
	//     }


	status = RegisterCallouts(wdmDevice);
	if (!NT_SUCCESS(status)) {
		UnregisterCallouts();
		return status;
	}

	//	__debugbreak();
	//  HANDLE thread_handle;
	// 	status = PsCreateSystemThread(&thread_handle,(ACCESS_MASK)0L,NULL,NULL,NULL,(PKSTART_ROUTINE)mainloop,0);
	// 	if (NT_SUCCESS(status)) {
	//         ZwClose(thread_handle);
	// 	}

	return STATUS_SUCCESS;
}
