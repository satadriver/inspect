#pragma once

#ifndef INSPECT_H_H_H
#define INSPECT_H_H_H

#include <ntddk.h>

#include <wdf.h>

#include <fwpsk.h>

#include <fwpmk.h>

#define INITGUID

#include <guiddef.h>

#define NUMBER_BUCKETS		127
#define MAX_DNS_ENTRIES		1024
#define WFP_DEVICE_NAME		L"\\device\\inspect"
#define WFP_DEVICE_SYMBOL	L"\\DosDevices\\inspect"
#define MAX_PAYLOAD_SIZE	0x10000


#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))


#endif
