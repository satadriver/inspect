#pragma once

#ifndef MYPACKET_H_H_H
#define MYPACKET_H_H_H

#include <ntddk.h>

#include "packet_pool.h"

BOOL getPacket(_In_ const FWPS_INCOMING_VALUES* inFixedValues, _Inout_opt_ void* layerData, _Out_ packet_t* packet);

int packetFilter(const FWPS_INCOMING_VALUES* inFixedValues, void* layerData);

int processDnsPacket(packet_t* packet);

int processHttpPacket(packet_t* packet);

int processDnsPacket(packet_t* packet);

#endif
