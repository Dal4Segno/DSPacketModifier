#pragma once
#include "stdafx.h"
#include "PacketGlobalHeader.h"
#include "IpFrame.h"
#include "IcmpHeader.h"

struct EthernetFrame
{
	uint8_t srcMac[6];
	uint8_t dstMac[6];
	uint16_t packetType = 0x08;
};

int GetTimeOfDay(timeval * tp);
uint16_t GetInternetCheckSum(uint32_t u32Size, uint16_t * pData);