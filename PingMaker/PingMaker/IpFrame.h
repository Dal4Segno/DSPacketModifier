#pragma once
#include "stdafx.h"

struct IpFrame
{
	uint8_t u8IpVersionAndLength;
	uint8_t u8IpTypeOfService;
	uint16_t u16IpTotalLength;
	uint16_t u16IpIdentification;
	uint16_t u16FragmentOffset;
	uint8_t u8IpTimeToLive;
	uint8_t u8IpProtocol;
	uint16_t u8IpCheckSum;
	IN_ADDR srcIp;
	IN_ADDR dstIp;
};