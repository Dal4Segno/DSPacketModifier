#pragma once
#include "stdafx.h"

struct IcmpHeader
{
	uint8_t u8IcmpType;
	uint8_t u8IcmpCode;
	uint16_t u16IcmpCheckSum;
	uint16_t u16IcmpIdentifier;
	uint16_t u16IcmpSequenceNumber;

	IcmpHeader();
};