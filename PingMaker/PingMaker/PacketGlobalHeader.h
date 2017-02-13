#pragma once
#include "stdafx.h"

struct PacketGlobalHeader
{
	u_char cSignature[4]{ 0xD4, 0xC3, 0xB2, 0xA1 };
	uint16_t u16MajorVersion{ 2 }, u16MinorVersion{ 4 };
	uint64_t u64TimeStamp{ 0 };
	uint32_t u32SnapshotLength{ 65535 }, u32NetworkType{ 1 };
};