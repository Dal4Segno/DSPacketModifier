#include "DSPacket.h"
#include "stdafx.h"
#include "IcmpHeader.h"

int GetTimeOfDay(timeval * tp)
{
	// Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
	// This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
	// until 00:00:00 January 1, 1970 
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME  system_time;
	FILETIME    file_time;
	uint64_t    time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec = (long)((time - EPOCH) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
}

uint16_t GetInternetCheckSum(uint32_t u32Size, uint16_t * pData)
{
	uint32_t sum32 = 0;
	uint32_t sum16 = 0;
	for (uint32_t i = 0; i < u32Size; i += 2)
	{
		sum32 += _byteswap_ushort(*(pData + i));
	}
	uint16_t *p = (uint16_t *)&sum32;
	sum16 = *(p)+*(p + 1);
	return ~sum16;
}

IcmpHeader::IcmpHeader()
{
	u8IcmpType = 0x08;
	u8IcmpCode = 0x00;
	u16IcmpIdentifier = 0x01;
	u16IcmpCheckSum = 0x00;
}