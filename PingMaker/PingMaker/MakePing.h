#pragma once
#include "stdafx.h"

struct IpFrame
{
	UINT8 u8IpVersionAndLength;
	UINT8 u8IpTypeOfService;
	UINT16 u16IpTotalLength;
	UINT16 u16IpIdentification;
	UINT16 u16FragmentOffset;
	UINT8 u8IpTimeToLive;
	UINT8 u8IpProtocol;
	UINT16 u8IpCheckSum;
	IN_ADDR srcIp;
	IN_ADDR dstIp;
};

struct IcmpHeader
{
	UINT8 u8IcmpType;
	UINT8 u8IcmpCode;
	UINT16 u16IcmpCheckSum;
	UINT16 u16IcmpIdentifier;
	UINT16 u16IcmpSequenceNumber;
};

bool MakePing(const po::variables_map &vm);
void WriteGlobalHeader(HANDLE &hOutputFile);
void WritePacketHeader(HANDLE & hOutputFile, const UINT16 & u16DataLength);
void WriteEthernetFrame(HANDLE &hOutputFile, const std::vector<UINT8> &srcMac, const std::vector<UINT8> &dstMac);
void WriteIpFrame(HANDLE & hOutputFile, IpFrame & ipFrame);
void WriteIcmpFrame(HANDLE & hOutputFile, IcmpHeader & icmpHeader, const UINT16 u16SequenceNumber, const UINT16 u16DataLength, const UINT16 * pData);
void PrintInvalidValueError(const string key, const string value, const string msg);

int GetTimeOfDay(timeval * tp);

void SetIpFrame(IpFrame & ipFrame, const UINT16 & u16DataLength, const sockaddr_in & srcIp, const sockaddr_in & dstIp);
void SetIcmpHeader(IcmpHeader & icmpHeader);
