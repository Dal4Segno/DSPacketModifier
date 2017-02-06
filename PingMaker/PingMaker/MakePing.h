#pragma once
#include "stdafx.h"

bool MakePing(const po::variables_map &vm);
void WriteGlobalHeader(HANDLE &hOutputFile);
void WritePacketHeader(HANDLE &hOutputFile);
void WriteEthernetFrame(HANDLE &hOutputFile, const std::vector<UINT8> &srcMac, const std::vector<UINT8> &dstMac);
void WriteIpFrame(HANDLE &hOutputFile, const sockaddr_in &srcIp, const sockaddr_in &dstIp);
void WriteIcmpFrame(HANDLE &hOutputFile, const UINT16 u16SequenceNumber);
void PrintInvalidValueError(const string key, const string value, const string msg);