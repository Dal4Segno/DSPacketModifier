#pragma once
#include "stdafx.h"
#include "DSPacket.h"
#include <fstream>

class PingMaker
{
	string injectType;
	std::ifstream injectionFile;
	string injectionString;
	std::ofstream outputFile;
	string srcIp, dstIp;
	string srcMac, dstMac;
	uint16_t dataLength;
	std::vector<char> data;
	uint16_t *pData;

	std::random_device rd;
	std::mt19937 gen{rd()};

	uint16_t sequenceNumber{};
	PacketGlobalHeader globalHeader;
	pcap_pkthdr packetHeader;
	EthernetFrame ethernetFrame;
	IpFrame ipFrame;
	IcmpHeader icmpHeader;

	uint32_t icmpPartialCheckSum{};

public:
	PingMaker();
	PingMaker(const po::variables_map &vm);
	~PingMaker();
	void InitEthernetFrame(const string srcMacString, const string dstMacString);
	void InitIpFrame(const string srcIpString, const string dstIpString);
	void SetPacketHeader();
	void SetIpFrame();
	void SetIcmpFrame(uint16_t * pData);
	void WritePacketToOutput();
	void MakePcap();
};

