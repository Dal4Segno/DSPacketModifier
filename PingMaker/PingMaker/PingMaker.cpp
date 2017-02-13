#pragma once
#include "stdafx.h"
#include "PingMaker.h"


PingMaker::PingMaker()
{
}

PingMaker::PingMaker(const po::variables_map &vm)
{
	using boost::any_cast;
	injectType = any_cast<string>(vm["type"].value());
	srcIp = any_cast<string>(vm["srcip"].value());
	dstIp = any_cast<string>(vm["dstip"].value());
	InitIpFrame(srcIp, dstIp);
	//srcMac = any_cast<string>(vm["srcmac"].value());
	//dstMac = any_cast<string>(vm["dstmac"].value());
	InitEthernetFrame(srcMac, dstMac);
	dataLength = std::stoi(any_cast<string>(vm["size"].value()));

	if (injectType == "file")
	{
		injectionFile.open(any_cast<string>(vm["input"].value()), std::ifstream::binary);
		injectionFile.seekg(0, injectionFile.end);
		unsigned int fileLength = injectionFile.tellg();
		injectionFile.seekg(0, injectionFile.beg);
		data.resize(fileLength);
		injectionFile.read(data.data(), fileLength);
	}
	else if (injectType == "string")
	{
		injectionString += any_cast<string>(vm["input"].value());
		std::copy(injectionString.begin(), injectionString.end(), std::back_inserter(data));
	}
	pData = reinterpret_cast<uint16_t *>(data.data());
	outputFile.open(any_cast<string>(vm["output"].value()), std::ofstream::binary);
	
	UINT16 *p = (UINT16 *)&icmpHeader;
	for (int i = 0; i < 4; i++)
	{
		icmpPartialCheckSum = *(p + i);
	}
}

PingMaker::~PingMaker()
{
	if (injectType == "file")
		injectionFile.close();
	outputFile.close();
}

void PingMaker::InitEthernetFrame(const string srcMacString, const string dstMacString)
{
	//ethernetFrame.srcMac;
	//ethernetFrame.dstMac;
	ethernetFrame.packetType = 0x08;
}

void PingMaker::InitIpFrame(const string srcIpString, const string dstIpString)
{
	ipFrame.u8IpVersionAndLength = 0x45;	// Version 4 and 20 Header Size
	ipFrame.u8IpTypeOfService = 0x00;
	ipFrame.u16IpTotalLength = _byteswap_ushort(20 + 8 + dataLength);
	ipFrame.u16IpIdentification;
	ipFrame.u16FragmentOffset = 0;
	ipFrame.u8IpTimeToLive = 250;
	ipFrame.u8IpProtocol = 0x01;	// ICMP
	ipFrame.u8IpCheckSum = 0;
	
	inet_pton(AF_INET, this->srcIp.c_str(), &(ipFrame.srcIp));
	inet_pton(AF_INET, this->dstIp.c_str(), &(ipFrame.dstIp));
}

void PingMaker::SetPacketHeader()
{
	GetTimeOfDay(&packetHeader.ts);
	packetHeader.caplen = 14 + 20 + 8 + dataLength;
	packetHeader.len = packetHeader.caplen;
}

void PingMaker::SetIpFrame()
{
	std::uniform_int_distribution<> distTimeToLive(1, 240);
	std::uniform_int_distribution<> distIdentification(1, 0xFFFF);
	ipFrame.u8IpTimeToLive = distTimeToLive(gen);
	ipFrame.u16IpIdentification = distIdentification(gen);
	ipFrame.u8IpCheckSum = 0;

	uint16_t *p = (uint16_t *)&ipFrame;
	ipFrame.u8IpCheckSum = GetInternetCheckSum(20, p);
}

void PingMaker::SetIcmpFrame(uint16_t *pData)
{
	icmpHeader.u16IcmpSequenceNumber = sequenceNumber;
	++sequenceNumber;

	UINT32 sum32 = icmpPartialCheckSum;
	UINT32 sum16 = 0;
	for (int i = 0; i < (dataLength / 2); i++)
	{
		sum32 += *(pData + i);
	}
	sum32 = (sum32 >> 16) + (sum32 & 0xFFFF);
	sum32 += (sum32 >> 16);

	uint16_t *p = (uint16_t *)&sum32;
	sum16 = *(p)+*(p + 1);
	sum16 += *(p);
	icmpHeader.u16IcmpCheckSum = (~sum32 & 0xFFFF) - 9;
}

void PingMaker::WritePacketToOutput()
{
	outputFile.write(reinterpret_cast<char *>(&packetHeader), sizeof(pcap_pkthdr));
	outputFile.write(reinterpret_cast<char *>(&ethernetFrame), sizeof(EthernetFrame));
	outputFile.write(reinterpret_cast<char *>(&ipFrame), sizeof(IpFrame));
	outputFile.write(reinterpret_cast<char *>(&icmpHeader), sizeof(IcmpHeader));
	outputFile.write(reinterpret_cast<char *>(pData), dataLength);
}

void PingMaker::MakePcap()
{
	outputFile.write(reinterpret_cast<char *>(&globalHeader), sizeof(PacketGlobalHeader));
	for (uint64_t i = 0; i < data.size(); i += dataLength)
	{
		SetPacketHeader();
		SetIcmpFrame(pData);
		WritePacketToOutput();
		pData += (dataLength / 2);
	}
}