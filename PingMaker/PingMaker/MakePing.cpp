#include <time.h>
#include "stdafx.h"
#include "MakePing.h"

/*
*	예외처리는 나중에 일괄 처리하도록 함.
*/

static DWORD dwBytesWrite;

bool MakePing(const po::variables_map & vm)
{
	using boost::any_cast;
	
	// Open Output File
	HANDLE hOutputFile = CreateFileA(any_cast<string>(vm.at("output").value()).c_str() ,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hOutputFile == NULL)
	{
		std::cerr << "Can't Make Result File\n";
		return false;
	}

	// Open Injection File or String
	bool isFileInput;
	std::vector<UINT8> vData;
	HANDLE hInjectionFile;
	string sInjectionString;
	if (any_cast<string>(vm.at("type").value()) == "file")
	{
		hInjectionFile = CreateFileA(any_cast<string>(vm.at("input").value()).c_str(),
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
			NULL);
		
		LARGE_INTEGER liFileSize;
		GetFileSizeEx(hInjectionFile, &liFileSize);
		vData.resize(static_cast<unsigned int>(liFileSize.QuadPart));

		DWORD dwByteRead;
		ReadFile(hInjectionFile, vData.data(), static_cast<unsigned int>(liFileSize.QuadPart), &dwByteRead, NULL);
		isFileInput = true;
	} 
	else if (any_cast<string>(vm.at("type").value()) == "string")
	{
		sInjectionString = any_cast<string>(vm.at("input").value());
		std::copy(sInjectionString.begin(), sInjectionString.end(), std::back_inserter(vData));
		isFileInput = false;
	}
	else
	{
		PrintInvalidValueError("type", any_cast<string>(vm.at("type").value()), "");
	}

	WriteGlobalHeader(hOutputFile);
	
	sockaddr_in srcIp, dstIp;
	std::vector<UINT8> srcMac{ 0, 8 }, dstMac{ 0, 8 };
	UINT16 u16SequenceNumber = 0;
	
	inet_pton(AF_INET, "192.168.0.1", &(srcIp.sin_addr));
	inet_pton(AF_INET, "192.168.0.2", &(dstIp.sin_addr));
	UINT16 u16DataLength = std::stoi(any_cast<string>(vm.at("size").value()));
	IpFrame ipFrame;
	SetIpFrame(ipFrame, u16DataLength, srcIp, dstIp);
	IcmpHeader icmpRequestHeader;
	SetIcmpHeader(icmpRequestHeader);
	UINT16 * pData = (UINT16 *)vData.data();
	for (UINT64 i = 0; i < vData.size(); i += u16DataLength)
	{
		WritePacketHeader(hOutputFile, u16DataLength);
		WriteEthernetFrame(hOutputFile, srcMac, dstMac);
		WriteIpFrame(hOutputFile, ipFrame);
		WriteIcmpFrame(hOutputFile, icmpRequestHeader, u16SequenceNumber, u16DataLength,pData);
		u16SequenceNumber++;
		pData += (u16DataLength/2);
	}

	return true;
}

void WriteGlobalHeader(HANDLE & hOutputFile)
{
	u_char cSignature[4] { 0xD4, 0xC3, 0xB2, 0xA1 };
	UINT16 u16MajorVersion{ 2 }, u16MinorVersion{ 4 };
	UINT64 u64TimeStamp{ 0 };
	UINT32 u32SnapshotLength{ 65535 }, u32NetworkType{ 1 };

	WriteFile(hOutputFile, cSignature, 4, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, &u16MajorVersion, 2, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, &u16MinorVersion, 2, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, &u64TimeStamp, 8, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, &u32SnapshotLength, 4, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, &u32NetworkType, 4, &dwBytesWrite, NULL);
}

void WritePacketHeader(HANDLE & hOutputFile, const UINT16 & u16DataLength)
{
	static pcap_pkthdr packetHeader;
	GetTimeOfDay(&packetHeader.ts);
	packetHeader.caplen = 14 + 20 + 8 + u16DataLength ;
	packetHeader.len = packetHeader.caplen;

	WriteFile(hOutputFile, &packetHeader.ts.tv_sec, 4, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, &packetHeader.ts.tv_usec, 4, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, &packetHeader.caplen, 4, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, &packetHeader.len, 4, &dwBytesWrite, NULL);
}

void WriteEthernetFrame(HANDLE & hOutputFile, const std::vector<UINT8>& srcMac, const std::vector<UINT8>& dstMac)
{
	static UINT16 d16PacketType = 0x08;

	WriteFile(hOutputFile, srcMac.data(), 6, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, dstMac.data(), 6, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, &d16PacketType, 2, &dwBytesWrite, NULL);
}

void WriteIpFrame(HANDLE & hOutputFile, IpFrame &ipFrame)
{
	std::random_device rd;   // non-deterministic generator  
	std::mt19937 gen(rd());  // to seed mersenne twister.  
	std::uniform_int_distribution<> distTimeToLive(1, 240); // distribute results between 1 and 6 inclusive.  
	std::uniform_int_distribution<> distIdentification(1, 0xFFFF); // distribute results between 1 and 6 inclusive.  
	ipFrame.u8IpTimeToLive = distTimeToLive(gen);
	ipFrame.u16IpIdentification = distIdentification(gen);
	ipFrame.u8IpCheckSum = 0;

	UINT16 *p = (UINT16 *)&ipFrame;
	UINT32 sum32 = 0;
	UINT32 sum16 = 0;
	for (int i = 0; i < 20; i += 1)
	{
		sum32 += *(p + i);
	}
	p = (UINT16 *)&sum32;
	sum16 = *(p)+*(p + 1);
	ipFrame.u8IpCheckSum = ~sum16;

	WriteFile(hOutputFile, &ipFrame, 20, &dwBytesWrite, NULL);
}

void WriteIcmpFrame(HANDLE & hOutputFile, IcmpHeader &icmpHeader, const UINT16 u16SequenceNumber, const UINT16 u16DataLength, const UINT16 * pData)
{
	icmpHeader.u16IcmpCheckSum = 0;
	icmpHeader.u16IcmpSequenceNumber = u16SequenceNumber;

	UINT16 *p = (UINT16 *)&icmpHeader;
	UINT32 sum32 = 0;
	UINT32 sum16 = 0;
	for (int i = 0; i < 4; i++)
	{
		sum32 = *(p + i);
	}
	for (int i = 0; i < (u16DataLength/2); i++)
	{
		sum32 += *(pData + i);
	}
	sum32 = (sum32 >> 16) + (sum32 & 0xFFFF);
	sum32 += (sum32 >> 16);
	
	p = (UINT16 *)&sum32;
	sum16 = *(p)+*(p + 1);
	sum16 += *(p);
	icmpHeader.u16IcmpCheckSum = (~sum32 & 0xFFFF) - 9;

	WriteFile(hOutputFile, &icmpHeader, 8, &dwBytesWrite, NULL);
	WriteFile(hOutputFile, pData, u16DataLength, &dwBytesWrite, NULL);
}

void PrintInvalidValueError(const string key, const string value, const string msg)
{
	std::cerr << "Invalid Input " << value << " for " << key << std::endl;
	if (!msg.empty())
	{
		std::cerr << msg << std::endl;
	}
}

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

void SetIpFrame(IpFrame & ipFrame, const UINT16 & u16DataLength, const sockaddr_in & srcIp, const sockaddr_in & dstIp)
{
	ipFrame.u8IpVersionAndLength = 0x45;	// Version 4 and 20 Header Size
	ipFrame.u8IpTypeOfService = 0x00;
	ipFrame.u16IpTotalLength = _byteswap_ushort(20 + 8 + u16DataLength);
	ipFrame.u16IpIdentification;
	ipFrame.u16FragmentOffset = 0;
	ipFrame.u8IpTimeToLive;
	ipFrame.u8IpProtocol = 0x01;	// ICMP
	ipFrame.u8IpCheckSum = 0;
	ipFrame.srcIp = srcIp.sin_addr;
	ipFrame.dstIp = dstIp.sin_addr;
}

void SetIcmpHeader(IcmpHeader & icmpHeader)
{
	icmpHeader.u8IcmpType = 0x08;
	icmpHeader.u8IcmpCode = 0x00;
	icmpHeader.u16IcmpIdentifier = 0x01;
	icmpHeader.u16IcmpCheckSum = 0x00;
}

UINT16 GetInternetCheckSum(UINT32 u32Size, UINT16 * pData)
{
	UINT32 sum32 = 0;
	UINT32 sum16 = 0;
	for (UINT32 i = 0; i < u32Size; i += 2)
	{
		sum32 += _byteswap_ushort(*(pData + i));
	}
	UINT16 *p = (UINT16 *)&sum32;
	sum16 = *(p)+*(p + 1);
	return ~sum16;
}