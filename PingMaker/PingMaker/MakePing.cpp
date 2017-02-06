#include "stdafx.h"
#include "MakePing.h"

/*
*	예외처리는 나중에 일괄 처리하도록 함.
*/
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
		vData.resize(liFileSize.QuadPart);

		DWORD dwByteRead;
		ReadFile(hInjectionFile, vData.data, liFileSize.QuadPart, &dwByteRead, NULL);
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
	
	/*
	inet_pton(AF_INET, "192.168.0.1", &(srcIp.sin_addr));
	inet_pton(AF_INET, "192.168.0.2", &(dstIp.sin_addr));
	*/

	UINT16 u16DataLength = std::stoi(any_cast<string>(vm.at("size").value()));
	for (UINT64 i = 0; i < vData.size(); i += u16DataLength)
	{
		WritePacketHeader(hOutputFile);
		WriteEthernetFrame(hOutputFile, srcMac, dstMac);
		WriteIpFrame(hOutputFile, srcIp, dstIp);
		WriteIcmpFrame(hOutputFile, u16SequenceNumber);
		u16SequenceNumber++;
	}

	return true;
}

void WriteGlobalHeader(HANDLE & hOutputFile)
{
	DWORD dwBytesWrite;
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

void WritePacketHeader(HANDLE & hOutputFile)
{
}

void WriteEthernetFrame(HANDLE & hOutputFile, const std::vector<UINT8>& srcMac, const std::vector<UINT8>& dstMac)
{
}

void WriteIpFrame(HANDLE & hOutputFile, const sockaddr_in & srcIp, const sockaddr_in & dstIp)
{
}


void WriteIcmpFrame(HANDLE & hOutputFile, const UINT16 u16SequenceNumber)
{
}

void PrintInvalidValueError(const string key, const string value, const string msg)
{
	std::cerr << "Invalid Input " << value << " for " << key << std::endl;
	if (!msg.empty())
	{
		std::cerr << msg << std::endl;
	}
}