#include "stdafx.h"
#include "MakePing.h"

bool MakePing(const po::variables_map & vm)
{
	pcap_t *fp = 0;
	u_int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;

	pcap_pkthdr *header;
	const u_char *pkt_data;

	fp = pcap_open_offline("C:/Users/dal4s/Desktop/EasyPungBased.pcap", errbuf);
	if (fp == NULL)
	{
		cout << errbuf;
	}

	const char * FLAG = "w31lc0me_2_k3ep3R_c4p7ur3_tHe_F1@g:)";
	char data[32];
	HANDLE hFile = CreateFileA("C:\\Users\\dal4s\\Desktop\\EasyPung.pcap",
		GENERIC_WRITE,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		CREATE_ALWAYS,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	if (hFile == NULL)
	{
		cout << "Can't Make Result File\n";
		return -1;
	}

	HANDLE hSourceFile = CreateFileA("C:\\Users\\dal4s\\Desktop\\ANSWER.png",               // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, // normal file
		NULL);                 // no attr. template

	int index = 0;
	DWORD dwBytesWrite, dwBytesRead;
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
		{
			continue;
		}

		if (FALSE == ReadFile(hSourceFile, data, 32, &dwBytesRead, NULL))
		{
			printf("Can not Read File.\n");
		}

		WriteFile(hFile, &(header->ts.tv_sec), 4, &dwBytesWrite, NULL);
		WriteFile(hFile, &(header->ts.tv_usec), 4, &dwBytesWrite, NULL);
		WriteFile(hFile, &(header->caplen), 4, &dwBytesWrite, NULL);
		WriteFile(hFile, &(header->len), 4, &dwBytesWrite, NULL);
		WriteFile(hFile, pkt_data, 42, &dwBytesWrite, NULL);

		//memset(data, FLAG[index], 32);
		WriteFile(hFile, data, 32, &dwBytesWrite, NULL);
		//index++;
		if (index == 40)
		{
			break;
		}
	}

	if (res == -1)
	{
		fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	return false;
}
