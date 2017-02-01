// PingMaker.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"

int main()
{
	pcap_if_t *alldevs, *d;
	pcap_t *fp = 0;
	u_int inum, i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;

	pcap_pkthdr *header;
	const u_char *pkt_data;

	fp = pcap_open_offline("C:/Users/dal4s/Desktop/EasyPungBased.pcap", errbuf);
	if (fp == NULL)
	{
		std::cout << errbuf;
	}
	
	const char * FLAG = "2ef7bde608ce5404e97d5f042f95f89f1c232871";
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
		std::cout << "Can't Make Result File\n";
		return -1;
	}

	int index = 0;
	DWORD dwBytesWrite;
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
		{
			continue;
		}

		WriteFile(hFile, &(header->ts.tv_sec), 4, &dwBytesWrite, NULL);
		WriteFile(hFile, &(header->ts.tv_usec), 4, &dwBytesWrite, NULL);
		WriteFile(hFile, &(header->caplen), 4, &dwBytesWrite, NULL);
		WriteFile(hFile, &(header->len), 4, &dwBytesWrite, NULL);
		WriteFile(hFile, pkt_data, 42, &dwBytesWrite, NULL);
		memset(data, FLAG[index], 32);
		WriteFile(hFile, data, 32, &dwBytesWrite, NULL);
		index++;
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

    return 0;
}

