// PingMaker.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"
#include "MakePing.h"

int main(int argc, char * argv[])
{
	string input, output;
	string injectType, injectFilename;
	string srcIp, dstIp;
	string srcMac, dstMac;
	UINT16 dataLength;

	po::options_description desc("Allowed Options");
	desc.add_options()
		("help", "This Message")
		("type", po::value<string>(&injectType), "What Type you want to inject into Ping. string || file")
		("input", po::value<string>(&input), "What you want to inject into Ping.")
		("output", po::value<string>(&output)->default_value("output.pcap"), "Name of Result file. Default is output.pcap")
		("srcip", po::value<string>(&srcIp)->default_value("127.0.0.1"), "Source IP Address. Default is 127.0.0.1")
		("dstip", po::value<string>(&dstIp)->default_value("127.0.0.1"), "Destinaton IP Address. Default is 127.0.0.1")
		("srcmac", po::value<string>(&srcMac)->default_value("00:00:00:00:00:00"), "Source MAC Address. Default is 00:00:00:00:00:00")
		("dstmac", po::value<string>(&dstMac)->default_value("00:00:00:00:00:00"), "Destinaton MAC Address. Default 00:00:00:00:00:00")
		("size", po::value<UINT16>(&dataLength)->default_value(32), "Size of Ping");

	po::variables_map vm;
	po::store(po::command_line_parser(argc, argv).options(desc).run(), vm);
	po::notify(vm);

	const string EXAMPLE = "pingmaker.exe --type=string --input=\"this is EXAMPLE\" --output=output.pcap";

	if (vm.count("help"))
	{
		cout << desc << "\n";
	}
	else if (!vm.count("type"))
	{
		cout << "type is NECESSARY option." << std::endl;
		return -1;
	}
	else if (!vm.count("input"))
	{
		cout << "Are you sure you won't put anything in there?" << std::endl;
		return -1;
	}

	for (const auto& it : vm) {
		cout.width(10); 
		cout << std::left << it.first.c_str() << " :: ";
		auto& value = it.second.value();
		if (auto v = boost::any_cast<UINT16>(&value))
			cout << *v;
		else if (auto v = boost::any_cast<string>(&value))
			cout << *v;
		else
			cout << "error";
		cout << "\n";
	}
	
	MakePing(vm);
	
    return 0;
}

