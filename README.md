# PingMaker

This Tool Can Import (String/File Data) to ICMP Packet's Data Area.

## How To Use

### Arguments

 - type
    - What Type You Want to Inject into Ping.
    - You Can Choose either \'**string**\' or \'**file**\'.
 - input
    - What you want to inject into Ping.
    - If You Choose \'**file**\' Type, File's Path is Recommended.
 - output
    - Path of Output File.
    - Default is \'**.**\'
 - srcip, dstip
    - Source/Destination IP Address
    - Type like \'127.0.0.1\'
    - Default is \'**127.0.0.1**\'
 - srcmac, dstmac
    - **Not Available** now.
    - Source/Destination MAC Address
    - Type like \'AB:CD:EF:01:23:45\'
    - Default is \'00:00:00:00:00:00\'
 - size
    - Data Size of each Ping Packet.
    - It Must be Multiple of 2.
    - Default is **32**

### Example

#### Inject String

 - Inject *\'Hello, This is Dal4Segno's Github Repository. Thank you for Visiting.\'* **String**
 - Others are Default
```
.\PingMaker.exe --type=string --input="Hello, This is Dal4Segno's Github Repository. Thank you for Visiting."
```

#### Inject File

 - Inject *\'Some.thing\'* **File**
 - Source IP Address is *192.168.0.1*
 - Destination IP Address is *192.168.254.1*
 - Others are Default
```
.\PingMaker.exe --type=file --input=.\Some.thing --srcip=192.168.0.1 --dstip=192.168.254.1
```

### Caution 

 - If Size is too **Small**, Output File may be Lager than Limit of pcap format.
 - I have not tested it in other environments. **;)**

### Known Problem

 - Setting MAC Address is Not Available.
 - Do Not 0 Fill in the last Packet.
 - Time Interval between each Packet is very Narrow.
 - Many Exception Handlings have been Omitted.

## Used Library

- pcap.h
    - Packet Header, IP Address ...
- boost::program_option
    - To Receive Program Option
- std::random
    - To Make Random Value
    - Time To Live, Identification in IP Frame