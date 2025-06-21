# ipgrep
Merge PCAP files and filter for IP addresse(s)

The tool copies packets from source PCAP files to a destination PCAP file.
Packets that are not of the the type IP are dropped. In addition, packets can
be filtered by IP version (v4 or v6), one matching address or two matching addresses.

No libpcap is used. This tool is based und standard libraries only.
It works in one thread but should run very fast compared to complexer solutions.

This software might not work with all variants of PCAP files. Ethernet link layer should work.
PCAPNG is not supported.

## Compile:
All you need is in the source file ```ipgrep.c```:
```
gcc -o ipgrep ipgrep.c
```
(or use make)

## Usage:
```
./ipgrep PATTERN OUTFILE INFILE1 [INFILE2 ...]
```
The file format ist PCAP (PCAPNG is not supported)

Patterns:
- ```ip```: Copy all IP packets
- ```v4```: Copy all IPv4 packets
- ```v6```: Copy all IPv6 packets
- ```ADDRESS```: Copy packets if source or destination address matches
- ```ADDRESS-ADDRESS```: Copy packets if one address is source and one is the destination

The PCAP file header is taken from the first input file. These values are untuched:
Magic number, version number, time correction, accuracy of timestamps, data link type.
Only maximal length of captured packets (snaplen) is adjusted.
Compression of IPv6 addresses removing colons does not work.

## Examples:
- Copy all IP packets:
```
./ipgrep ip out.pcap dump.pcap
```
- Copy all IPv6 packets:
```
./ipgrep v6 out.pcap dump.pcap
```
- Copy packets sent from or to the given IP address:
```
./ipgrep ff02:::::::fb out.pcap dump.pcap
```
Copy all packets that traveled in between the given IP adresses:
```
./ipgrep 192.168.1.7-216.58.207.78 out.pcap dump1.pcap dump2.pcap
```

## Disclaimer
Use this piece of software on your own risk. Accuracy is not garanteed.

Report bugs to: markus.thilo@gmail.com

Project page: https://github.com/markusthilo/iprunner
