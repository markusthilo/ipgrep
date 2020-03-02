# ipgrep

The tool copies packets from source PCAP files to a destination PCAP file.
Packets that are not of the the type IP are dropped. In addition, packets can
be filtered by IP Version, one matching address or two matching addresses.

Usage:

ipgrep PATTERN OUTFILE INFILE1 [INFILE2 ...]

The file format ist PCAP.

Patterns:

ip		Copy all IP packets.

v4		Copy all IPv4 packets.

v6		Copy all IPv6 packets.

ADDRESS		Copy packets if source or destination address matches.

ADDRESS-ADDRESS	Copy packets if one address is source and one is the destination.

The PCAP file header is taken from the first input file. These values are untuched:
Magic number, version number, time correction, accuracy of timestamps, data link type.
Only maximal length of captured packets (snaplen) is adjusted.
Compression of IPv6 addresses removing colons does not work.

Examples:

ipgrep ip out.pcap dump.pcap = all IP packets

ipgrep v6 out.pcap dump.pcap = all IPv6 packets

ipgrep ff02:::::::fb out.pcap dump.pcap = packets comming from or going to this address

ipgrep 192.168.1.7-216.58.207.78 out.pcap dump1.pcap dump2.pcap = packets inbetween these
