/* IPGREP v0.3-20201015 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>

/* Print help */
void help(int r){
	printf("\nIPGREP v0.3-20201015\n\n");
	printf("Written by Markus Thilo\n");
	printf("September 2018 to November 2019, GPL-3\n");
	printf("Only the C standard library is used, no LIBPCAP.\n");
	printf("The tool copies packets from source PCAP files to a destination PCAP file.\n");
	printf("Packets that are not of the the type IP are dropped. In addition, packets can\n");
	printf("be filtered by IP Version, one matching address or two matching addresses.\n\n");
	printf("Usage:\n\n");
	printf("ipgrep PATTERN OUTFILE INFILE1 [INFILE2 ...]\n\n");
	printf("The file format ist PCAP.\n\n");
	printf("Patterns:\n");
	printf("ip\t\tCopy all IP packets.\n");
	printf("v4\t\tCopy all IPv4 packets.\n");
	printf("v6\t\tCopy all IPv6 packets.\n");
	printf("ADDRESS\tCopy packets if source or destination address matches.\n");
	printf("ADDRESS-ADDRESS\tCopy packets if one address is source and one is the destination.\n\n");
	printf("The PCAP file header is taken from the first input file. These values are untuched:\n");
	printf("Magic number, version number, time correction, accuracy of timestamps, data link type.\n");
	printf("Only maximal length of captured packets (snaplen) is adjusted.\n");
	printf("Compression of IPv6 addresses removing colons does not work.\n\n");
	printf("Examples:\n");
	printf("ipgrep ip out.pcap dump.pcap = all IP packets\n");
	printf("ipgrep v6 out.pcap dump.pcap = all IPv6 packets\n");	
	printf("ipgrep ff02:::::::fb out.pcap dump.pcap = packets comming from or going to this address\n");
	printf("ipgrep 192.168.1.7-216.58.207.78 out.pcap dump1.pcap dump2.pcap = packets inbetween these\n\n");
	printf("Use this piece of software on your own risk. Accuracy is not garanteed.\n");
	printf("Report bugs to markus.thilo@gmail.com.\n");
	printf("Project page: https://github.com/markusthilo/netflower\n\n");
	exit(r);
}

/* Convert given decimal number (char) integer */
int dec2int(char c) {
	if ( ( c >= '0' ) && (  c <= '9' ) ) return c - '0';
	return -1;
}

/* Convert given hexadecimal number (0-9a-fA-F) integer */
int hex2int(char c) {
	int n = dec2int(c);
	if ( n >= 0 ) return n;
	if ( ( c >= 'a' ) && (  c <= 'f' ) ) return c - ('a'-0xa);
	if ( ( c >= 'A' ) && (  c <= 'F' ) ) return c - ('A'-0xa);
	return -1;
}

/* Convert decimal byte in string to integer inbetween 0 and 255 */
int decbyte2int(char *string, int *s_pos) {
	if ( string[*s_pos] < '0' || string[*s_pos] > '9'  ) return -1;
	int byte = 0, cifer;
	while ( string[*s_pos] != 0 && string[*s_pos] != '.' && string[*s_pos] != '-' ) {
		cifer = dec2int(string[*s_pos]);
		*s_pos += 1;
		if ( cifer < 0 ) return -1;
		byte = ( byte * 10 ) + cifer;
	}
	if ( byte > 255 ) return -1;
	return byte;
}

/* Convert 2 hexadecimal bytes in string to long integer inbetween 0 and 0xffff */
long hexbytes2long(char *string, int *s_pos) {
	long bytes = 0;
	int cifer;
	while ( string[*s_pos] != 0 && string[*s_pos] != ':' && string[*s_pos] != '-' ) {
		cifer = hex2int(string[*s_pos]);
		*s_pos += 1;
		if ( cifer < 0 ) return -1;
		bytes = ( bytes << 4 ) + cifer;
	}
	if ( bytes > 0xffff ) return -1;
	return bytes;
}

/* Structure for IP v4 adresses */
struct ipv4 {
	uint32_t addr;
	int error;
};


/* Convert string to binary IP address */
struct ipv4 str2ipv4(char *string, int *s_pos) {
	struct ipv4 ip;
	ip.addr = 0;
	ip.error = -1;
	int p_cnt = 0, byte;
	while (1) {
		byte = decbyte2int(string, s_pos);
		if ( byte < 0 ) return ip;
		ip.addr = ( ip.addr << 8 ) + byte;
		if ( string[*s_pos] == 0 || string[*s_pos] == '-' || p_cnt++ > 3 ) break;
		*s_pos +=1;
	}
	if ( p_cnt != 3 ) return ip;
	ip.error = 0;
	return ip;
}


/* Structure for IP v6 adresses */
struct ipv6 {
	uint64_t addr[2];
	int error;
};

/* Convert string to binary IPv6 */ 
struct ipv6 str2ipv6(char *string, int *s_pos) {
	struct ipv6 ip;
	int p_cnt = 0, i = 0;
	long bytes;
	while (1) {
		bytes = hexbytes2long(string, s_pos);
		if ( bytes < 0 ) {
			ip.addr[0] = 0;
			ip.addr[1] = 0;
			return ip;
		}
		ip.addr[i] = ( ip.addr[i] << 16 ) + bytes;
		if ( string[*s_pos] == 0 || string[*s_pos] == '-' || p_cnt++ > 7 ) break;
		*s_pos +=1;
		if ( p_cnt == 4 ) i = 1;
	}
	if ( p_cnt != 7 ) {
		ip.addr[0] = 0;
		ip.addr[1] = 0;
	}
	return ip;
}

/* Structure for grep pattern */
struct gpattern {
	struct ipv4 ipv4a, ipv4b;
	struct ipv6 ipv6a, ipv6b;
	char type;
};

/* Get grep pattern */
struct gpattern getpattern(char *string) {
	struct gpattern gp;	// to return
	int slen = strlen(string);
	gp.type = 'e';	// e = error
	if ( ( slen < 2 ) || ( slen > 79 ) ) return gp;	// return error if length is out of range
	if ( ( slen == 2 ) && ( string[0] == 'i' ) && ( string[1] == 'p' ) ) {	// ip for all ip packets
		gp.type = 'i';
		return gp;
	}
	if ( ( slen == 2 ) &&  ( string[0] == 'v' ) ) {	// v4 or v6 for packets of either v4 or v6
		if ( string[1] == '4' ) {
			gp.type = '4';
			return gp;
		} else if ( string[1] == '6' ) {
			gp.type = '6';
			return gp;
		} else return gp;
	}
	int s_pos = 0;	// pointer to char in string
	gp.ipv4a = str2ipv4(string, &s_pos);	// v4?
	if ( gp.ipv4a.error == 0 ) gp.type = 's';
	else {
		s_pos = 0;	// reset to first char in string
		gp.ipv6a = str2ipv6(string, &s_pos);	// v6?
		if ( gp.ipv6a.error != 0 ) return gp;
		gp.type = 'S';
	}
	if ( s_pos == slen ) return gp;	// one address?
	if ( string[s_pos++] != '-' ) {	// no link?
		gp.type = 'e';
		return gp;
	}
	switch (gp.type) {
		case 's':	// v4
			gp.ipv4b = str2ipv4(string, &s_pos);
			if ( gp.ipv4b.error == 0 ) gp.type = 'l';
			else gp.type = 'e';
			break;
		case 'S':	// v6
			gp.ipv6b = str2ipv6(string, &s_pos);
			if ( gp.ipv6b.error == 0 ) gp.type = 'L';
			else gp.type = 'e';
	}
	return gp;
}

/* Read raw data from PCAP file (n bytes) */
int readbytes(FILE *fin, uint8_t *bytes, uint32_t n) {
	if (fread(bytes,1,n,fin) != n) return 1;	// read n bytes
	return 0;
}
	
/* Write raw data to PCAP file */
void writebytes(FILE *fout, uint8_t *bytes, uint32_t n) {
	if (fwrite(bytes,1,n,fout) != n ) { // write n bytes file
		fprintf(stderr, "Error while writing output file.\n");
		exit(1);
	}
}

/* Write uint32_t = 32 bits to PCAP file */
void writeuint32(FILE *fout, uint32_t u, uint32_t pos, uint32_t magic_number) {
	uint8_t bytes[4];
	if ( magic_number == 0xd4c3b2a1 ) {	// byte order
		bytes[0] = u & 0xff;
		bytes[1] = ( u << 8 ) & 0xff;
		bytes[2] = ( u << 16 ) & 0xff;
		bytes[3] = ( u << 24 ) & 0xff;
	} else {
		bytes[3] = u & 0xff;
		bytes[2] = ( u << 8 ) & 0xff;
		bytes[1] = ( u << 16 ) & 0xff;
		bytes[0] = ( u << 24 ) & 0xff;
	}
	if ( (fseek(fout,pos,SEEK_SET) != 0) && (fwrite(bytes,1,4,fout) != 1 ) ) { // write 4 octets to file
		fprintf(stderr, "Error while writing value to output file.\n");
		exit(1);
	}
}

/* Extract 2 octets from byte array to uint16_t */
uint16_t extract16bits (uint8_t *bytes, int pos ) {
	return	( (uint16_t) bytes[pos]		<< 8 )
		|	( (uint16_t) bytes[pos+1] );
}

/* Extract 4 octest from byte array to uint32_t */
uint32_t extract32bits (uint8_t *bytes, int pos ) {
	return	( (uint32_t) bytes[pos] 	<< 24 )
		|	( (uint32_t) bytes[pos+1] 	<< 16 )
		|	( (uint32_t) bytes[pos+2] 	<< 8 )
		|	( (uint32_t) bytes[pos+3] );
}

/* Extract 4 octest from byte array to uint32_t and swap byte order */
uint32_t extract32swapped (uint8_t *bytes, int pos ) {
	return 	( (uint32_t) bytes[pos+3] 	<< 24 )
		|	( (uint32_t) bytes[pos+2] 	<< 16 )
		|	( (uint32_t) bytes[pos+1] 	<< 8 )
		|	( (uint32_t) bytes[pos] );
}

/* Extract 8 octets from byte array to uint64_t */
uint64_t extract64bits (uint8_t *bytes, int pos ) {
	return	( (uint64_t) bytes[pos] 	<< 56 )
		|	( (uint64_t) bytes[pos+1] 	<< 48 )
		|	( (uint64_t) bytes[pos+2] 	<< 40 )
		|	( (uint64_t) bytes[pos+3] 	<< 32 )
		|	( (uint64_t) bytes[pos+4] 	<< 24 )
		|	( (uint64_t) bytes[pos+5] 	<< 16 )
		|	( (uint64_t) bytes[pos+6] 	<< 8 )
		|	( (uint64_t) bytes[pos+7] );
}

/* Structure for PCAP file header */
struct pcapheader {
	uint8_t raw[24];
	uint32_t magic_number, snaplen, network;
};

/* Read PCAP file header */
struct pcapheader readpcapheader (FILE *fin) {
	struct pcapheader pcaph;
	if ( readbytes(fin, pcaph.raw, 24) == 1 ) {
		fprintf(stderr, "Error: could not read PCAP file.\n");
		exit(1);
	}
	pcaph.magic_number = extract32bits(pcaph.raw, 0);
	if ( pcaph.magic_number == 0xd4c3b2a1 ) {
		pcaph.snaplen = extract32swapped(pcaph.raw, 16);
		pcaph.network = extract32swapped(pcaph.raw, 20);
	} else if ( pcaph.magic_number == 0xa1b2c3d4 ) {
		pcaph.snaplen = extract32bits(pcaph.raw, 16);
		pcaph.network = extract32bits(pcaph.raw, 20);
	} else {
		fprintf(stderr, "Error: an input file does not look like PCAP.\n");
		exit(1);
	}
	return pcaph;
}

/* Structure for packet header */
struct packetheader {
	uint8_t raw[16];
	uint32_t incl_len;
	int error;
};

/* Read packet header in PCAP file */
struct packetheader readpacketheader (FILE *fin, uint32_t magic_number) {
	struct packetheader ph;
	if ( readbytes(fin, ph.raw, 16) == 1 ) { ph.error = 1; return ph; }
	if ( magic_number == 0xd4c3b2a1 ) ph.incl_len = extract32swapped(ph.raw, 8);
	else ph.incl_len = extract32bits(ph.raw, 8);
	ph.error = 0;
	return ph;
}

/* Structure for the packet content */
struct packetcont {
	uint8_t raw[14];
	int ipv, len, error;
};

/* Read null or data link layer */
struct packetcont readcontent(FILE *fd, uint32_t network) {
	struct packetcont pc;
	pc.ipv = 0;
	switch (network) {	// data link type
		case 0:	// null
			pc.len = 4;
			pc.error = readbytes(fd, pc.raw, pc.len);	// family and version
			if ( pc.error == 1 ) return pc;
			uint32_t family = extract32bits(pc.raw, 0);
			switch (family) {
				case 0x2000000: pc.ipv = 4; break;	// ipv4
				case 0x1800000: pc.ipv = 6;	// ipv6
			}
			break;
		case 1:	// ethernet
			pc.len = 14;
			pc.error = readbytes(fd, pc.raw, pc.len);	// ethernet layer
			if ( pc.error == 1 ) return pc;
			uint16_t type = extract16bits(pc.raw, 12);	// get type
			switch (type) {
				case 0x0800: pc.ipv = 4; break;	// ipv4
				case 0x86dd: pc.ipv = 6;	// ipv6
			}
	}
	return pc;
}

/* Structure for IP v4 layer */
struct ipv4layer {
	uint8_t raw[20];
	uint32_t src_addr, dst_addr;
	int error;
};

/* Read IPv4 */
struct ipv4layer readipv4layer (FILE *fin) {
	struct ipv4layer il;
	if ( readbytes(fin, il.raw, 20) == 1 ) { il.error = 1; return il; }
	il.src_addr = extract32bits(il.raw, 12);
	il.dst_addr = extract32bits(il.raw, 16);
	il.error = 0;
	return il;
}

/* Structure for IP v6 layer */
struct ipv6layer {
	uint8_t raw[40];
	uint64_t src_addr[2], dst_addr[2];
	int error;
};

/* Read IPv6 */
struct ipv6layer readipv6layer (FILE *fin) {
	struct ipv6layer il;
	if ( readbytes(fin, il.raw, 40) == 1 ) { il.error = 1; return il; }
	il.src_addr[0] = extract64bits(il.raw, 8);
	il.src_addr[1] = extract64bits(il.raw, 16);
	il.dst_addr[0] = extract64bits(il.raw, 24);
	il.dst_addr[1] = extract64bits(il.raw, 32);
	il.error = 0;
	return il;
}

/* Copy unanalized date from input to output file */
void copypayload (FILE *fin, FILE *fout, uint32_t n) {
	uint8_t byte;
	for (; n>0; n--) {
		if ( ( fread(&byte,1,1,fin) != 1 )	// read one byte
			|| ( fwrite(&byte,1,1,fout) != 1 ) ) {	// write one byte
			fprintf(stderr, "Error: could not copy packet data.\n");
			exit(1);
		}
	}
}

/* Skip n bytes in input file */
void skippayload (FILE *fin, uint32_t n) {
	if ( fseek(fin,n,SEEK_CUR) != 0 ) {
		fprintf(stderr, "Error: could not go through input file.\n");
		exit(1);
	}
}

/* Main function - program starts here*/
int main(int argc, char **argv) {
	if ( ( argc < 2 )
	|| ( ( argv[1][0] == '-' ) && ( argv[1][1] == '-' ) && ( argv[1][2] == 'h' ) )
	|| ( ( argv[1][0] == '-' ) && ( argv[1][1] == 'h' ) ) )  help(0);
	if ( argc < 4 ) help(1);	// print help on not enougth command line arguments
	int v;	// to grep vor ip version
	struct gpattern gp = getpattern(argv[1]);	// get grep pattern
	switch (gp.type) {
		case 'i': v = 0; break;	// 0 means ipv4 or v6 
		case '4':
		case 's':
		case 'l': v = 1; break;	// 1 means ipv4
		case '6':
		case 'S':
		case 'L': v = -1; break;	// -1 means ipv6
		default	: help(1);
	}
	if ( access(argv[2], F_OK) != -1 ) {	// check for existing output file
		fprintf(stderr, "Error: file %s exists.\n", argv[2]);
		exit(1);
	}
	FILE *fout;	// file pointer for output pcap file
	fout = fopen(argv[2], "wb");	// open output file
	if ( fout == NULL ) {
		fprintf(stderr, "Error: could not open output file %s.\n", argv[2]);
		exit(1);
	}
	int il_error, rem_len;	// error handling, remaining bytes in packet
	uint32_t maxsnaplen = 0, network;	// to put the maximal length of packets in the output pcap file header, network type
	uint64_t pcnt = 0;	// count copied packets
	FILE *fin;	// file pointer for input pcap file(s)
	struct pcapheader pcaph;	// to read pcap file headers
	struct packetheader ph;	// to read packet headers
	struct packetcont pc;	// to read packet content
	struct ipv4layer v4l;	// to read ipv4 layers
	struct ipv6layer v6l;	// to read ipv6 layers
	for (int i = 3; i < argc; i++) {	// main loop - go through the input files
		fin = fopen(argv[i], "rb");	// open input file
		if ( fin == NULL ) {
			fprintf(stderr, "Error: could not open input file %s.\n", argv[i]);
			exit(1);
		}
		pcaph = readpcapheader(fin);	// read pcap file header
		if ( pcaph.snaplen > maxsnaplen ) maxsnaplen = pcaph.snaplen;	// update maximal snaplen for output pcap file
		if ( i == 3) {	// if 1st input file then write it to output file
			writebytes(fout, pcaph.raw, 24);
			network = pcaph.network;
		} else if ( network != pcaph.network ) {
			fprintf(stderr, "Error: inconsistent network type in file %s.\n", argv[i]);
			exit(1);
		}
		do {	// loop through packets
			ph = readpacketheader(fin, pcaph.magic_number);	// read packet header
			rem_len = ph.incl_len;
			if ( ph.error == 1 ) break;	// if not successful, end of file might be reached
			pc = readcontent(fin, pcaph.network);
			rem_len -= pc.len;
			if ( pc.error == 1 ) break;
			il_error = 1;
			if ( ( pc.ipv == 4 ) && ( v >= 0 ) ) {	// ip v4
				v4l = readipv4layer(fin);
				rem_len -= 20;
				if ( v4l.error == 1 ) break;
				if (	// filter
						( gp.type == 'i' )
					||	( gp.type == '4' )
					||	( ( gp.type == 's' ) && ( ( v4l.src_addr == gp.ipv4a.addr ) || ( v4l.dst_addr == gp.ipv4a.addr ) ) )
					||	( ( gp.type == 'l' ) && ( ( ( ( v4l.src_addr == gp.ipv4a.addr ) && ( v4l.dst_addr == gp.ipv4b.addr ) )
												|| ( ( v4l.src_addr == gp.ipv4b.addr ) && ( v4l.dst_addr == gp.ipv4a.addr ) ) ) ) )
				) {	// copy analized packet data
					writebytes(fout, ph.raw, 16);
					writebytes(fout, pc.raw, pc.len);
					writebytes(fout, v4l.raw, 20);
					copypayload(fin, fout, rem_len);	// copy the rest of the packet
					pcnt++;
				} else skippayload(fin, rem_len);	// go to next packet
			} else if ( ( pc.ipv == 6 ) && ( v <= 0 ) ) {	// ip v6
				v6l = readipv6layer(fin);
				rem_len -= 40;
				if ( v6l.error == 1 ) break;
				if (	// filter
						( gp.type == 'i' )
					||	( gp.type == '6' )
					||	( ( gp.type == 'S' ) && ( ( ( v6l.src_addr[0] == gp.ipv6a.addr[0] ) && ( v6l.src_addr[1] == gp.ipv6a.addr[1] ) )
												|| ( ( v6l.dst_addr[0] == gp.ipv6a.addr[0] ) && ( v6l.dst_addr[1] == gp.ipv6a.addr[1] ) ) ) )
					||	( ( gp.type == 'L' ) && ( ( ( ( v6l.src_addr[0] == gp.ipv6a.addr[0] ) && ( v6l.src_addr[1] == gp.ipv6a.addr[1] )
													&& ( v6l.dst_addr[0] == gp.ipv6b.addr[0] ) && ( v6l.dst_addr[1] == gp.ipv6b.addr[1] ) )
												|| ( ( v6l.src_addr[0] == gp.ipv6b.addr[0] ) && ( v6l.src_addr[1] == gp.ipv6b.addr[1] )
													&& ( v6l.dst_addr[0] == gp.ipv6a.addr[0] ) && ( v6l.dst_addr[1] == gp.ipv6a.addr[1] ) ) ) ) )
				) {	// copy analized packet data
					writebytes(fout, ph.raw, 16);
					writebytes(fout, pc.raw, pc.len);
					writebytes(fout, v6l.raw, 40);
					copypayload(fin, fout, rem_len);	// copy the rest of the packet
					pcnt++;
				} else skippayload(fin, rem_len);	// go to next packet
			} else {	// skip other protocol or mismatch of protocol and filter
				skippayload(fin, rem_len);	// go to next packet
			}
			il_error = 0;
		} while ( ( ph.error == 0 ) && ( pc.error == 0 ) );	// exit loop on error
		writeuint32(fout, maxsnaplen, 16, pcaph.magic_number);	// write maximal snap_len of all input files to output file
		fclose(fin);
	}
	fclose(fout);
	printf("Number of copied packets: %lu\n", pcnt);
	exit(0);
}
