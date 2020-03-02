/* IPGREP for MINGW-W64-GCC v0.2.1 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* Structure for IP v4 adresses */
struct ipv4 {
	unsigned long addr;
	int error;
};

/* Structure for IP v6 adresses */
struct ipv6 {
	unsigned long long addr[2];
	int error;
};

/* Structure for PCAP file header */
struct pcapheader {
	unsigned char raw[24];
	unsigned long magic_number, snaplen;
};

/* Structure for packet header */
struct packetheader {
	unsigned char raw[16];
	unsigned long incl_len;
	int error;
};

/* Structure for Ethernet II layer */
struct ethernetlayer {
	unsigned char raw[14];
	unsigned short type;
	int error;
};

/* Structure for IP v4 layer */
struct ipv4layer {
	unsigned char raw[20];
	unsigned long src_addr, dst_addr;
	int error;
};

/* Structure for IP v6 layer */
struct ipv6layer {
	unsigned char raw[40];
	unsigned long long src_addr[2], dst_addr[2];
	int error;
};

/* Structure for grep pattern */
struct gpattern {
	struct ipv4 ipv4a, ipv4b;
	struct ipv6 ipv6a, ipv6b;
	char type;
};

/* Give length of a string */
int stringlength(char *string) {
	int i = 0;
	while (string[i] != 0) i++;
	return i;
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

/* Convert string to integer inbetween 0 and 255 */
int str2byte(char *string) {
	const int factor[] = { 1, 10, 100 };
	int d, n = 0, slen = stringlength(string), i, j = 0;
	if ( ( slen < 1 ) || ( slen > 3 ) ) { return -1; }
	for (i=slen-1; i>=0; i--) {
		d = dec2int(string[i]);
		if ( d < 0) { return -1; }
		n += d * factor[j++];
	}
	if ( n > 255 ) { return -1; }
	return n;
}

/* Convert string to binary IPv4 */ 
struct ipv4 str2ipv4(char *string) {
	unsigned long factor = 0x1000000;
	struct ipv4 out;
	int b, i, j = 0;
	char byte[4] = "";
	out.addr = 0;
	out.error = -1;
	for (i=0; i<=stringlength(string); i++) {
		if ( ( string[i] == '.' ) || ( string[i] == 0 ) ) {
			byte[j] = 0;
			b = str2byte(byte);
			if ( b < 0 ) return out;
			out.addr += b * factor;
			j = 0;
			factor = factor >> 8;
		} else {
			byte[j++] = string[i];
			if ( j > 3 ) { return out; }
		}

	}
	out.error = 0;
	return out;
}

/* Convert string to binary IPv6 */ 
struct ipv6 str2ipv6(char *string) {
	unsigned long n, factor = 1;
	struct ipv6 out;
	int i, j = 1, k = 4;
	out.addr[0] = 0;
	out.addr[1] = 0;
	out.error = -1;
	for (i=stringlength(string)-1; i>=0; i--) {
		if ( string[i] == ':' ) {
			if ( k < 0 ) return out;
			factor = factor << ( k << 2 );
			k = 5;
		} else {
			n = hex2int(string[i]);
			if ( n == -1 ) return out;
			out.addr[j] += n * factor;
			factor = factor << 4;
		}
		if ( factor == 0 ) { 
			if ( j-- == 0 ) {
				if ( i > 0 ) return out;
				break;
			}
			factor = 1;
		}
		if ( k-- == 0 ) return out;
	}
	if ( j < 0 ) out.error = 0;
	return out;
}

/* Get grep pattern */
struct gpattern getpattern(char *instr) {
	struct gpattern r;	// to return
	char ipstr[40];	// to copy ip address in
	int ipstrptr = 0, instrptr = 0, instrlen = stringlength(instr);
	r.type = 'e';	// e = error
	if ( ( instrlen < 2 ) || ( instrlen > 79 ) ) return r;	// return error if length is out of range
	if ( ( instrlen == 2 ) && ( instr[0] == 'i' ) && ( instr[1] == 'p' ) ) {	// ip for all ip packets
		r.type = 'i';
		return r;
	}
	if ( ( instrlen == 2 ) &&  ( instr[0] == 'v' ) ) {	// v4 or v6 for packets of either v4 or v6
		if ( instr[1] == '4' ) {
			r.type = '4';
			return r;
		} else if ( instr[1] == '6' ) {
			r.type = '6';
			return r;
		} else return r;
	}
	while (1) {
		if ( ( instr[instrptr] == '-' ) && ( r.type = 'e' ) ) {	// - seperates two ip addresses
			instrptr++;
			ipstr[ipstrptr] = 0;
			ipstrptr = 0;
			r.ipv4a = str2ipv4(ipstr);
			if ( r.ipv4a.error == 0 ) {
				r.type = 'l';
				continue;
			}
			r.ipv6a = str2ipv6(ipstr);
			if ( r.ipv6a.error == 0 ) {
				r.type = 'L';
				continue;
			}
			return r;
		}
		if ( instr[instrptr] == 0 ) {	// end of string
			ipstr[ipstrptr] = 0;
			if ( r.type == 'e' ) {
				r.ipv4a = str2ipv4(ipstr);
				if ( r.ipv4a.error == 0 ) {
					r.type = 's'; 
					return r;
				}	
				r.ipv6a = str2ipv6(ipstr);
				if ( r.ipv6a.error == 0 ) {
					r.type = 'S';
					return r;
				}
			}
			if ( r.type == 'l' ) {
				r.ipv4b = str2ipv4(ipstr);
				if ( r.ipv4b.error != 0 ) r.type = 'e';
				return r;
			}
			if ( r.type == 'L') {
				r.ipv6b = str2ipv6(ipstr);
				if ( r.ipv6b.error != 0 ) r.type = 'e';
				return r;
			}
			return r;
		}
		ipstr[ipstrptr++] = instr[instrptr++];
	}
}

/* Read raw data from PCAP file (n bytes) */
int readbytes(FILE *fin, unsigned char *bytes, unsigned long n) {
	if (fread(bytes,1,n,fin) != n) return 1;	// read n bytes
	return 0;
}
	
/* Write raw data to PCAP file */
void writebytes(FILE *fout, unsigned char *bytes, unsigned long n) {
	if (fwrite(bytes,1,n,fout) != n ) { // write n bytes file
		fprintf(stderr, "Error while writing output file.\n");
		exit(1);
	}
}

/* Write unsigned long = 32 bits to PCAP file */
void writeuint32(FILE *fout, unsigned long u, unsigned long pos, unsigned long magic_number) {
	unsigned char bytes[4];
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

/* Extract 2 octets from byte array to unsigned short */
unsigned short extract16bits (unsigned char *bytes, int pos ) {
	return	( (unsigned short) bytes[pos]		<< 8 )
		|	( (unsigned short) bytes[pos+1] );
}

/* Extract 4 octest from byte array to unsigned long */
unsigned long extract32bits (unsigned char *bytes, int pos ) {
	return	( (unsigned long) bytes[pos] 	<< 24 )
		|	( (unsigned long) bytes[pos+1] 	<< 16 )
		|	( (unsigned long) bytes[pos+2] 	<< 8 )
		|	( (unsigned long) bytes[pos+3] );
}

/* Extract 4 octest from byte array to unsigned long and swap byte order */
unsigned long extract32swapped (unsigned char *bytes, int pos ) {
	return 	( (unsigned long) bytes[pos+3] 	<< 24 )
		|	( (unsigned long) bytes[pos+2] 	<< 16 )
		|	( (unsigned long) bytes[pos+1] 	<< 8 )
		|	( (unsigned long) bytes[pos] );
}

/* Extract 8 octets from byte array to unsigned long long */
unsigned long long extract64bits (unsigned char *bytes, int pos ) {
	return	( (unsigned long long) bytes[pos] 	<< 56 )
		|	( (unsigned long long) bytes[pos+1] 	<< 48 )
		|	( (unsigned long long) bytes[pos+2] 	<< 40 )
		|	( (unsigned long long) bytes[pos+3] 	<< 32 )
		|	( (unsigned long long) bytes[pos+4] 	<< 24 )
		|	( (unsigned long long) bytes[pos+5] 	<< 16 )
		|	( (unsigned long long) bytes[pos+6] 	<< 8 )
		|	( (unsigned long long) bytes[pos+7] );
}

/* Read PCAP file header */
struct pcapheader readpcapheader (FILE *fin) {
	struct pcapheader pcaph;
	if ( readbytes(fin, pcaph.raw, 24) == 1 ) {
		fprintf(stderr, "Error: could not read PCAP file.\n");
		exit(1);
	}
	pcaph.magic_number = extract32bits(pcaph.raw, 0);
	if ( pcaph.magic_number == 0xd4c3b2a1 ) pcaph.snaplen = extract32swapped(pcaph.raw, 16);
	else if ( pcaph.magic_number == 0xa1b2c3d4 ) pcaph.snaplen = extract32bits(pcaph.raw, 16);
	else {
		fprintf(stderr, "Error: an input file does not look like PCAP.\n");
		exit(1);
	}
	return pcaph;
}

/* Read packet header in PCAP file */
struct packetheader readpacketheader (FILE *fin, unsigned long magic_number) {
	struct packetheader ph;
	if ( readbytes(fin, ph.raw, 16) == 1 ) { ph.error = 1; return ph; }
	if ( magic_number == 0xd4c3b2a1 ) ph.incl_len = extract32swapped(ph.raw, 8);
	else ph.incl_len = extract32bits(ph.raw, 8);
	ph.error = 0;
	return ph;
}

/* Read Ethernet Layer II */
struct ethernetlayer readethernetlayer (FILE *fin) {
	struct ethernetlayer el;
	if ( readbytes(fin, el.raw, 14) == 1 ) { el.error = 1; return el; }
	el.type = extract16bits(el.raw, 12);
	el.error = 0;
	return el;
}

/* Read IPv4 */
struct ipv4layer readipv4layer (FILE *fin) {
	struct ipv4layer il;
	if ( readbytes(fin, il.raw, 20) == 1 ) { il.error = 1; return il; }
	il.src_addr = extract32bits(il.raw, 12);
	il.dst_addr = extract32bits(il.raw, 16);
	il.error = 0;
	return il;
}

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
void copypayload (FILE *fin, FILE *fout, unsigned long n) {
	unsigned char byte;
	for (; n>0; n--) {
		if ( ( fread(&byte,1,1,fin) != 1 )	// read one byte
			|| ( fwrite(&byte,1,1,fout) != 1 ) ) {	// write one byte
			fprintf(stderr, "Error: could not copy packet data.\n");
			exit(1);
		}
	}
}

/* Skip n bytes in input file */
void skippayload (FILE *fin, unsigned long n) {
	if ( fseek(fin,n,SEEK_CUR) != 0 ) {
		fprintf(stderr, "Error: could not go through input file.\n");
		exit(1);
	}
}

/* Print help */
void help(int r){
	printf("\nIPGREP v0.2.1\n\n");
	printf("Written by Markus Thilo\n");
	printf("September 2018 to Novemeber 2019, GPL-3\n");
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
	printf("ADDRESS\t\tCopy packets if source or destination address matches.\n");
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

/* Main function - program starts here*/
int main(int argc, char **argv) {
	if ( ( argc < 2 )
	|| ( ( argv[1][0] == '-' ) && ( argv[1][1] == '-' ) && ( argv[1][2] == 'h' ) )
	|| ( ( argv[1][0] == '-' ) && ( argv[1][1] == 'h' ) ) )  help(0);
	if ( argc < 4 ) help(1);	// print help on not enougth command line arguments
	int v, il_error;
	unsigned long maxsnaplen = 0;	// to put the maximal length of packets in the output pcap file header
	unsigned long long pcnt = 0;	// count copied packets
	FILE *fin, *fout;	// file pointers
	struct pcapheader pcaph;	// to read pcap file headers
	struct packetheader ph;	// to read packet headers
	struct ethernetlayer el;	// to read ethernet layers
	struct ipv4layer v4l;	// to read ipv4 layers
	struct ipv6layer v6l;	// to read ipv6 layers
	struct gpattern gp = getpattern(argv[1]);	// get grep pattern
	switch (gp.type) {
		case 'i': v = 0; break;	// 0 means ipv4 or v6 
		case '4':
		case 's':
		case 'l': v = 1; break;	// 1 means ipv4
		case '6':
		case 'S':
		case 'L': v = -1; break;	// -1 menas ipv6
		default	: help(1);
	}
	if ( access(argv[2], F_OK) != -1 ) {	// check for existing output file
		fprintf(stderr, "Error: file %s exists.\n", argv[2]);
		exit(1);
	}
	fout = fopen(argv[2], "wb");	// open output file
	if ( fout == NULL ) {
		fprintf(stderr, "Error: could not open output file %s.\n", argv[2]);
		exit(1);
	}
	for (int i = 3; i < argc; i++) {	// main loop - go through the input files
		fin = fopen(argv[i], "rb");	// open input file
		if ( fin == NULL ) {
			fprintf(stderr, "Error: could not open input file %s.\n", argv[i]);
			exit(1);
		}
		pcaph = readpcapheader(fin);	// read pcap file header
		if ( pcaph.snaplen > maxsnaplen ) maxsnaplen = pcaph.snaplen;	// update maximal snaplen for output pcap file
		if ( i == 3) writebytes(fout, pcaph.raw, 24);	// if 1st input file then write it to output file
		do {	// loop through packets
			ph = readpacketheader(fin, pcaph.magic_number);	// read packet header
			if ( ph.error == 1 ) break;	// if not successful, end of file might be reached
			el = readethernetlayer(fin);
			if ( el.error == 1 ) break;
			il_error = 1;
			if ( ( el.type == 0x0800 ) && ( v >= 0 ) ) {	// ip v4
				v4l = readipv4layer(fin);
				if ( v4l.error == 1 ) break;
				if (	// filter
						( gp.type == 'i' )
					||	( gp.type == '4' )
					||	( ( gp.type == 's' ) && ( ( v4l.src_addr == gp.ipv4a.addr ) || ( v4l.dst_addr == gp.ipv4a.addr ) ) )
					||	( ( gp.type == 'l' ) && ( ( ( ( v4l.src_addr == gp.ipv4a.addr ) && ( v4l.dst_addr == gp.ipv4b.addr ) )
												|| ( ( v4l.src_addr == gp.ipv4b.addr ) && ( v4l.dst_addr == gp.ipv4a.addr ) ) ) ) )
				) {	// copy analized packet data
					writebytes(fout, ph.raw, 16);
					writebytes(fout, el.raw, 14);
					writebytes(fout, v4l.raw, 20);
					copypayload(fin, fout, ph.incl_len-34);	// copy the rest of the packet
					pcnt++;
				} else skippayload(fin, ph.incl_len-34);	// go to next packet
			} else if ( ( el.type == 0x86dd ) && ( v <= 0 ) ) {	// ip v6
				v6l = readipv6layer(fin);
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
					writebytes(fout, el.raw, 14);
					writebytes(fout, v6l.raw, 40);
					copypayload(fin, fout, ph.incl_len-54);	// copy the rest of the packet
					pcnt++;
				} else skippayload(fin, ph.incl_len-54);	// go to next packet
			} else {	// skip other protocol or mismatch of protocol and filter
				skippayload(fin, ph.incl_len-14);	// go to next packet
			}
			il_error = 0;
		} while ( ( ph.error == 0 ) && ( el.error == 0 ) );	// exit loop on error
		writeuint32(fout, maxsnaplen, 16, pcaph.magic_number);	// write maximal snap_len of all input files to output file
		fclose(fin);
	}
	fclose(fout);
	printf("Number of copied packets: %lu\n", pcnt);
	exit(0);
}
