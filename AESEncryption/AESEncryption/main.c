#include "Windows.h"
#include "stdio.h"
#include "aes.h"

void printBytes(DWORD sizeBytes, PBYTE pBytes) {
	for (int i = 0; i < sizeBytes; i++) {
		printf("%.2x", pBytes[i]);
	}
}

void generateRandomBytes(DWORD sizeBytesRandom, PBYTE pBytesRandom) {
	for (int i = 0; i < sizeBytesRandom; i++) {
		pBytesRandom[i] = rand();
	}
}

DWORD padBytesSize(DWORD blockSizeInBytes, DWORD bytesSize) {
	DWORD bytesPaddedSize = bytesSize + (blockSizeInBytes - (bytesSize % blockSizeInBytes));
	return bytesPaddedSize;
}

PBYTE padBytes(DWORD blockSizeInBytes, DWORD bytesSize, PBYTE pBytes) {
	DWORD bytesPaddedSize = padBytesSize(blockSizeInBytes, bytesSize);
	PBYTE pBytesPadded = malloc(bytesPaddedSize);
	memset(pBytesPadded, 0, bytesPaddedSize);
	memcpy(pBytesPadded, pBytes, bytesSize);
	return pBytesPadded;
}

const DWORD aesBlockSizeInBytes = 16;
const DWORD aesIvSizeInBytes = 16;
const DWORD aesKeySizeInBytes = 32; // 32 bytes for AES256

void main() {
	/* Seed random with time */
	srand(time(NULL));

	/* Initialise key and IV */
	PBYTE pIV = malloc(aesIvSizeInBytes);
	PBYTE pKey = malloc(aesKeySizeInBytes);
	generateRandomBytes(aesIvSizeInBytes, pIV);
	generateRandomBytes(aesKeySizeInBytes, pKey);

	/* Data to encrypt */
	PBYTE pMessage = "secret";
	DWORD messageSize = strlen(pMessage);
	PBYTE pMessagePadded = padBytes(aesBlockSizeInBytes, messageSize, pMessage);
	DWORD messagePaddedSizeInBytes = padBytesSize(aesBlockSizeInBytes, messageSize);

	printf("Original plaintext: %s\n", pMessage);
	printf("Padded plaintext %d bytes: ", messagePaddedSizeInBytes);
	printBytes(messagePaddedSizeInBytes, pMessagePadded);
	printf("\n");

	/* Perform encryption */
	struct AES_ctx ctx_encryption;
	AES_init_ctx_iv(&ctx_encryption, pKey, pIV); // Prepare encryption context

	printf("Key: ");
	printBytes(aesKeySizeInBytes, pKey);
	printf(", IV: ");
	printBytes(aesIvSizeInBytes, pIV);
	printf("\n");
	
	AES_CBC_encrypt_buffer(&ctx_encryption, pMessagePadded, messagePaddedSizeInBytes);
	printf("Encrypted buffer bytes: ");
	printBytes(messagePaddedSizeInBytes, pMessagePadded);
	printf("\n");

	/* Perform decryption */
	struct AES_ctx ctx_decryption;
	AES_init_ctx_iv(&ctx_decryption, pKey, pIV); // Prepare decryption context, same as encryption context (DONT REUSE SAME CONTEXT; INIT NEW)

	printf("Key: ");
	printBytes(aesKeySizeInBytes, pKey);
	printf(", IV: ");
	printBytes(aesIvSizeInBytes, pIV);
	printf("\n");

	AES_CBC_decrypt_buffer(&ctx_decryption, pMessagePadded, messagePaddedSizeInBytes);
	printf("Decrypted buffer bytes: ");
	printBytes(messagePaddedSizeInBytes, pMessagePadded);
	printf("\n");
	printf("Decrypted plaintext: %s\n", pMessagePadded);

	/* Cleanup */
	free(pIV);
	free(pKey);
	free(pMessagePadded);
}