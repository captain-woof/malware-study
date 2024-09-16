#include "Windows.h"
#include "winternl.h"

void RtlZeroMemoryCustom(IN PBYTE pBuf, IN DWORD bufSize) {
	for (int i = 0; i < bufSize; i++) {
		pBuf[i] = 0;
	}
}

void WideStringToLower(IN PWCHAR strIn, IN OUT PWCHAR strOut) {
	int stringLenBytes = lstrlenW(strIn) * sizeof(WCHAR);
	for (int i = 0; i < stringLenBytes; i++) {
		strOut[i] = towlower(strIn[i]);
	}
}

void AsciiToWideString(IN PCHAR strIn, OUT PWCHAR strOut) {
	mbstate_t state;
	SIZE_T strInLen = strlen(strIn);
	SIZE_T retVal = 0;
	memset(&state, 0, sizeof(state));
	mbsrtowcs_s(&retVal, strOut, 1 + (strInLen * sizeof(WCHAR)), &strIn, strInLen, &state);
}

HMODULE GetModuleHandleCustom(PCHAR moduleName) {
	// Get PEB from GS register (for x64) or FS register (for x86)
#ifdef _WIN64
	PPEB pPeb = (PVOID)(__readgsqword(12 * sizeof(PVOID)));
#elif _WIN32
	PPEB pPeb = (PVOID)(__readfsdword(12 * sizeof(PVOID)));
#endif

	// Convert module name from ASCII to Unicode lower
	WCHAR moduleNameW[MAX_PATH * sizeof(WCHAR)];
	WCHAR moduleNameWLower[MAX_PATH];
	AsciiToWideString(moduleName, moduleNameW);
	RtlZeroMemoryCustom(moduleNameWLower, MAX_PATH);
	WideStringToLower(moduleNameW, moduleNameWLower);

	// Cycle through modules and select the necessary one
	WCHAR dllNameCurrLower[MAX_PATH];
	LIST_ENTRY listEntry = pPeb->Ldr->InMemoryOrderModuleList;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = listEntry.Flink;
	PLDR_DATA_TABLE_ENTRY pDataTableEntryFirst = listEntry.Flink;

	while (TRUE) {
		// If current module's name matches, return address to it
		RtlZeroMemoryCustom(dllNameCurrLower, MAX_PATH);
		WideStringToLower(pDataTableEntry->FullDllName.Buffer, dllNameCurrLower);
		if (lstrcmpW(dllNameCurrLower, moduleNameWLower) == 0) {
			return (HMODULE)pDataTableEntry->Reserved2[0];
		}

		// Move to next entry
		pDataTableEntry = pDataTableEntry->Reserved1[0];

		// Break if we reach first element of the circular linked list
		if (pDataTableEntry == pDataTableEntryFirst) {
			break;
		}
	}

	// If execution comes here, it means module was not found
	return NULL;
}

PVOID GetProcAddressCustom(HMODULE hModule, PCHAR procName) {
	// Get export data directory
	PBYTE pModuleBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pModuleBase + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pDirectoryExport = (PIMAGE_EXPORT_DIRECTORY)(pModuleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pAddressOfNames = (pModuleBase + (pDirectoryExport->AddressOfNames));
	PWORD pAddressOfOrdinals = (pModuleBase + (pDirectoryExport->AddressOfNameOrdinals));
	PDWORD pAddressOfFunctions = (pModuleBase + (pDirectoryExport->AddressOfFunctions));

	for (int i = 0; i < pDirectoryExport->NumberOfNames; i++) {
		PCHAR procNameCurr = pModuleBase + pAddressOfNames[i];
		if (strcmp(procNameCurr, procName) == 0) {
			return (PVOID)(pModuleBase + pAddressOfFunctions[pAddressOfOrdinals[i]]);
		}
	}

	return NULL;
}

BYTE GetByteAtAddress(PVOID baseAddr, DWORD32 offset) {
#ifdef _M_X64
	return *(BYTE*)((DWORD64)baseAddr + offset);
#else
	return *(BYTE*)((DWORD32)baseAddr + offset);
#endif
}

WORD GetWordAtAddress(PVOID baseAddr, DWORD32 offset) {
#ifdef _M_X64
	return *(WORD*)((DWORD64)baseAddr + offset);
#else
	return *(WORD*)((DWORD32)baseAddr + offset);
#endif
}

PVOID GetAddressAfterOffset(PVOID baseAddr, DWORD32 offset) {
#ifdef _M_X64
	return (PVOID)((DWORD64)baseAddr + offset);
#elif
	return (PVOID)((DWORD32)baseAddr + offset);
#endif
}

// Ascending comparator for SortIntegersArray function
DWORD SortIntegersArrayComparatorDWORD64(PDWORD64 elem1, PDWORD64 elem2) {
	if (*elem1 < *elem2) {
		return -1;
	}
	else if (*elem1 > *elem2) {
		return 1;
	}
	else {
		return 0;
	}
}

// Quicksort function
void SortIntegersArrayDWORD64(PDWORD64 inputArray, PDWORD64 outputArray, DWORD numElements) {
	// Copy input array elements into output array elements
	for (DWORD i = 0; i < numElements; i++) {
		outputArray[i] = inputArray[i];
	}
	// Perform quicksort
	qsort(outputArray, numElements, sizeof(DWORD64), &SortIntegersArrayComparatorDWORD64);
}