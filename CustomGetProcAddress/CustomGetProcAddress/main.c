#include "windows.h"
#include "stdio.h"
#include "wchar.h";
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
	mbsrtowcs_s(&retVal, strOut, 1+ (strInLen * sizeof(WCHAR)), &strIn, strInLen, &state);
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

HMODULE GetModuleHandleCustom(PCHAR moduleName) {
	// Get PEB from GS register (for x64) or FS register (for x86)
#ifdef _WIN64
	PPEB pPeb = (PBYTE)(__readgsqword(96));
#elif _WIN32
	PPEB pPeb = (PBYTE)(__readfsdword(48));
#endif

	// Convert module name from ASCII to Unicode
	WCHAR moduleNameW[MAX_PATH * sizeof(WCHAR)];
	AsciiToWideString(moduleName, moduleNameW);

	// Cycle through modules and select the necessary one
	LIST_ENTRY listEntry = pPeb->Ldr->InMemoryOrderModuleList;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = listEntry.Flink;
	PLDR_DATA_TABLE_ENTRY pDataTableEntryFirst = listEntry.Flink;
	WCHAR dllNameCurrLower[MAX_PATH];
	WCHAR moduleNameWLower[MAX_PATH];

	RtlZeroMemoryCustom(moduleNameWLower, MAX_PATH);
	WideStringToLower(moduleNameW, moduleNameWLower);

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

void FreeLibraryCustom(IN HMODULE* phModule) {
	// Get FreeLibrary
	HMODULE hKernel32 = GetModuleHandleCustom("kernel32.dll");
	if (hKernel32 == NULL) {
		printf("Failed to locate Kernel32.dll for FreeLibraryCustom\n");
		return NULL;
	}
	PVOID pFreeLibrary = GetProcAddressCustom(hKernel32, "FreeLibrary");

	if (pFreeLibrary == NULL) {
		printf("Failed to locate necessary functions for unloading target module from memory\n");
		return NULL;
	}

	BOOL(*FreeLibrary)(HMODULE hLibModule) = (BOOL (*)())pFreeLibrary;

	// Use FreeLibrary
	if (!FreeLibrary(*phModule)) {
		printf("Failed to unload target module; error: %d\n", GetLastError());
	}
}

LPVOID LoadProcedure(IN PCHAR moduleName, IN PCHAR procName, OUT HMODULE* phModule) {
	// Get kernel32.dll handle. If not found in memory, load from file.
	HMODULE hKernel32 = GetModuleHandleCustom("Kernel32.dll");
	if (hKernel32 == NULL) {
		printf("Could not load kernel32.dll\n");
		return NULL;
	}

	// Find LoadLibraryA and GetProcAddress addresses
	LPVOID pLoadLibraryA = GetProcAddressCustom(hKernel32, "LoadLibraryA");
	LPVOID pGetProcAddress = GetProcAddressCustom(hKernel32, "GetProcAddress");
	if (pLoadLibraryA == NULL || pGetProcAddress == NULL) {
		printf("Failed to locate necessary functions to locate target module and function\n");
		return NULL;
	}
	HMODULE (*LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE (*)())pLoadLibraryA;
	LPVOID (*GetProcAddress)(HMODULE hModule, LPCSTR lpProcName) = (LPVOID (*)())pGetProcAddress;

	// Load the module, then locate the function in it
	*phModule = LoadLibraryA(moduleName);
	if (*phModule == NULL) {
		printf("Failed to load target module\n");
		return NULL;
	}
	LPVOID procAddress = GetProcAddress(*phModule, procName);

	// Return result
	return procAddress;
}

void main() {
	HMODULE hModule = NULL;

	// Find MessageBoxA address
	LPVOID procAddress = LoadProcedure("User32.dll", "MessageBoxA", &hModule);
	if (procAddress == NULL) {
		printf("Failed to locate function address\n");
		return;
	}

	// Execute MessageBoxA for demonstration
	int (*MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) = (int (*)())procAddress;
	MessageBoxA(NULL, "Hello world", "Demo", MB_OK);

	// Unload target library
	FreeLibraryCustom(&hModule);
}