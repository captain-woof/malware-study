#include "Windows.h"
#include "stdio.h"
#include "tlhelp32.h"

void strToLowerW(IN PWCHAR strSrc, OUT PWCHAR strOut) {
	DWORD size = lstrlenW(strSrc);

	// Copy all src bytes to destination while lowercasing it
	for (int i = 0; i < size; i++) {
		// For all other characters, proceed to copy and move on
		strOut[i] = (WCHAR)tolower(strSrc[i]);
	}
}

void findProcessWithName(IN PWCHAR targetProcessName, OUT PPROCESSENTRY32 pProcessEntry) {
	pProcessEntry->dwSize = sizeof(PROCESSENTRY32);
	WCHAR processNameLower[MAX_PATH];

	// Take all processes snapshot
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == NULL) return;

	// Find out first process
	if (!Process32First(hSnapshot, pProcessEntry)) {
		// Return if first process could not be derived
		CloseHandle(hSnapshot);
		return;
	}
	// Check if first process is the required one
	memset(processNameLower, 0, MAX_PATH);
	strToLowerW(pProcessEntry->szExeFile, processNameLower);
	if (wcscmp(processNameLower, targetProcessName) == 0) {
		CloseHandle(hSnapshot);
		return;
	}
	memset(processNameLower, 0, lstrlenW(processNameLower) * 2);
	
	// If not, continue iterating
	while (Process32Next(hSnapshot, pProcessEntry)) {
		strToLowerW(pProcessEntry->szExeFile, processNameLower);
		if (wcscmp(processNameLower, targetProcessName) == 0) {
			CloseHandle(hSnapshot);
			return;
		}
		memset(processNameLower, 0, lstrlenW(processNameLower) * 2);
	}

	// Cleanup
	pProcessEntry->th32ProcessID = -1;
	CloseHandle(hSnapshot);
}
void injectDll(PPROCESSENTRY32 pProcessEntry, PWCHAR targetDllPath) {
	// Get target process handle
	HANDLE hTargetProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pProcessEntry->th32ProcessID);
	if (hTargetProcess == NULL) {
		wprintf(L"Failed to open handle to \"%s\" (pid: %d)\n", pProcessEntry->szExeFile, pProcessEntry->th32ProcessID);
		return;
	}
	wprintf(L"Opened handle to PID: %d\n", pProcessEntry->th32ProcessID);

	// Use VirtualAllocEx to allocate memory in target process
	DWORD targetDllPathSize = (lstrlenW(targetDllPath) * 2) + 1;
	LPVOID targetDllPathAddr = VirtualAllocEx(hTargetProcess, NULL, targetDllPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (targetDllPathAddr == NULL) {
		wprintf(L"Failed to allocate memory for target DLL name in target process; error %d\n", GetLastError());
		CloseHandle(hTargetProcess);
		return;
	}
	wprintf(L"Allocated %d bytes at 0x%p in target process\n", targetDllPathSize, targetDllPathAddr);

	// Use "WriteProcessMemory" in target process to write name of target DLL
	DWORD numOfBytesWritten = 0;
	WriteProcessMemory(hTargetProcess, targetDllPathAddr, targetDllPath, targetDllPathSize, &numOfBytesWritten);
	if (numOfBytesWritten != targetDllPathSize) {
		wprintf(L"Failed to write entire target DLL name to target process; only %d/%d written; error: %d\n", numOfBytesWritten, targetDllPathSize, GetLastError());
		VirtualFreeEx(hTargetProcess, targetDllPathAddr, targetDllPathSize, MEM_DECOMMIT | MEM_RELEASE);
		CloseHandle(hTargetProcess);
		return;
	}
	wprintf(L"%d bytes written at 0x%p in target process\n", numOfBytesWritten, targetDllPathAddr);

	// Get "kernel32.dll" module handle
	HANDLE hModule = GetModuleHandleW(L"kernel32.dll");
	if (hModule == NULL) {
		wprintf(L"Failed to find \"kernel32.dll\"; error %d\n", GetLastError());
		VirtualFreeEx(hTargetProcess, targetDllPathAddr, targetDllPathSize, MEM_DECOMMIT | MEM_RELEASE);
		CloseHandle(hTargetProcess);
		return;
	}
	wprintf(L"Got handle to \"kernel32.dll\"\n");

	// Get virtual address of "LoadLibraryW"
	LPVOID pLoadLibraryW = GetProcAddress(hModule, "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		wprintf(L"Failed to find address of \"LoadLibraryW\" in target process; error %d\n", GetLastError());
		VirtualFreeEx(hTargetProcess, targetDllPathAddr, targetDllPathSize, MEM_DECOMMIT | MEM_RELEASE);
		CloseHandle(hTargetProcess);
		return;
	}
	wprintf(L"\"LoadLibraryW\" found at 0x%p in target process\n", pLoadLibraryW);

	// Call "CreateRemoteThread" in target process with entrypoint address as "LoadLibraryW" address, parameter as address where target DLL name was written
	DWORD targetThreadId = -1;
	HANDLE hTargetThread = CreateRemoteThread(hTargetProcess, NULL, 0, pLoadLibraryW, targetDllPathAddr, 0, &targetThreadId);
	if (targetThreadId == -1 || hTargetThread == NULL) {
		wprintf(L"Failed to create remote thread in target process; error %d\n", GetLastError());
		VirtualFreeEx(hTargetProcess, targetDllPathAddr, targetDllPathSize, MEM_DECOMMIT | MEM_RELEASE);
		CloseHandle(hTargetProcess);
		return;
	}
	wprintf(L"Created remote thread in target process, thread ID: %d\n", targetThreadId);

	// Wait for thread to complete
	WaitForSingleObject(hTargetThread, INFINITE);
	wprintf(L"Target thread execution complete\n");

	// Cleanup
	VirtualFreeEx(hTargetProcess, targetDllPathAddr, targetDllPathSize, MEM_DECOMMIT | MEM_RELEASE);
	CloseHandle(hTargetProcess);
}

BOOL doesFileExist(PWCHAR filePath) {
	DWORD attr = GetFileAttributesW(filePath);

	return ((attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

// DllInjector.exe PATH_TO_DLL TARGET_PROCESS_NAME
void wmain(DWORD argc, PWCHAR argv[]) {
	// Parse command line arguments
	if (argc != 3) {
		wprintf(L"Usage: DllInjector.exe PATH_TO_DLL TARGET_PROCESS_NAME\n");
		return;
	}
	PWCHAR targetDllPath = argv[1];
	PWCHAR targetProcessName = argv[2];

	// Validate target DLL exists
	if (!doesFileExist(targetDllPath)) {
		wprintf(L"\"%s\" does not exist\n", targetDllPath);
		return;
	}

	// Try finding the target process
	PROCESSENTRY32 processEntry;
	findProcessWithName(targetProcessName, &processEntry);
	if(processEntry.th32ProcessID == -1) {
		wprintf(L"Could not find \"%s\"\n", targetProcessName);
	}
	else {
		// Target process is found
		wprintf(L"Found PID: %d\n", processEntry.th32ProcessID);

		// Perform DLL injection
		injectDll(&processEntry, targetDllPath);
	}
}