#pragma once

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

void RtlZeroMemoryCustom(IN PBYTE pBuf, IN DWORD bufSize);
void WideStringToLower(IN PWCHAR strIn, IN OUT PWCHAR strOut);
void AsciiToWideString(IN PCHAR strIn, OUT PWCHAR strOut);
HMODULE GetModuleHandleCustom(PCHAR moduleName);
PVOID GetProcAddressCustom(HMODULE hModule, PCHAR procName);
BYTE GetByteAtAddress(PVOID baseAddr, DWORD32 offset);
WORD GetWordAtAddress(PVOID baseAddr, DWORD32 offset);
PVOID GetAddressAfterOffset(PVOID baseAddr, DWORD32 offset);
void SortIntegersArrayDWORD64(PDWORD64 inputArray, PDWORD64 outputArray, DWORD numElements);