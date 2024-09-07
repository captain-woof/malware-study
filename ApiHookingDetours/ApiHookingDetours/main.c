#include "stdio.h"
#include "Windows.h"
#include "detours.h"

/*
NOTE: DETOURS LIBRARY WILL NOT WORK WITH DEBUG BUILDS
*/

int (WINAPI* MessageBoxAActual)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) = MessageBoxA;

int hookFunction(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	// Custom functionality
	printf("From hooked function; MessageBoxA about to be called with body-text: \"%s\"\n", lpText);

	// Call actual target function
	return MessageBoxAActual(hWnd,lpText, lpCaption, uType);
}

BOOL installHook() {
	DWORD error = NO_ERROR;

	error = DetourTransactionBegin();
	if (error != NO_ERROR) {
		printf("Failed to begin Detour transaction; error: %d\n", error);
		return FALSE;
	}

	error = DetourUpdateThread(GetCurrentThread());
	if (error != NO_ERROR) {
		printf("Failed to update thread for Detour transaction; error: %d\n", error);
		return FALSE;
	}

	error = DetourAttach(&(PVOID)MessageBoxAActual, hookFunction);
	if (error != NO_ERROR) {
		printf("Failed to attach Detour hook function; error: %d\n", error);
		return FALSE;
	}

	error = DetourTransactionCommit();
	if (error != NO_ERROR) {
		printf("Failed to commit Detour transaction; error: %d\n", error);
		return FALSE;
	}

	return TRUE;
}

BOOL removeHook() {
	DWORD error = NO_ERROR;

	error = DetourTransactionBegin();
	if (error != NO_ERROR) {
		printf("Failed to begin Detour transaction; error: %d\n", error);
		return FALSE;
	}

	error = DetourUpdateThread(GetCurrentThread());
	if (error != NO_ERROR) {
		printf("Failed to update thread for Detour transaction; error: %d\n", error);
		return FALSE;
	}

	error = DetourDetach(&(PVOID)MessageBoxAActual, hookFunction);
	if (error != NO_ERROR) {
		printf("Failed to detach Detour hook function; error: %d\n", error);
		return FALSE;
	}

	error = DetourTransactionCommit();
	if (error != NO_ERROR) {
		printf("Failed to commit Detour transaction; error: %d\n", error);
		return FALSE;
	}

	return TRUE;
}

void main() {
	// Install hook
	installHook();

	// Invoke hooked function
	MessageBoxA(NULL, "Testing API hooking", "Test", MB_OK);

	// Remove hook
	removeHook();
}