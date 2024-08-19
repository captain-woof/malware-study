#include "Windows.h"

int main()
{
    LPCSTR moduleName = "TestDLL.dll";
    
    /* Get handle to test DLL */
    HANDLE hModule = GetModuleHandleA(moduleName);
    if (hModule == NULL) {
        hModule = LoadLibraryA(moduleName);
    }

    /* Get reference to exported function in test DLL */
    PVOID addrHelloWorld = GetProcAddress(hModule, "HelloWorld");

    /* Execute function */
    void (*HelloWorld)() = ((void (*)())addrHelloWorld);
    HelloWorld();
}


