#include "windows.h"
#include "stdio.h"

typedef struct _ustring {
    DWORD Length;
    DWORD MaximumLength;
    unsigned char* Buffer;
} ustring;

int main()
{
    /* Get reference to SystemFunction032 or SystemFunction033 */
    HMODULE hModule = GetModuleHandle(L"advapi32.dll");
    if (hModule == NULL) {
        hModule = LoadLibrary(L"advapi32.dll");
        if (hModule == NULL) {
            exit(1);
        }
    }
    NTSTATUS (*SystemFunction032)(ustring* data, ustring* key) = ((NTSTATUS(*)(ustring*, ustring*))GetProcAddress(hModule, "SystemFunction032"));

    /* Prepare context */
    PCHAR keyString = "PASSWORD";
    PCHAR plaintextString = "This message is to be encrypted";
    DWORD plaintextStringSize = strlen(plaintextString);
    DWORD keyStringSize = strlen(keyString);
    PCHAR encryptedString = malloc(plaintextStringSize + 1);
    strcpy_s(encryptedString, plaintextStringSize + 1, plaintextString);
    ustring key = { .Length = keyStringSize, .MaximumLength = keyStringSize, .Buffer = keyString};
    ustring data = { .Length = plaintextStringSize, .MaximumLength = plaintextStringSize, .Buffer = encryptedString };

    /* Perform encryption */
    SystemFunction032(&data, &key);
    printf("Original plaintext: %s\n", plaintextString);
    printf("Encrypted ciphertext: %s\n", data.Buffer);


    /* Perform decryption */
    SystemFunction032(&data, &key);
    printf("Decrypted ciphertext: %s\n", data.Buffer);

    /* Free memory */
    free(encryptedString);
}
