#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

/*
Checkout
--------------
How to: https://learn.microsoft.com/en-us/windows/win32/wmisdk/creating-a-wmi-application-using-c-
Example: https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
*/

void ConnectToWMI(BSTR repository, IWbemLocator** locator, IWbemServices** services) {
    // COM interface pointers
    *locator = NULL;
    *services = NULL;

    // initialize COM
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    // connect to WMI
    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)locator);
    if (*locator == NULL) return;
    hr = (*locator)->lpVtbl->ConnectServer(locator, repository, NULL, NULL, NULL, 0, NULL, NULL, services);
}

HRESULT IssueWMIQuery(IWbemServices* services, BSTR language, BSTR query, IEnumWbemClassObject** results) {
    return services->lpVtbl->ExecQuery(services, language, query, WBEM_FLAG_BIDIRECTIONAL, NULL, results);
}

void DisconnectFromWMI(IWbemLocator** locator, IWbemServices** services, IEnumWbemClassObject** results) {
    (*results)->lpVtbl->Release(*results);
    (*services)->lpVtbl->Release(*services);
    (*locator)->lpVtbl->Release(*locator);

    CoUninitialize();
}

void main()
{
    // COM interface pointers
    IWbemLocator* locator = NULL;
    IWbemServices* services = NULL;
    IEnumWbemClassObject* results = NULL;

    // BSTR strings we'll use (http://msdn.microsoft.com/en-us/library/ms221069.aspx)
    BSTR repository = SysAllocString(L"ROOT\\CIMV2");
    BSTR language = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT * FROM CIM_BIOSElement");

    // Connect to WMI
    ConnectToWMI(repository, &locator, &services);
    
    // Issue WMI query and get results
    IssueWMIQuery(services, language, query, &results);

    // List the query results
    if (results != NULL) {
        IWbemClassObject* result = NULL;
        ULONG returnedCount = 0;
        HRESULT hr = 0;

        // enumerate the retrieved objects
        while ((hr = results->lpVtbl->Next(results, WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) {
            VARIANT name;

            // obtain the desired properties of the next result and print them out
            hr = result->lpVtbl->Get(result, L"Name", 0, &name, 0, 0);
            wprintf(L"%s\n", name.bstrVal);

            // release the current result object
            result->lpVtbl->Release(result);
        }
    }

    // Disconnect from WMI
    DisconnectFromWMI(&locator, &services, &results);

    // Free BSTRs
    SysFreeString(query);
    SysFreeString(language);
    SysFreeString(repository);
}