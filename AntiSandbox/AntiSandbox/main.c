#include "Windows.h"
#include "stdio.h"
#include "winternl.h"

void CustomZero(PCHAR buf, DWORD bufSize) {
	for (int i = 0; i < bufSize; i++) {
		buf[i] = 0;
	}
}

// vendorId is of 12 bytes string (excluding null terminator)
BOOL IsHypervisor(OPTIONAL OUT PCHAR vendorId) {
	// Get vendor ID
	CHAR vendorIdLocal[13];
	CustomZero(vendorIdLocal, 13);
	GetCpuId(vendorIdLocal);

	// If vendorId parameter is non-null, copy the found vendorIdLocal to that
	if (vendorId != NULL) {
		CustomZero(vendorId, 13);
		for (int i = 0; i < 12; i++) {
			vendorId[i] = vendorIdLocal[i];
		}
	}

	// Check vendor ID against blacklisted vendor IDs
	/*
	FreeBSD HV 	bhyve bhyve
	Hyper-V 	Microsoft Hv
	KVM 	KVMKVMKVM
	Parallels 	prl hyperv
	VirtualBox 	VBoxVBoxVBox
	VirtualPC 	Microsoft Hv
	VMware 	VMwareVMware
	Xen 	XenVMMXenVMM
	*/
	CHAR vendorIdsBlacklist[][13] = { "bhyve bhyve", "Microsoft Hv", "KVMKVMKVM", "prl hyperv", "VBoxVBoxVBox", "VMwareVMware", "XenVMMXenVMM" };
	for (int i = 0; i < 7; i++) {
		if (strcmp(vendorIdsBlacklist[i], vendorIdLocal) == 0) {
			return TRUE;
		}
	}

	// If check passes through, then it's not hypervisor
	return FALSE;
}

typedef struct _HV_DETAILS {
	ULONG Data[4];
} HV_DETAILS, * PHV_DETAILS;

typedef struct _HV_VENDOR_AND_MAX_FUNCTION {
	UINT32 MaxFunction;
	UINT8 VendorName[12];
} HV_VENDOR_AND_MAX_FUNCTION, *PHV_VENDOR_AND_MAX_FUNCTION;

typedef struct _HV_HYPERVISOR_INTERFACE_INFO {
	UINT32 Interface;
	UINT32 Reserved1;
	UINT32 Reserved2;
	UINT32 Reserved3;
} HV_HYPERVISOR_INTERFACE_INFO, * PHV_HYPERVISOR_INTERFACE_INFO;

typedef struct _HV_HYPERVISOR_VERSION_INFO {
	UINT32 BuildNumber;
	UINT32 MinorVersion : 16;
	UINT32 MajorVersion : 16;
	UINT32 ServicePack;
	UINT32 ServiceNumber : 24;
	UINT32 ServiceBranch : 8;
} HV_HYPERVISOR_VERSION_INFO, *PHV_HYPERVISOR_VERSION_INFO;

typedef struct _HV_IMPLEMENTATION_LIMITS {
		UINT32 MaxVirtualProcessorCount;
		UINT32 MaxLogicalProcessorCount;
		UINT32 Reserved1;
		UINT32 Reserved2;
} HV_IMPLEMENTATION_LIMITS, *PHV_IMPLEMENTATION_LIMITS;

typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION {
	HV_VENDOR_AND_MAX_FUNCTION HvVendorAndMaxFunction;
	HV_HYPERVISOR_INTERFACE_INFO HypervisorInterface;
	HV_HYPERVISOR_VERSION_INFO HypervisorVersion;
	HV_DETAILS HvFeatures;
	HV_DETAILS HwFeatures;
	HV_DETAILS EnlightenmentInfo;
	HV_IMPLEMENTATION_LIMITS ImplementationLimits;
} SYSTEM_HYPERVISOR_DETAIL_INFORMATION, *PSYSTEM_HYPERVISOR_DETAIL_INFORMATION;

BOOL GetHypervisorDetails(PSYSTEM_HYPERVISOR_DETAIL_INFORMATION pSystemHypervisorDetailInformation) {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL) return FALSE;
	PVOID pZwQuerySystemInformation = GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (pZwQuerySystemInformation == NULL) return FALSE;

	NTSTATUS (*ZwQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, ULONG * ReturnLength) = (NTSTATUS(*)())pZwQuerySystemInformation;
	CustomZero(pSystemHypervisorDetailInformation, sizeof(SYSTEM_HYPERVISOR_DETAIL_INFORMATION));
	NTSTATUS status = ZwQuerySystemInformation(0x9F, pSystemHypervisorDetailInformation, sizeof(SYSTEM_HYPERVISOR_DETAIL_INFORMATION), NULL);
	if (status != 0) return FALSE;

	return TRUE;
}

BOOL IsHypervisor3()
{
	unsigned int invalid_leaf = 0x13371337;
	unsigned int valid_leaf = 0x40000000;
	struct _HV_DETAILS
	{
		unsigned int Data[4];
	};
	HV_DETAILS InvalidLeafResponse = { 0 };
	HV_DETAILS ValidLeafResponse = { 0 };
	__cpuid(&InvalidLeafResponse, invalid_leaf);
	__cpuid(&ValidLeafResponse, valid_leaf);
	if ((InvalidLeafResponse.Data[0] != ValidLeafResponse.Data[0]) ||
		(InvalidLeafResponse.Data[1] != ValidLeafResponse.Data[1]) ||
		(InvalidLeafResponse.Data[2] != ValidLeafResponse.Data[2]) ||
		(InvalidLeafResponse.Data[3] != ValidLeafResponse.Data[3]))
		return TRUE;

	return FALSE;
}

void main() {
	/*
	CHAR vendorId[13];
	BOOL isHypervisor = IsHypervisor(vendorId);

	printf("Is hypervisor: %d; Vendor ID: %s\n", isHypervisor, vendorId);
	*/
	printf("IsHypervisor2: %d\n", IsHypervisor2());
	printf("IsHypervisor3: %d\n", IsHypervisor3());

	SYSTEM_HYPERVISOR_DETAIL_INFORMATION systemHypervisorDetailInformation;
	if (!GetHypervisorDetails(&systemHypervisorDetailInformation)) return;

	printf("Vendor ID: %.12s\n", systemHypervisorDetailInformation.HvVendorAndMaxFunction.VendorName);
	printf("Interface: %.4s\n", &systemHypervisorDetailInformation.HypervisorInterface.Interface);
	printf("Major version: %u; minor version: %u; build number: %u\n", systemHypervisorDetailInformation.HypervisorVersion.MajorVersion, systemHypervisorDetailInformation.HypervisorVersion.MinorVersion, systemHypervisorDetailInformation.HypervisorVersion.BuildNumber);
	printf("MaxLogicalProcessorCount: %u; MaxVirtualProcessorCount: %u\n", systemHypervisorDetailInformation.ImplementationLimits.MaxLogicalProcessorCount, systemHypervisorDetailInformation.ImplementationLimits.MaxVirtualProcessorCount);

	return;
}