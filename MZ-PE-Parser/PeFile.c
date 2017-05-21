#include "PeFile.h"
#include <stdio.h>

#define ASCII_MZ	0x5a4d
#define ASCII_PE00	0x00004550

/* ===================== init ===================== */

static DWORD
LoadDosHeader(
	_Inout_	PPE_FILE	pPeFile
)
{
	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. LoadDosHeader: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	pPeFile->pDosHeader = (PIMAGE_DOS_HEADER)pPeFile->pData;
	if (pPeFile->pDosHeader->e_magic != ASCII_MZ)
	{
		fprintf(stderr, "[ERR]. LoadDosHeader: invalid MZ magic.\n");
		return ERROR_INVALID_MZ_MAGIC;
	}
	return ERROR_SUCCESS;
}

static DWORD
LoadNtHeader(
	_Inout_	PPE_FILE	pPeFile
)
{
	DWORD	ntOffset;
	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. LoadNtHeader: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	ntOffset = (DWORD)pPeFile->pDosHeader->e_lfanew;
	if (ntOffset > pPeFile->bcFileSize || pPeFile->pDosHeader->e_lfanew < 0)
	{
		fprintf(stderr, "[ERR]. LoadNtHeader: invalid FA inside e_lfanew.\n");
		return ERROR_INVALID_LFANEW;
	}

	pPeFile->pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pPeFile->pDosHeader + ntOffset);
	if (pPeFile->pNtHeaders->Signature != ASCII_PE00)
	{
		fprintf(stderr, "[ERR]. LoadNtHeader: invalid PE magic.\n");
		return ERROR_INVALID_PE_MAGIC;
	}
	return ERROR_SUCCESS;
}

static DWORD
LoadSectionHeaders(
	_Inout_	PPE_FILE	pPeFile
)
{
	DWORD headersOffset;

	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. LoadSectionHeaders: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	headersOffset = sizeof(DWORD) +
		sizeof(IMAGE_FILE_HEADER) +
		pPeFile->pNtHeaders->FileHeader.SizeOfOptionalHeader;
	pPeFile->pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pPeFile->pNtHeaders + headersOffset);
	return ERROR_SUCCESS;
}

static DWORD
LoadExportDirectory(
	_Inout_	PPE_FILE	pPeFile
)
{
	DWORD	exportDirectoryRva;
	PBYTE	exportDirectoryOffset;

	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. LoadExportDirectory: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}
	
	exportDirectoryRva = pPeFile->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	exportDirectoryOffset = OffsetFromRva(pPeFile, exportDirectoryRva);
	pPeFile->pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)exportDirectoryOffset;
	pPeFile->exportDirectorySize = pPeFile->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	return ERROR_SUCCESS;
}

static DWORD
LoadImportDirectory(
	_Inout_	PPE_FILE	pPeFile
)
{
	DWORD	importDirectoryRva;
	PBYTE	importDirectoryOffset;

	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. LoadImportDirectory: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	importDirectoryRva = pPeFile->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	importDirectoryOffset = OffsetFromRva(pPeFile, importDirectoryRva);
	pPeFile->lpImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR)importDirectoryOffset;
	pPeFile->importDescriptorsSize = pPeFile->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	return ERROR_SUCCESS;
}

DWORD
PeFileInit(
	_Out_		PPE_FILE	pPeFile,
	_In_		PBYTE		pData,
	_In_		DWORD		bcFileSize
)
{
	DWORD	errorCode;

	if (NULL == pData || NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. PeFileInit: invalid parameter(s).\n");
		return ERROR_INVALID_PARAMETER;
	}

	errorCode = ERROR_SUCCESS;

	pPeFile->pData = pData;
	pPeFile->bcFileSize = bcFileSize;

	errorCode = LoadDosHeader(pPeFile);
	if (errorCode != ERROR_SUCCESS)
	{
		return errorCode;
	}

	errorCode = LoadNtHeader(pPeFile);
	if (errorCode != ERROR_SUCCESS)
	{
		return errorCode;
	}

	pPeFile->optionalHeaderMagic = pPeFile->pNtHeaders->OptionalHeader.Magic;

	errorCode = LoadSectionHeaders(pPeFile);
	if (errorCode != ERROR_SUCCESS)
	{
		return errorCode;
	}

	errorCode = LoadExportDirectory(pPeFile);
	if (errorCode != ERROR_SUCCESS)
	{
		return errorCode;
	}

	errorCode = LoadImportDirectory(pPeFile);
	if (errorCode != ERROR_SUCCESS)
	{
		return errorCode;
	}

	return ERROR_SUCCESS;
}

/* ===================== addr ===================== */

DWORD
FaFromRva(
	_In_	PPE_FILE	pPeFile,
	_In_	DWORD		rvaAddress
)
{
	DWORD	i;
	DWORD	offset;
	DWORD	size;

	for (i = 0; i < pPeFile->pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		size = 0;
		size = pPeFile->pSectionHeaders[i].Misc.VirtualSize;
		if ((rvaAddress >= pPeFile->pSectionHeaders[i].VirtualAddress) && (rvaAddress < pPeFile->pSectionHeaders[i].VirtualAddress + size))
		{
			offset = rvaAddress - pPeFile->pSectionHeaders[i].VirtualAddress;
			return pPeFile->pSectionHeaders[i].PointerToRawData + offset;
		}
	}
	return 0;
}

PBYTE
OffsetFromRva(
	_In_	PPE_FILE	pPeFile,
	_In_	DWORD		rvaAddress
)
{
	DWORD faAddress;

	faAddress = FaFromRva(pPeFile, rvaAddress);
	if (0 == faAddress)
	{
		return NULL;
	}
	return pPeFile->pData + faAddress;
}

/* ===================== info ===================== */

DWORD
PrintFileHeaderInfos(
	_In_	PPE_FILE	pPeFile
)
{
	WORD machine;
	WORD nrOfSections;
	WORD characteristics;

	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. PrintFileHeaderInfos: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	machine = pPeFile->pNtHeaders->FileHeader.Machine;
	nrOfSections = pPeFile->pNtHeaders->FileHeader.NumberOfSections;
	characteristics = pPeFile->pNtHeaders->FileHeader.Characteristics;

	// Machine
	printf("Machine id: %u\n", machine);
	printf("Machine: ");
	switch (machine)
	{
	case IMAGE_FILE_MACHINE_UNKNOWN:
		printf("[any]");
		break;
	case IMAGE_FILE_MACHINE_AM33:
		printf("Matsushita AM33");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		printf("AMD x64");
		break;
	case IMAGE_FILE_MACHINE_ARM:
		printf("ARM little endian");
		break;
	case IMAGE_FILE_MACHINE_ARMNT:
		printf("ARM Thumb-2 little endian");
		break;
	case IMAGE_FILE_MACHINE_EBC:
		printf("EFI byte code");
		break;
	case IMAGE_FILE_MACHINE_I386:
		printf("Intel i386 (x86)");
		break;
	case 0x014d:
		printf("Intel 80486 family");
		break;
	case 0x014e:
		printf("Intel Pentium");
		break;
	case IMAGE_FILE_MACHINE_IA64:
		printf("Intel IA64 Itanium");
		break;
	case IMAGE_FILE_MACHINE_M32R:
		printf("Mitsubishi M32R (little endian)");
		break;
	case IMAGE_FILE_MACHINE_MIPS16:
		printf("MIPS16");
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU:
		printf("MIPS with FPU");
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU16:
		printf("MIPS16 with FPU");
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		printf("IBM Power PC (little endian)");
		break;
	case IMAGE_FILE_MACHINE_POWERPCFP:
		printf("IBM Power PC FP (with floating point support)");
		break;
	case IMAGE_FILE_MACHINE_R4000:
		printf("MIPS little endian");
		break;
	case IMAGE_FILE_MACHINE_SH3:
		printf("Hitachi SH3");
		break;
	case IMAGE_FILE_MACHINE_SH3DSP:
		printf("Hitachi SH3 DSP");
		break;
	case IMAGE_FILE_MACHINE_SH4:
		printf("Hitachi SH4");
		break;
	case IMAGE_FILE_MACHINE_SH5:
		printf("Hitachi SH5");
		break;
	case IMAGE_FILE_MACHINE_THUMB:
		printf("ARM Thumb");
		break;
	case IMAGE_FILE_MACHINE_WCEMIPSV2:
		printf("MIPS little-endian WCE v2");
		break;
	default:
		printf("[unknown]");
	}
	printf("\n");

	// Number of sections
	printf("Number of sections: %u", nrOfSections);
	if (nrOfSections >= MAX_INCONSISTENCY_COUNT_SECTIONS)
	{
		printf(" (may be inconsistent)");
	}
	printf("\n");

	// Characteristics
	printf("Characteristics: 0x04%x:\n", characteristics);
	if (characteristics & IMAGE_FILE_RELOCS_STRIPPED)
	{
		printf("\t- IMAGE_FILE_RELOCS_STRIPPED: There is no base relocation information in the file. It must be loaded at its preferred base address.\n");
		printf("\tIf the base address is not available, the loader reports an error.\n");
		printf("\tThe default behavior of the linker is to strip base relocations from executable (EXE) files.\n");
	}
	if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
	{
		printf("\t- IMAGE_FILE_EXECUTABLE_IMAGE: The file is executable (there are no unresolved external references).\n");
	}
	if (characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
	{
		printf("\t- IMAGE_FILE_LINE_NUMS_STRIPPED [deprecated]: COFF line numbers were stripped from the file.\n");
	}
	if (characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
	{
		printf("\t- IMAGE_FILE_LOCAL_SYMS_STRIPPED [deprecated]: COFF symbol table entries were stripped from file.\n");
	}
	if (characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM)
	{
		printf("\t- IMAGE_FILE_AGGRESIVE_WS_TRIM [deprecated]: Aggressively trim working set. i.e. the operating system is supposed to trim the working\n");
		printf("\tset of the running proces (the amount of RAM the process uses) aggressivly by paging it out\n");
	}
	if (characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
	{
		printf("\t- IMAGE_FILE_LARGE_ADDRESS_AWARE: The application can handle addresses larger than 2 GB.\n");
	}
	if (characteristics & IMAGE_FILE_BYTES_REVERSED_LO)
	{
		printf("\t- IMAGE_FILE_BYTES_REVERSED_LO [deprecated]: Little endian.\n");
	}
	if (characteristics & IMAGE_FILE_32BIT_MACHINE)
	{
		printf("\t- IMAGE_FILE_32BIT_MACHINE: Machine is based on a 32-bit-word architecture.\n");
	}
	if (characteristics & IMAGE_FILE_DEBUG_STRIPPED)
	{
		printf("\t- IMAGE_FILE_DEBUG_STRIPPED: Debugging information is removed from the image file.\n");
	}
	if (characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
	{
		printf("\t- IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: The application may not run from a removable medium such as a floppy or a CD - ROM.\n");
		printf("\tThe operating system is advised to copy the file to the swapfile and execute it from there.\n");
	}
	if (characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP)
	{
		printf("\t- IMAGE_FILE_NET_RUN_FROM_SWAP: The application may not run from the network.\n");
		printf("\tThe operating system is advised to copy the file to the swapfile and execute it from there.\n");
	}
	if (characteristics & IMAGE_FILE_SYSTEM)
	{
		printf("\t- IMAGE_FILE_SYSTEM: The image file is a system file (e.g. driver, etc.), not a user program.\n");
	}
	if (characteristics & IMAGE_FILE_DLL)
	{
		printf("\t- IMAGE_FILE_DLL: The image file is a dynamic-link library (DLL).\n");
	}
	if (characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
	{
		printf("\t- IMAGE_FILE_UP_SYSTEM_ONLY: The file should be run only on a uniprocessor machine.\n");
	}
	if (characteristics & IMAGE_FILE_BYTES_REVERSED_HI)
	{
		printf("\t- IMAGE_FILE_BYTES_REVERSED_HI [deprecated]: Big endian.\n");
	}

	return ERROR_SUCCESS;
}

DWORD
PrintOptionalHeaderInfos(
	_In_	PPE_FILE	pPeFile
)
{
	DWORD	addressOfEntryPoint;
	DWORD	imageBase;
	DWORD	sectionAlignment;
	DWORD	fileAlignment;
	WORD	subsystem;
	DWORD	numberOfRvaAndSizes;

	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. PrintFileHeaderInfos: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	addressOfEntryPoint = pPeFile->pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	imageBase = pPeFile->pNtHeaders->OptionalHeader.ImageBase;
	sectionAlignment = pPeFile->pNtHeaders->OptionalHeader.SectionAlignment;
	fileAlignment = pPeFile->pNtHeaders->OptionalHeader.FileAlignment;
	subsystem = pPeFile->pNtHeaders->OptionalHeader.Subsystem;
	numberOfRvaAndSizes = pPeFile->pNtHeaders->OptionalHeader.NumberOfRvaAndSizes;

	// AddressOfEntryPoint
	printf("AddressOfEntryPoint:\n");
	printf("\tRVA:\t0x%08x\n\tFA:\t0x%08x\n", addressOfEntryPoint, FaFromRva(pPeFile, addressOfEntryPoint));

	// ImageBase
	printf("ImageBase: 0x%08x\n", imageBase);

	// SectionAlignment
	printf("SectionAlignment: %lu bytes\n", sectionAlignment);

	// FileAlignment
	printf("FileAlignment: %lu bytes\n", fileAlignment);

	// Subsystem
	printf("Subsystem: 0x04%x: ", subsystem);
	switch (subsystem)
	{
	case IMAGE_SUBSYSTEM_UNKNOWN:
		printf("unknown system");
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		printf("device drivers and native Windows processes");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		printf("Windows GUI");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		printf("Windows CUI");
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		printf("OS/2 CUI");
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		printf("POSIX CUI");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		printf("Windows CE");
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		printf("Extensible Firmware Interface (EFI)");
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		printf("EFI driver with boot services");
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		printf("EFI driver with run-time services");
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		printf("EFI ROM image");
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		printf("XBOX");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		printf("Windows Boot Application");
		break;
	default:
		printf("[unknown]");
		break;
	}
	printf("\n");

	// NumberOfRvaAndSizes
	printf("NumberOfRvaAndSizes: %lu\n", numberOfRvaAndSizes);

	return ERROR_SUCCESS;
}

DWORD
PrintSectionHeadersInfos(
	_In_	PPE_FILE	pPeFile
)
{
	DWORD	nrSections;
	DWORD	iSection;
	CHAR	temp[IMAGE_SIZEOF_SHORT_NAME + 1];

	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. PrintSectionHeadersInfos: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	nrSections = pPeFile->pNtHeaders->FileHeader.NumberOfSections;
	memset(temp, 0, IMAGE_SIZEOF_SHORT_NAME + 1);

	for (iSection = 0; iSection < nrSections; iSection++)
	{
		memset(temp, 0, IMAGE_SIZEOF_SHORT_NAME + 1);
		memcpy(temp, pPeFile->pSectionHeaders[iSection].Name, IMAGE_SIZEOF_SHORT_NAME);
		printf("Section nr. %lu:\n", iSection + 1);
		printf("\t- name:\t%s\n", temp);
		printf(
			"\t- addresss:\n\t\tRVA:\t0x%08x\n\t\tFA:\t0x%08x\n",
			pPeFile->pSectionHeaders[iSection].VirtualAddress,
			FaFromRva(pPeFile, pPeFile->pSectionHeaders[iSection].VirtualAddress)
		);
		printf("\t- virtual size:\t%lu bytes\n", pPeFile->pSectionHeaders[iSection].Misc.VirtualSize);
		printf("\t- raw size:\t%lu bytes\n", pPeFile->pSectionHeaders[iSection].SizeOfRawData);

		if (iSection > MAX_INCONSISTENCY_COUNT_SECTIONS)
		{
			printf(
				"NumberOfSections (%d) seems to indicate inconsistent section headers. Only %d out of %d sections were shown.\n",
				nrSections,
				iSection + 1,
				nrSections
			);
			break;
		}
	}

	return ERROR_SUCCESS;
}

DWORD
PrintExportInfos(
	_In_	PPE_FILE	pPeFile
)
{
	DWORD	error;
	LPSTR	dllName;
	DWORD	nrOfNames;
	DWORD	nrOfFunctions;
	PDWORD	functionNames;
	PWORD	functionOrdinals;
	PDWORD	functionAddresses;
	DWORD	i;
	PBYTE	fName;
	WORD	fOrdinal;
	DWORD	fRva;
	LPBYTE	lpFlagArray;
	DWORD	nInconsistencyCount;

	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. PrintExportInfos: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	if (pPeFile->exportDirectorySize == 0)
	{
		printf("The PE file has no export directory (size = 0).\n");
		return ERROR_SUCCESS;
	}
	if (pPeFile->pExportDirectory == NULL)
	{
		printf("Null export directory file offset due to invalid or null RVA (size = %lu)\n", pPeFile->exportDirectorySize);
		return ERROR_SUCCESS;
	}

	if (((PBYTE)pPeFile->pExportDirectory > pPeFile->pData + pPeFile->bcFileSize) || ((PBYTE)pPeFile->pExportDirectory < pPeFile->pData))
	{
		fprintf(stderr, "[ERR]. PrintExportInfos: pointer to export directory is invalid.\n");
		return ERROR_INVALID_POINTER;
	}

	error = ERROR_SUCCESS;
	dllName = NULL;
	nrOfNames = 0;
	nrOfFunctions = 0;
	functionNames = NULL;
	functionOrdinals = NULL;
	functionAddresses = NULL;
	lpFlagArray = NULL;
	nInconsistencyCount = 0;

	__try
	{
		dllName = (LPSTR)OffsetFromRva(pPeFile, pPeFile->pExportDirectory->Name);
		if (dllName)
		{
			printf("name of the DLL: %s\n", dllName);
		}
		else
		{
			printf("name of the DLL: [unknown] due to bad RVA.\n");
		}

		nrOfNames = pPeFile->pExportDirectory->NumberOfNames;
		printf("nr of functions exported by name: %lu\n", nrOfNames);

		nrOfFunctions = pPeFile->pExportDirectory->NumberOfFunctions;
		printf("total number of functions: %lu\n", nrOfFunctions);

		functionNames = (PDWORD)OffsetFromRva(pPeFile, pPeFile->pExportDirectory->AddressOfNames);
		functionOrdinals = (PWORD)OffsetFromRva(pPeFile, pPeFile->pExportDirectory->AddressOfNameOrdinals);
		functionAddresses = (PDWORD)OffsetFromRva(pPeFile, pPeFile->pExportDirectory->AddressOfFunctions);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf("Cannot parse export directory due to exception while accessing the fields.\n");
		error = ERROR_INVALID_STRUCT_ACCESS;
	}
	if (error != ERROR_SUCCESS)
	{
		goto CleanUp;
	}

	lpFlagArray = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nrOfFunctions * sizeof(BYTE));
	if (NULL == lpFlagArray)
	{
		error = GetLastError();
		fprintf(stderr, "PrintExportInfos: HeapAlloc() failed. GLE = 0x%x.\n", error);
		goto CleanUp;
	}

	printf("\n%11s %-50s %-10s %-10s\n", "Ordinal", "Function name", "RVA", "FA");

	// functions exported by name
	for (i = 0; i < nrOfNames; i++)
	{
		fOrdinal = 0;
		fName = NULL;
		fRva = 0;

		__try
		{
			fOrdinal = functionOrdinals[i];
			fName = OffsetFromRva(pPeFile, functionNames[i]);
			fRva = functionAddresses[fOrdinal];

			if (fName)
			{
				printf("%11u %-50s 0x%08x 0x%08x\n", fOrdinal, fName, fRva, FaFromRva(pPeFile, fRva));
			}
			else
			{
				printf("%11u %-50s 0x%08x 0x%08x\n", fOrdinal, "[unknown_function_name]", fRva, FaFromRva(pPeFile, fRva));
			}

			lpFlagArray[fOrdinal] = 1;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			nInconsistencyCount += 1;
			if (nInconsistencyCount >= MAX_INCONSISTENCY_COUNT_EXPORT)
			{
				printf("The export directory seems to be inconsistent or corrupted.\n");
				goto CleanUp;
			}
		}
	}

	nInconsistencyCount = 0;

	// functions exported by ordinal
	for (i = 0; i < nrOfFunctions; i++)
	{
		if (lpFlagArray[i] != 0)
		{
			// function exported by name (already printed)
			continue;
		}

		fRva = 0;

		__try
		{
			fRva = functionAddresses[i];
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			nInconsistencyCount += 1;
			if (nInconsistencyCount >= MAX_INCONSISTENCY_COUNT_EXPORT)
			{
				printf("The export directory seems to be inconsistent or corrupted.\n");
				goto CleanUp;
			}
		}

		if (fRva == 0)
		{
			continue;
		}

		printf("%11u %-50s 0x%08x 0x%08x\n", i, "[exported by ordinal]", fRva, FaFromRva(pPeFile, fRva));
	}

CleanUp:
	if (lpFlagArray != NULL)
	{
		HeapFree(GetProcessHeap(), 0, lpFlagArray);
		lpFlagArray = NULL;
	}

	return ERROR_SUCCESS;
}

static BOOL
ImportDescriptorIsNull(
	_In_	PIMAGE_IMPORT_DESCRIPTOR	pImportDescriptor
)
{
	if (NULL == pImportDescriptor)
	{
		fprintf(stderr, "[ERR]. ImportDescriptorIsNull: invalid parameter.\n");
		return FALSE;
	}

	__try
	{
		if (pImportDescriptor->OriginalFirstThunk == 0 &&
			pImportDescriptor->TimeDateStamp == 0 &&
			pImportDescriptor->ForwarderChain == 0 &&
			pImportDescriptor->Name == 0 &&
			pImportDescriptor->FirstThunk == 0)
		{
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf("ImportDescriptorIsNull: invalid import descriptor - exception during memory access.\n");
		return TRUE;
	}

	return FALSE;
}

DWORD
PrintImportInfos(
	_In_	PPE_FILE	pPeFile
)
{
	PIMAGE_IMPORT_DESCRIPTOR	lpImportDescriptor;
	PIMAGE_THUNK_DATA			lpThunk;
	PIMAGE_IMPORT_BY_NAME		pImageImportByName;
	LPSTR						dllName;
	LPSTR						functionName;
	DWORD						functionOrdinal;
	DWORD						nInconsistencyCount;

	if (NULL == pPeFile)
	{
		fprintf(stderr, "[ERR]. PrintImportInfos: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	if (pPeFile->importDescriptorsSize == 0)
	{
		printf("The PE file has no import directory (size = 0).\n");
		return ERROR_SUCCESS;
	}

	if (pPeFile->lpImportDescriptors == NULL)
	{
		printf("Null import directory file offset due to invalid or null RVA (size = %lu)\n", pPeFile->importDescriptorsSize);
		return ERROR_INVALID_POINTER;
	}

	if (((PBYTE)pPeFile->lpImportDescriptors > pPeFile->pData + pPeFile->bcFileSize) || ((PBYTE)pPeFile->lpImportDescriptors < pPeFile->pData))
	{
		printf("PrintImportInfos: pointer to import descriptors is invalid.\n");
		return ERROR_INVALID_POINTER;
	}
	
	lpImportDescriptor = NULL;
	lpThunk = NULL;
	pImageImportByName = NULL;
	dllName = NULL;
	functionName = NULL;
	functionOrdinal = 0;
	nInconsistencyCount = 0;

	for (lpImportDescriptor = pPeFile->lpImportDescriptors; !ImportDescriptorIsNull(lpImportDescriptor); lpImportDescriptor++)
	{
		dllName = NULL;
		__try
		{
			dllName = (LPSTR)OffsetFromRva(pPeFile, lpImportDescriptor->Name);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("Exception while trying to access dll name.\n");
		}

		if (dllName)
		{
			printf("imported DLL module: %s\n", dllName);
		}
		else
		{
			printf("imported DLL module: [unknown name] due to bad RVA\n");
		}

		lpThunk = NULL;
		__try
		{
			if (lpImportDescriptor->OriginalFirstThunk != 0)
			{
				lpThunk = (PIMAGE_THUNK_DATA)OffsetFromRva(pPeFile, lpImportDescriptor->OriginalFirstThunk);
			}
			else if (lpImportDescriptor->FirstThunk != 0)
			{
				lpThunk = (PIMAGE_THUNK_DATA)OffsetFromRva(pPeFile, lpImportDescriptor->FirstThunk);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("Exception while trying to access (Original)FirstThunk\n");
		}
		
		if (NULL == lpThunk)
		{
			nInconsistencyCount += 1;
			if (nInconsistencyCount >= MAX_INCONSISTENCY_COUNT_IMPORT)
			{
				printf("The import directory seems to be inconsistent or corrupted.\n");
				goto CleanUp;
			}
			printf("\tBoth OriginalFirstThunk and FirstThunk RVAs are invalid.\n");
			continue;
		}

		__try
		{
			for (; lpThunk->u1.AddressOfData; lpThunk++)
			{
				if (lpThunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG32)
				{
					functionOrdinal = 0;
					__try
					{
						functionOrdinal = lpThunk->u1.Ordinal & (IMAGE_ORDINAL_FLAG32 - 1);
						printf("\t(function imported by ordinal) ordinal number: %lu\n", functionOrdinal);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						printf("\t(function imported by ordinal) ordinal number: [cannot access]\n");
					}
				}
				else
				{
					functionName = NULL;
					__try
					{
						functionName = (LPSTR)((PIMAGE_IMPORT_BY_NAME)OffsetFromRva(pPeFile, lpThunk->u1.AddressOfData))->Name;
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						// do nothing
					}

					if (functionName)
					{
						printf("\t%s\n", functionName);
					}
					else
					{
						printf("\t[unknown function name] due to bad RVA\n");
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("Exception while looping a thunk.\n");
		}
	}

CleanUp:
	return ERROR_SUCCESS;
}