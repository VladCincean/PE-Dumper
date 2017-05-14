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
	if (ntOffset > pPeFile->bcFileSizeLow || ntOffset < 0)
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

DWORD
PeFileInit(
	_Out_		PPE_FILE	pPeFile,
	_In_		PBYTE		pData,
	_In_		DWORD		bcFileSizeLow,
	_In_opt_	DWORD		bcFileSizeHigh
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
	pPeFile->bcFileSizeLow = bcFileSizeLow;
	pPeFile->bcFileSizeHigh = bcFileSizeHigh;

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

	errorCode = LoadSectionHeaders(pPeFile);
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

	for (i = 0; i < pPeFile->pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (rvaAddress >= pPeFile->pSectionHeaders[i].VirtualAddress &&
			rvaAddress < pPeFile->pSectionHeaders[i].VirtualAddress + pPeFile->pSectionHeaders[i].Misc.VirtualSize
			)
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
	printf("Machine id: %d\n", machine);
	printf("Machine: ");
	switch (machine)
	{
	case IMAGE_FILE_MACHINE_UNKNOWN:
		printf("any");
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
	printf("Number of sections: %d\n", nrOfSections);

	// Characteristics
	printf("Characteristics: 0x04%x:\n", characteristics);
	if (characteristics & IMAGE_FILE_RELOCS_STRIPPED)
	{
		printf("- There is no base relocation information in the file. It must be loaded at its preferred base address. ");
		printf("If the base address is not available, the loader reports an error. ");
		printf("The default behavior of the linker is to strip base relocations from executable (EXE) files.\n");
	}
	if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
	{
		printf("- The file is executable (i.e. it is not an object file or library).\n");
	}
	else
	{
		printf("- [If it is an image] a linked error occured.\n");
	}
	if (characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
	{
		printf("Warning: deprecated flag is set: IMAGE_FILE_LINE_NUMS_STRIPPED\n");
		printf("- COFF line numbers have been removed\n");
	}
	if (characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
	{
		printf("Warning: deprecated flag is set: IMAGE_FILE_LOCAL_SYMS_STRIPPED\n");
		printf("- COFF symbol table entries for local symbols have been removed (there is no information about local symbols in the file)\n");
	}
	if (characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM)
	{
		printf("Warning: IMAGE_FILE_AGGRESIVE_WS_TRIM flag is deprecated for Windows 2000 and later and must be zero, but it is set.\n");
		printf("- Aggressively trim working set. i.e. the operating system is supposed to trim the working set of the running proces\n");
		printf("(the amount of RAM the process uses) aggressivly by paging it out\n");
	}
	if (characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
	{
		printf("- Application can handle > 2 GB addresses.\n");
	}
	if (characteristics & IMAGE_FILE_BYTES_REVERSED_LO)
	{
		printf("Warning: deprecated flag IMAGE_FILE_BYTES_REVERSED_LO set.\n");
		printf("- Little endian.\n");
	}
	if (characteristics & IMAGE_FILE_32BIT_MACHINE)
	{
		printf("- Machine is based on a 32-bit-word architecture.\n");
	}
	if (characteristics & IMAGE_FILE_DEBUG_STRIPPED)
	{
		printf("- Debugging information is removed from the image file.\n");
	}
	if (characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
	{
		printf("- The application may not run from a removable medium such as a floppy or a CD - ROM.\n");
		printf("The operating system is advised to copy the file to the swapfile and execute it from there.\n");
	}
	if (characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP)
	{
		printf("- The application may not run from the network.\n");
		printf("The operating system is advised to copy the file to the swapfile and execute it from there.\n");
	}
	if (characteristics & IMAGE_FILE_SYSTEM)
	{
		printf("- The image file is a system file (e.g. driver, etc.), not a user program.\n");
	}
	if (characteristics & IMAGE_FILE_DLL)
	{
		printf("- The image file is a dynamic-link library (DLL).\n");
	}
	if (characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
	{
		printf("- The file should be run only on a uniprocessor machine.\n");
	}
	if (characteristics & IMAGE_FILE_BYTES_REVERSED_HI)
	{
		printf("Warning: deprecated flag IMAGE_FILE_BYTES_REVERSED_HI set.\n");
		printf("- Big endian.\n");
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
	printf("ImageBase:\n");
	printf("\tRVA:\t0x%08x\n\tFA:\t0x%08x\n", imageBase, FaFromRva(pPeFile, imageBase));

	// SectionAlignment
	printf("SectionAlignment: %d bytes\n", sectionAlignment);

	// FileAlignment
	printf("FileAlignment: %d bytes\n", fileAlignment);

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
		printf("the Windows GUI subsystem");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		printf("the Windows character subsystem");
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		printf("the Posix character subsystem");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		printf("Windows CE");
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		printf("an Extensible Firmware Interface (EFI) application");
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		printf("an EFI driver with boot services");
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		printf("an EFI driver with run-time services");
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		printf("an EFI ROM image");
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		printf("XBOX");
		break;
	default:
		printf("[unknown]");
		break;
	}
	printf("\n");

	// NumberOfRvaAndSizes
	printf("NumberOfRvaAndSizes: %d\n", numberOfRvaAndSizes);

	return ERROR_SUCCESS;
}