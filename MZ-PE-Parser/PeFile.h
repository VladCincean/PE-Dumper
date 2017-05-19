#ifndef PE_FILE_H
#define PE_FILE_H
#include <Windows.h>
#include "FileMap.h"

#define ERROR_INVALID_MZ_MAGIC		0x4001
#define ERROR_INVALID_PE_MAGIC		0x4002
#define ERROR_INVALID_LFANEW		0x4003
#define ERROR_NULL_FILE_OFFSET		0x4004
#define ERROR_INVALID_STRUCT_ACCESS	0x4005

#define ERROR_IS_32BIT_MACHINE		0x4006
#define ERROR_IS_64BIT_MACHINE		0x4007

typedef struct _PE_FILE
{
	PBYTE						pData;
	DWORD						bcFileSizeHigh;
	DWORD						bcFileSizeLow;
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	PIMAGE_SECTION_HEADER		pSectionHeaders;
	PIMAGE_EXPORT_DIRECTORY		pExportDirectory;
	DWORD						exportDirectorySize;
	PIMAGE_IMPORT_DESCRIPTOR	lpImportDescriptors;
	DWORD						importDescriptorsSize;
} PE_FILE, *PPE_FILE;

/* ===================== init =====================*/

DWORD
PeFileInit(
	_Out_		PPE_FILE	pPeFile,
	_In_		PBYTE		pData,
	_In_		DWORD		bcFileSizeLow,
	_In_opt_	DWORD		bcFileSizeHigh
);

/* ===================== addr ===================== */

DWORD
FaFromRva(
	_In_	PPE_FILE	pPeFile,
	_In_	DWORD		rvaAddress
);

PBYTE
OffsetFromRva(
	_In_	PPE_FILE	pPeFile,
	_In_	DWORD		rvaAddress
);

/* ===================== info ===================== */

DWORD
PrintFileHeaderInfos(
	_In_	PPE_FILE	pPeFile
);

DWORD
PrintOptionalHeaderInfos(
	_In_	PPE_FILE	pPeFile
);

DWORD
PrintSectionHeadersInfos(
	_In_	PPE_FILE	pPeFile
);

DWORD
PrintExportInfos(
	_In_	PPE_FILE	pPeFile
);

DWORD
PrintImportInfos(
	_In_	PPE_FILE	pPeFile
);

#endif