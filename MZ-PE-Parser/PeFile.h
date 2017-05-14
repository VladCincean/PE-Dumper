#ifndef PE_FILE_H
#define PE_FILE_H
#include <Windows.h>
#include "FileMap.h"

#define ERROR_INVALID_MZ_MAGIC	0x4001
#define ERROR_INVALID_PE_MAGIC	0x4002
#define ERROR_INVALID_LFANEW	0x4003

typedef struct _PE_FILE
{
	PBYTE					pData;
	DWORD					bcFileSizeHigh;
	DWORD					bcFileSizeLow;
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNtHeaders;
	PIMAGE_SECTION_HEADER	pSectionHeaders;
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

#endif