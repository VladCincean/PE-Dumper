#ifndef PE_FILE_H
#define PE_FILE_H
#include <Windows.h>
#include "FileMap.h"

#define ERROR_INVALID_MZ_MAGIC		0x4001
#define ERROR_INVALID_PE_MAGIC		0x4002
#define ERROR_INVALID_LFANEW		0x4003
#define ERROR_NULL_FILE_OFFSET		0x4004
#define ERROR_INVALID_STRUCT_ACCESS	0x4005
#define ERROR_INVALID_POINTER		0x4006

#define MAX_INCONSISTENCY_COUNT_SECTIONS	42
#define MAX_INCONSISTENCY_COUNT_EXPORT		42
#define MAX_INCONSISTENCY_COUNT_IMPORT		42

typedef struct _PE_FILE
{
	PBYTE						pData;
	DWORD						bcFileSize;
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	PIMAGE_SECTION_HEADER		pSectionHeaders;
	WORD						optionalHeaderMagic;
	PIMAGE_EXPORT_DIRECTORY		pExportDirectory;
	DWORD						exportDirectorySize;
	PIMAGE_IMPORT_DESCRIPTOR	lpImportDescriptors;
	DWORD						importDescriptorsSize;
} PE_FILE, *PPE_FILE;

/* ===================== init =====================*/

/**
 *	Inits a PE_FILE structure.
 *	@param		pPeFile (output)
 *	@param		pData: file mapping data
 *	@param		bcFileSize: file mapping size (low dword)
 *	@pre		pPeFile, pData must not be null
 *	@returns	ERROR_SUCCESS, if success
 *	@returns	other value, if failure
 */
DWORD
PeFileInit(
	_Out_		PPE_FILE	pPeFile,
	_In_		PBYTE		pData,
	_In_		DWORD		bcFileSize
);

/* ===================== addr ===================== */

/**
 *	Provides the file address (FA) from a relative virtual address (RVA)
 *	@param		pPeFile
 *	@param		rvaAddress
 *	@returns	the corresponding FA, if RVA is valid
 *	@returns	0, otherwise
 */
DWORD
FaFromRva(
	_In_	PPE_FILE	pPeFile,
	_In_	DWORD		rvaAddress
);

/**
 *	Provides the offset inside a file mapping of a given relative virtual address (RVA)
 *	@param		pPeFile
 *	@param		rvaAddress
 *	@returns	the corresponding offset, if RVA is valid
 *	@returns	NULL, otherwise
 */
PBYTE
OffsetFromRva(
	_In_	PPE_FILE	pPeFile,
	_In_	DWORD		rvaAddress
);

/* ===================== info ===================== */

/**
 *	Dumps the following FileHeader infos:
 *		- Machine number
 *		- Machine name (if any)
 *		- NumberOfSections
 *		- Characteristics (flags and details)
 *	@param		pPeFile
 *	@pre		pPeFile must not be null
 *	@returns	ERROR_SUCCESS, if success
 *	@returns	other, if failure
 */
DWORD
PrintFileHeaderInfos(
	_In_	PPE_FILE	pPeFile
);

/**
 *	Dumps the following OptionalHeader infos:
 *		- AddressOfEntryPoint (RVA and FA)
 *		- ImageBase
 *		- SectionAlignment (in bytes)
 *		- FileAlignment (in bytes)
 *		- Subsystem (code and name)
 *		- NumberOfRvaAndSizes
 *	@param		pPeFile
 *	@pre		pPeFile must not be null
 *	@returns	ERROR_SUCCESS, if success
 *	@returns	other, if failure
 */
DWORD
PrintOptionalHeaderInfos(
	_In_	PPE_FILE	pPeFile
);

/**
 *	Dumps the following infos for section headers (for each section):
 *		- Name
 *		- Address (RVA and FA)
 *		- Virtual Size
 *		- Raw Size
 *	@param		pPeFile
 *	@pre		pPeFile must not be null
 *	@returns	ERROR_SUCCESS, if success
 *	@returns	other, if failure
 */
DWORD
PrintSectionHeadersInfos(
	_In_	PPE_FILE	pPeFile
);

/**
 *	Dumps information about exported functions (if any):
 *		- Function Ordinal
 *		- Function Name (if any)
 *		- Function Address (RVA and FA)
 *	@param		pPeFile
 *	@pre		pPeFile must not be null
 *	@returns	ERROR_SUCCESS, if success
 *	@returns	other, if failure
 */
DWORD
PrintExportInfos(
	_In_	PPE_FILE	pPeFile
);

/**
 *	Dumps information about imported functions (for each module):
 *		- Function Name (if any), or
 *		- Function Ordinal (if function was imported by ordinal)
 *	@param		pPeFile
 *	@pre		pPeFile must not be null
 *	@returns	ERROR_SUCCESS, if success
 *	@returns	other, if failure
 */
DWORD
PrintImportInfos(
	_In_	PPE_FILE	pPeFile
);

#endif