#include "FileMap.h"
#include <stdio.h>

DWORD
FileMapPreinit(
	_Out_	PFILE_MAP	pFileMap
) {
	if (NULL == pFileMap)
	{
		fprintf(stderr, "[ERR]. FileMapPreinit: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	pFileMap->hFile = INVALID_HANDLE_VALUE;
	pFileMap->hMapping = NULL;
	pFileMap->pData = NULL;
	pFileMap->bcFileSizeHigh = 0;
	pFileMap->bcFileSizeLow = 0;

	return ERROR_SUCCESS;
}

DWORD
FileMapInit(
	_Out_	PFILE_MAP	pFileMap,
	_In_	PCHAR		szFileName,
	_In_	BOOL		bWriteAccess
) {
	DWORD	errorCode;
	DWORD	fileAccess;
	DWORD	flProtect;
	DWORD	mappingAccess;

	if (NULL == pFileMap || NULL == szFileName)
	{
		fprintf(stderr, "[ERR]. FileMapInit: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	errorCode = ERROR_SUCCESS;
	if (FALSE == bWriteAccess)
	{
		fileAccess = GENERIC_READ;
		flProtect = PAGE_READONLY;
		mappingAccess = FILE_MAP_READ;
	}
	else
	{
		fileAccess = GENERIC_READ | GENERIC_WRITE;
		flProtect = PAGE_READWRITE;
		mappingAccess = FILE_MAP_ALL_ACCESS;
	}

	pFileMap->hFile = CreateFileA(
		szFileName,		//_In_     LPCTSTR               lpFileName,
		fileAccess,		//_In_     DWORD                 dwDesiredAccess,
		0,				//_In_     DWORD                 dwShareMode,
		NULL,			//_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		OPEN_EXISTING,	//_In_     DWORD                 dwCreationDisposition,
		0,				//_In_     DWORD                 dwFlagsAndAttributes,
		NULL			//_In_opt_ HANDLE                hTemplateFile
	);
	if (INVALID_HANDLE_VALUE == pFileMap->hFile)
	{
		errorCode = GetLastError();
		goto CleanUp;
	}

	pFileMap->bcFileSizeLow = GetFileSize(
		pFileMap->hFile,			//_In_      HANDLE  hFile,
		&pFileMap->bcFileSizeHigh	//_Out_opt_ LPDWORD lpFileSizeHigh
	);
	if (pFileMap->bcFileSizeLow == INVALID_FILE_SIZE && GetLastError() != NO_ERROR)
	{
		errorCode = GetLastError();
		fprintf(stderr, "[ERR]. FileMapInit: GetFileSize() failed. GLE = 0x%x.\n", errorCode);
		goto CleanUp;
	}

	if (pFileMap->bcFileSizeLow == 0 && pFileMap->bcFileSizeHigh == 0)
	{
		errorCode = INVALID_FILE_SIZE;
		fprintf(stderr, "[ERR]. FileMapInit: '%s' is a 0-byte size file.\n", szFileName);
		goto CleanUp;
	}

	pFileMap->hMapping = CreateFileMappingA(
		pFileMap->hFile,	//_In_     HANDLE                hFile,
		NULL,				//_In_opt_ LPSECURITY_ATTRIBUTES lpAttributes,
		flProtect,			//_In_     DWORD                 flProtect,
		0,					//_In_     DWORD                 dwMaximumSizeHigh,
		0,					//_In_     DWORD                 dwMaximumSizeLow,
		NULL				//_In_opt_ LPCTSTR               lpName
	);
	if (NULL == pFileMap->hMapping)
	{
		errorCode = GetLastError();
		fprintf(stderr, "[ERR]. FileMapInit: CreateFileMappingA() failed. GLE = 0x%x.\n", errorCode);
		goto CleanUp;
	}

	pFileMap->pData = MapViewOfFile(
		pFileMap->hMapping,	//_In_ HANDLE hFileMappingObject,
		mappingAccess,		//_In_ DWORD  dwDesiredAccess,
		0,					//_In_ DWORD  dwFileOffsetHigh,
		0,					//_In_ DWORD  dwFileOffsetLow,
		0					//_In_ SIZE_T dwNumberOfBytesToMap
	);
	if (NULL == pFileMap->pData)
	{
		errorCode = GetLastError();
		fprintf(stderr, "[ERR]. FileMapInit: MapViewOfFile() failed. GLE = 0x%x.\n", errorCode);
		goto CleanUp;
	}

CleanUp:
	if (errorCode != ERROR_SUCCESS)
	{
		FileMapDestroy(pFileMap);
	}
	return errorCode;
}

VOID
FileMapDestroy(
	_Inout_	PFILE_MAP	pFileMap
) {
	if (NULL == pFileMap)
	{
		fprintf(stderr, "[ERR]. FileMapDestroy: invalid parameter.\n");
		return;
	}

	if (NULL != pFileMap->pData)
	{
		UnmapViewOfFile(pFileMap->pData);
		pFileMap->pData = NULL;
	}

	if (NULL != pFileMap->hMapping)
	{
		CloseHandle(pFileMap->hMapping);
		pFileMap->hMapping = NULL;
	}

	if (INVALID_HANDLE_VALUE != pFileMap->hFile)
	{
		CloseHandle(pFileMap->hFile);
		pFileMap->hFile = INVALID_HANDLE_VALUE;
	}

	pFileMap->bcFileSizeLow = 0;
	pFileMap->bcFileSizeHigh = 0;
}