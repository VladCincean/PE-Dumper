#ifndef FILE_MAP_H
#define FILE_MAP_H
#include <Windows.h>

typedef struct _FILE_MAP
{
	HANDLE	hFile;
	HANDLE	hMapping;
	BYTE	*pData;
	DWORD	bcFileSizeHigh;
	DWORD	bcFileSizeLow;
} FILE_MAP, *PFILE_MAP;

/**
 *	Preinits a FILE_MAP structure.
 *	@param		pFileMap
 *	@pre		pFileMap must not be null
 *	@returns	ERROR_SUCCESS, if success
 *	@returns	ERROR_INVALID_PARAMETER, if invalid parameter
 */
DWORD
FileMapPreinit(
	_Out_	PFILE_MAP	pFileMap
);

/**
 *	Inits a FILE_MAP structure.
 *	@param		pFileMap
 *	@param		szFileName: path to the file
 *	@param		bWriteAccess: FALSE, if write access is not required; other value, otherwise
 *	@pre		pFileMap, szFileName must not be null
 *	@returns	ERROR_SUCCESS, if success
 *	@returns	other value, if failure
 */
DWORD
FileMapInit(
	_Out_	PFILE_MAP	pFileMap,
	_In_	PCHAR		szFileName,
	_In_	BOOL		bWriteAccess
);

/**
 *	Deinits a FILE_MAP structure.
 *	@param	pFileMap
 *	@pre	pFileMap must not be null
 */
VOID
FileMapDestroy(
	_Inout_	PFILE_MAP	pFileMap
);

#endif