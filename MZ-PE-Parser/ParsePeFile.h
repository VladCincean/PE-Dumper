#ifndef PARSE_PE_FILE_H
#define PARSE_PE_FILE_H
#include <Windows.h>

/**
 *	Dumps the information about a Portable Executable (PE file):
 *		- basic info from FileHeader
 *		- basic info from OptionalHeader
 *		- basic info from section headers
 *		- list of exported functions, if any
 *		- list of imported functions, per module
 *	@param		fileName: string denoting the path to the PE file
 *	@pre		fileName must not be null
 *	@returns	ERROR_SUCCESS, if success
 *	@returns	other, if failure
 */
DWORD
ParsePeFie(
	_In_	LPSTR	fileName
);

#endif