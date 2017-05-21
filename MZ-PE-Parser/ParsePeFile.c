#include "ParsePeFile.h"
#include "PeFile.h"
#include <stdio.h>

DWORD
ParsePeFie(
	_In_	LPSTR	fileName
)
{
	DWORD		error;
	BOOL		is64Bit;
	FILE_MAP	fileMap;
	BOOL		bInitialized;
	PE_FILE		peFile;

	if (NULL == fileName)
	{
		fprintf(stderr, "[ERR]. ParsePeFile: invalid parameter.\n");
		return ERROR_INVALID_PARAMETER;
	}

	error = ERROR_SUCCESS;
	is64Bit = FALSE;
	bInitialized = FALSE;

	error = FileMapPreinit(&fileMap);
	if (ERROR_SUCCESS != error)
	{
		fprintf(stderr, "[ERR]. ParsePeFile: FileMapPreinit() failed: 0x%x.\n", error);
		goto CleanUp;
	}

	error = FileMapInit(&fileMap, fileName, FALSE);
	if (ERROR_SUCCESS != error)
	{
		fprintf(stderr, "[ERR]. ParsePeFile: FileMapInit() failed: 0x%x.\n", error);
		goto CleanUp;
	}

	bInitialized = TRUE;

	error = PeFileInit(
		&peFile,
		fileMap.pData,
		fileMap.bcFileSizeLow
	);
	if (error != 0)
	{
		fprintf(stderr, "[ERR]. ParsePeFile: PeFileInit() failed: 0x%x.\n", error);
		goto CleanUp;
	}

	is64Bit = peFile.optionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

	__try
	{
		printf("---- File Header infos ----\n");
		PrintFileHeaderInfos(&peFile);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf("\nParsePeFile: Exception while printing file header infos.\n");
	}
	printf("\n");

	if (is64Bit)
	{
		printf("PE Parser v1.0: I currently cannot show more info for 'non-x86 32-bit PE files'.\n");
		goto CleanUp;
	}

	__try
	{
		printf("---- Optional Header infos ----\n");
		PrintOptionalHeaderInfos(&peFile);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf("\nParsePeFile: Exception while printing optional header infos.\n");
	}
	printf("\n");

	__try
	{
		printf("---- Section Headers infos ----\n");
		PrintSectionHeadersInfos(&peFile);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf("\nParsePeFile: Exception while printing section headers infos.\n");
	}
	printf("\n");

	__try
	{
		printf("---- Exported functions ----\n");
		PrintExportInfos(&peFile);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf("\nParsePeFile: Exception while printing exported functions.\n");
	}
	printf("\n");

	__try
	{
		printf("---- Imported functions ----\n");
		PrintImportInfos(&peFile);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf("\nParsePeFile: Exception while printing imported functions.\n");
	}
	printf("\n");

CleanUp:
	if (bInitialized)
	{
		FileMapDestroy(&fileMap);
	}
	return error;
}