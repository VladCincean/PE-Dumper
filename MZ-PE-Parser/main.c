#include "FileMap.h"
#include "PeFile.h"
#include <stdio.h>

VOID
PrintUsage(CHAR *argv0)
{
	if (NULL == argv0)
	{
		return;
	}

	printf("Usage: %s <peFile>\n", argv0);
	printf("	<peFile>	- PE file to parse.\n");
}

INT
main(
	INT		argc,
	CHAR	**argv
)
{
	DWORD		error;
	BOOL		is32Bit;
	FILE_MAP	fileMap;
	BOOL		bInitialized;
	PE_FILE		peFile;

	if (argc < 2)
	{
		PrintUsage(argv[0]);
		return ERROR_INVALID_PARAMETER;
	}

	error = ERROR_SUCCESS;
	is32Bit = FALSE;
	bInitialized = FALSE;

	error = FileMapPreinit(&fileMap);
	if (ERROR_SUCCESS != error)
	{
		fprintf(stderr, "[ERR]. FileMapPreinit failed: 0x%x.\n", error);
		goto CleanUp;
	}

	error = FileMapInit(&fileMap, argv[1], FALSE);
	if (ERROR_SUCCESS != error)
	{
		fprintf(stderr, "[ERR]. FileMapInit failed: 0x%x.\n", error);
		goto CleanUp;
	}

	bInitialized = TRUE;

	error = PeFileInit(
		&peFile,
		fileMap.pData,
		fileMap.bcFileSizeLow,
		fileMap.bcFileSizeHigh
	);
	if (error != 0)
	{
		fprintf(stderr, "[ERR]. PeFileInit failed: 0x%x.\n", error);
		goto CleanUp;
	}

	printf("---- File Header infos ----\n");
	error = PrintFileHeaderInfos(&peFile);
	printf("\n");
	if (error != ERROR_IS_32BIT_MACHINE && error != ERROR_IS_64BIT_MACHINE)
	{
		goto CleanUp;
	}
	if (error == ERROR_IS_32BIT_MACHINE)
	{
		is32Bit = TRUE;
	}
	else
	{
		goto CleanUp;
	}

	printf("---- Optional Header infos ----\n");
	error = PrintOptionalHeaderInfos(&peFile);
	printf("\n");
	if (error != ERROR_SUCCESS)
	{
		goto CleanUp;
	}

	printf("---- Section Headers infos ----\n");
	error = PrintSectionHeadersInfos(&peFile);
	printf("\n");
	if (error != ERROR_SUCCESS)
	{
		goto CleanUp;
	}

	printf("---- Exported functions ----\n");
	error = PrintExportInfos(&peFile);
	printf("\n");
	if (error != ERROR_SUCCESS)
	{
		goto CleanUp;
	}

	printf("---- Imported functions ----\n");
	error = PrintImportInfos(&peFile);
	printf("\n");
	if (error != ERROR_SUCCESS)
	{
		goto CleanUp;
	}

CleanUp:
	if (!is32Bit)
	{
		printf("PE Parser v1.0: I currently cannot show more info for 'non-x86 32-bit PE files'.\n");
	}
	if (bInitialized)
	{
		FileMapDestroy(&fileMap);
	}
	return error;
}