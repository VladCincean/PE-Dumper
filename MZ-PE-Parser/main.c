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
	FILE_MAP	fileMap;
	BOOL		bInitialized;
	PE_FILE		peFile;

	if (argc < 2)
	{
		PrintUsage(argv[0]);
		return ERROR_INVALID_PARAMETER;
	}

	error = ERROR_SUCCESS;
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

	//printf("Image Base:\t0x%08x\n", peFile.pNtHeaders->OptionalHeader.ImageBase);
	//printf("Entry Point:\t0x%08x 0x%08x\n",
	//	peFile.pNtHeaders->OptionalHeader.AddressOfEntryPoint,
	//	FaFromRva(&peFile, peFile.pNtHeaders->OptionalHeader.AddressOfEntryPoint)
	//);

	printf("---- File Header infos ----\n");
	PrintFileHeaderInfos(&peFile);
	printf("\n");

	printf("---- Optional Header infos ----\n");
	PrintOptionalHeaderInfos(&peFile);
	printf("\n");

	printf("---- Section Headers infos ----\n");
	PrintSectionHeadersInfos(&peFile);
	printf("\n");

	printf("---- Exported functions ----\n");
	PrintExportInfos(&peFile);
	printf("\n");

	printf("---- Imported functions ----\n");
	PrintImportInfos(&peFile);
	printf("\n");

CleanUp:
	if (bInitialized)
	{
		FileMapDestroy(&fileMap);
	}
	return error;
}