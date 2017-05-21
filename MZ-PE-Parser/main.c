#include "FileMap.h"
#include "ParsePeFile.h"
#include <stdio.h>

VOID
PrintUsage(CHAR *argv0)
{
	if (NULL == argv0)
	{
		return;
	}

	printf("Usage: %s <peFile> [<peFile1> <peFile2> ...]\n", argv0);
	printf("	<peFile>	- PE file to parse.\n");
}

INT
main(
	INT		argc,
	CHAR	**argv
)
{
	INT		i;

	if (argc < 2)
	{
		PrintUsage(argv[0]);
		return ERROR_INVALID_PARAMETER;
	}

	printf("PE Parser v1.0\n\n");

	for (i = 1; i < argc; i++)
	{
		__try
		{
			printf("Parsing file #%d out of %d: %s ...\n.\n.\n.\n", i, argc - 1, argv[i]);
			ParsePeFie(argv[i]);
			printf(".\n.\n.\nDone...\n\n");
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("\nException while parsing %s.\n\n", argv[i]);
		}
	}

	return ERROR_SUCCESS;
}