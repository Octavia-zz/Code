/* 
Created by Peleg
*/

#include <Windows.h>
#include <stdio.h>
#include <string.h>

IMAGE_DOS_HEADER* MapPEFile(char* filename)
{
  	HANDLE pe, pemap;
	IMAGE_DOS_HEADER* image_dos_header;

	pe = CreateFile(filename,GENERIC_READ | GENERIC_WRITE,
		0, NULL , OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL ,NULL);

	pemap = CreateFileMapping(pe, NULL, PAGE_READWRITE, 0, 0, NULL);

	image_dos_header = (IMAGE_DOS_HEADER*)MapViewOfFile(pemap,FILE_MAP_ALL_ACCESS,0,0,0);

	CloseHandle(pe);
	CloseHandle(pemap);

	return image_dos_header;
}
int CheckSignature(char* pebase)
{
	int i=0;
	char signature[2];

	for(i=0; i<2; i++)
	{
		signature[i] = *pebase;
		pebase++;
	}

	if(!strcmp(signature,"MZ"))
	{
		return 1;
	}

	else 
	{
		return 0;
	}

}
void PrintSignature(char* pebase)
{
	int i=0;
	for(i=0; i<2; i++)
	{
		printf("%c", pebase[i]);
	}
}

int main(int argc, char** argv)
{
	
	IMAGE_DOS_HEADER* image_dos_header;
	char* pebase = NULL;
	char *buf;

	if(argc < 2)
	{
		printf("Usage: %s %s", argv[0], argv[1]);
		return 0;
	}

	buf = _strdup(argv[1]);
	image_dos_header = MapPEFile(buf);
	pebase = (char*)image_dos_header;

	printf(":: PE Signature Checker ::\n");
	printf("by Peleg\n\n");


	printf("Base Address: %p\n", image_dos_header);
	printf("Signature: ");
	PrintSignature(pebase);
	printf("\n");
	
	if(CheckSignature(pebase))
	{
		printf("File's Signature is OK.");
	}
	else
	{
		printf("File's Signature is Invalid.");
	}
	
	free(buf);

	fflush(stdin);
	getchar();
}
