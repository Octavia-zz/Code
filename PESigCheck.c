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

	if(!strncmp(pebase,"MZ",2))
	{
		return 1;
	}

	else 
	{
		return 0;
	}

}
void PrintSignature(IMAGE_DOS_HEADER *image_dos_header)
{
	printf("%.2s", image_dos_header);
}

int main(int argc, char** argv)
{
	
	IMAGE_DOS_HEADER *image_dos_header;
	IMAGE_NT_HEADERS *image_nt_header;
	IMAGE_SECTION_HEADER *image_section_header;
	char *textsection, *textsectionend;
	int textsectionvasize;

	char* pebase = NULL;
	char *buf;
	unsigned int offset = 40;
	unsigned int i = 0, sections = 0;

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
	PrintSignature(image_dos_header);
	printf("\n");
	
	if(CheckSignature(pebase))
	{
		printf("File's Signature is OK.");
	}
	else
	{
		printf("File's Signature is Invalid.");
	}
	image_nt_header = (IMAGE_NT_HEADERS*)((BYTE*)image_dos_header + image_dos_header->e_lfanew);
	printf("\n\nPE Header Signature: %.2s\n\n", image_nt_header);

	sections = image_nt_header ->FileHeader.NumberOfSections;

	image_section_header = (IMAGE_SECTION_HEADER*)((BYTE*)image_dos_header 
		+ image_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	textsection = (char*)((BYTE*)image_dos_header + image_section_header->PointerToRawData);
	textsectionend = (char*)((BYTE*)image_dos_header + image_section_header->PointerToRawData 
		+ image_section_header->SizeOfRawData);
	
	textsectionvasize = 
	printf("Text Section VA Size: %d", textsectionvasize);
	/*for(; i < sections; i++, offset += 40)
	{
		printf("%s\t", image_section_header ->Name);

		image_section_header = (IMAGE_SECTION_HEADER*)((BYTE*)image_dos_header 
			+ image_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + offset);
	}*/

	free(buf);

	fflush(stdin);
	getchar();
}
