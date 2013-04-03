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

void* GetBaseAddressFromPEB()
{
	__asm
	{
		mov eax, FS:[0x30];
		add eax, 8;
		mov eax, [eax];
	}
}

int main(int argc, char** argv)
{
	
	IMAGE_DOS_HEADER *image_dos_header;
	IMAGE_NT_HEADERS *image_nt_header;
	IMAGE_SECTION_HEADER *image_section_header;
	char *textsection, *textsectionend;
	

	char* pebase = NULL;
	char *buf;
	unsigned int i = 0, sections = 0, offset = 0;
	unsigned int OEPoffset = 0;
	unsigned int textsectionvasize,vsize=0,voffset=0;

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

	////Text Section Pre-Test
	//textsection = (char*)((BYTE*)image_dos_header + image_section_header->PointerToRawData);
	//textsectionend = (char*)((BYTE*)image_dos_header + image_section_header->PointerToRawData 
	//	+ image_section_header->SizeOfRawData);
	//textsectionvasize = image_section_header->Misc.VirtualSize;
	////Finish Text Section Pre-Tests.


	sections = image_nt_header ->FileHeader.NumberOfSections;

	for(; i < sections; i++, offset += 40)
	{
		image_section_header = (IMAGE_SECTION_HEADER*)((BYTE*)image_dos_header 
			+ image_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + offset);

		vsize = image_section_header->Misc.VirtualSize;

			if(offset <= OEPoffset && OEPoffset < (offset+vsize))
			{
				break; //Found Original Entry Point (OEP)
			}
	}
	
	printf("Code Section: %s\n", image_section_header->Name);
	

	free(buf);

	fflush(stdin);
	getchar();
}
