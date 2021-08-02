#include <stdio.h>
#include <Windows.h>

void out(const char* szName, DWORD dwValue)
{
	printf("%s\t 0x%08X\n", szName, dwValue);
}

int main(void)
{
	// 파싱할 PE파일 경로 저장
	WCHAR szFilePath[100];
	ZeroMemory(szFilePath, 100);
	GetModuleFileNameW(NULL, szFilePath, sizeof(szFilePath));
	
	// 파일 핸들 발급 및 읽기
	HANDLE hFile = CreateFileW(
		szFilePath,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	BYTE* lpFileBuffer = (BYTE*)malloc(dwFileSize);
	ReadFile(hFile, lpFileBuffer, dwFileSize, &dwFileSize, NULL);
	
	// 주요 PE헤더 주소 파싱
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)lpFileBuffer;
	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((BYTE*)pDos + pDos->e_lfanew);
	IMAGE_FILE_HEADER* pFileHeader = (IMAGE_FILE_HEADER*)((BYTE*)pNt + 0x4);
	IMAGE_OPTIONAL_HEADER* pOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)pNt + 0x18);
	IMAGE_DATA_DIRECTORY* pDataDirectory[16];
	IMAGE_SECTION_HEADER* pSectionHeader[16];
	for (int i = 0; i < 16; i++)
	{
		pDataDirectory[i] = (IMAGE_DATA_DIRECTORY*)((BYTE*)pNt + 0x18 + 0x60 + i * 8);
	}
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		pSectionHeader[i] = (IMAGE_SECTION_HEADER*)((BYTE*)pOptionalHeader + 0x60 + 128 + i * sizeof(IMAGE_SECTION_HEADER));
	}

	
	// DOS 헤더 출력
	printf("========== DOS HEADER ==========\n");
	out("e_magic\t", pDos->e_magic);
	out("e_lfanew", pDos->e_lfanew);
	printf("\n");

	// NT 헤더 출력
	printf("========== NT HEADERS ==========\n");
	out("Signature\t\t", pNt->Signature);
	printf("\n");

	out("Machine\t\t\t", pNt->FileHeader.Machine);
	out("NumberOfSections\t", pNt->FileHeader.NumberOfSections);
	out("TimeDateStamp\t\t", pNt->FileHeader.TimeDateStamp);
	out("PointerToSymbolTable\t", pNt->FileHeader.PointerToSymbolTable);
	out("NumberOfSymbols\t\t", pNt->FileHeader.NumberOfSymbols);
	out("SizeOfOptionalHeader\t", pNt->FileHeader.SizeOfOptionalHeader);
	out("Characteristics\t\t", pNt->FileHeader.Characteristics);
	printf("\n");

	out("Magic\t\t\t", pNt->OptionalHeader.Magic);
	out("MajorLinkerVersion\t", pNt->OptionalHeader.MajorLinkerVersion);
	out("MinorLinkerVersion\t", pNt->OptionalHeader.MinorLinkerVersion);
	out("SizeOfCode\t\t", pNt->OptionalHeader.SizeOfCode);
	out("SizeOfInitializedData\t", pNt->OptionalHeader.SizeOfInitializedData);
	out("SizeOfUnInitializedData\t", pNt->OptionalHeader.SizeOfUninitializedData);
	out("AddressOfEntryPoint\t", pNt->OptionalHeader.AddressOfEntryPoint);
	out("BaseOfCode\t\t", pNt->OptionalHeader.BaseOfCode);
	out("BaseOfData\t\t", pNt->OptionalHeader.BaseOfData);
	out("ImageBase\t\t", pNt->OptionalHeader.ImageBase);
	out("SectionAlignment\t", pNt->OptionalHeader.SectionAlignment);
	out("FileAlignment\t\t", pNt->OptionalHeader.FileAlignment);
	out("MajorOperationSystemVersion", pNt->OptionalHeader.MajorOperatingSystemVersion);
	out("MinorOperationSystemVersion", pNt->OptionalHeader.MinorOperatingSystemVersion);
	out("MajorImageVersion\t", pNt->OptionalHeader.MajorImageVersion);
	out("MinorImageVersion\t", pNt->OptionalHeader.MinorImageVersion);
	out("Win32VersionValue\t", pNt->OptionalHeader.Win32VersionValue);
	out("SizeOfImage\t\t", pNt->OptionalHeader.SizeOfImage);
	out("SizeOfHeaders\t\t", pNt->OptionalHeader.SizeOfHeaders);
	out("CheckSum\t\t", pNt->OptionalHeader.CheckSum);
	out("SubSystem\t\t", pNt->OptionalHeader.Subsystem);
	out("DllCharacteristics\t", pNt->OptionalHeader.DllCharacteristics);
	out("SizeOfStackReserve\t", pNt->OptionalHeader.SizeOfStackReserve);
	out("SizeOfStackCommit\t", pNt->OptionalHeader.SizeOfStackCommit);
	out("SizeOfHeapReserve\t", pNt->OptionalHeader.SizeOfHeapReserve);
	out("SizeOfHeapCommit\t", pNt->OptionalHeader.SizeOfHeapCommit);
	out("LoaderFlags\t\t", pNt->OptionalHeader.LoaderFlags);
	out("NumberOfRvaAndSizes\t", pNt->OptionalHeader.NumberOfRvaAndSizes);
	printf("\n");


	// 섹션 이름 및 섹션 데이터 출력
	printf("========== SECTION TABLES ==========\n");
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		BYTE* pSection = (BYTE*)pDos + pSectionHeader[i]->PointerToRawData;
		
		printf("%s\n", pSectionHeader[i]->Name);
		for (int j = 0; j < pSectionHeader[i]->SizeOfRawData; j += 0x20)
		{
			for (int k = 0; k < 0x20; k++)
			{
				printf("%02X ", pSection[j + k]);
			}
			printf("\n");
		}
		printf("\n");
	}
	
	return 0;
}
