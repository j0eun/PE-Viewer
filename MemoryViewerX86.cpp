#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("Usage: PE-Viewer.exe [PID]\n");
		return 1;
	}

	// ���μ��� ���� ���� �� ���� ȹ��
	DWORD pid = atoi(argv[1]);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32W me32;
	WCHAR szPath[0x100];
	DWORD dwLength = sizeof(szPath);
	HANDLE hModule = 0;

	ZeroMemory(&me32, sizeof(me32));
	ZeroMemory(szPath, sizeof(szPath));
	me32.dwSize = sizeof(me32);
	QueryFullProcessImageNameW(hProc, 0, szPath, &dwLength);
	Module32FirstW(hSnap, &me32);
	do
	{
		if (!_wcsicmp(me32.szExePath, szPath))
		{
			hModule = me32.modBaseAddr;
			break;
		}
	} while (Module32NextW(hSnap, &me32));

	DWORD SizeOfImage = 0;
	DWORD NtOffset = 0;		// e_lfanew
	ReadProcessMemory(hProc, (BYTE*)hModule + 0x3c, &NtOffset, 4, NULL);
	ReadProcessMemory(hProc, (BYTE*)hModule + NtOffset + 0x18 + 0x38, &SizeOfImage, 4, NULL);
	
	BYTE* pBuffer = (BYTE*)malloc(SizeOfImage);
	ReadProcessMemory(hProc, hModule, pBuffer, SizeOfImage, NULL);

	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBuffer;
	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((BYTE*)pDos + pDos->e_lfanew);
	DWORD dwSizeOfOptionalHeader = pNt->FileHeader.SizeOfOptionalHeader;
	IMAGE_SECTION_HEADER* pSectionHeaderBase = (IMAGE_SECTION_HEADER*)((BYTE*)pNt + 0x18 + dwSizeOfOptionalHeader);	// pNt + OptionalHeader ������ + OptionalHeader ũ��
	
	// hModule = Ÿ�� ���μ����� ���� �ּ�
	// pBuffer = Ÿ�� �̹����� �����ߴ� ���� ���μ����� ����

	// DOS ���
	printf("========== DOS HEADER ==========\n\n");
	printf("%08X:  0x%X \t (e_magic)\n", hModule, pDos->e_magic);
	printf("%08X:  0x%X \t (e_lfanew)\n", (BYTE*)hModule + 0x3c , pDos->e_lfanew);
	printf("\n");


	// NT ���
	printf("========== NT HEADERS ==========\n\n");
	printf("%08X:  0x%X \t (Signature)\n", hModule, pNt->Signature);
	printf("%08X:  0x%X \t\t (NumberOfSections)\n", (BYTE*)hModule + 0x4 + 0x2, pNt->FileHeader.NumberOfSections);
	printf("%08X:  0x%X \t (AddressOfEntryPoint)\n", (BYTE*)hModule + 0x18 + 0x10, pNt->OptionalHeader.AddressOfEntryPoint);
	printf("%08X:  0x%X \t (ImageBase)\n", (BYTE*)hModule + 0x18 + 0x1c, pNt->OptionalHeader.ImageBase);
	printf("%08X:  0x%X \t (SizeOfImage)\n", (BYTE*)hModule + 0x18 + 0x38, pNt->OptionalHeader.SizeOfImage);
	printf("\n");


	// ���� �̸� �� ���� �ٵ� ���
	printf("========== SECTION BODY ==========\n\n");

	IMAGE_SECTION_HEADER* pSectionHeader	= pSectionHeaderBase;
	DWORD NumberOfSections					= pNt->FileHeader.NumberOfSections;
	BYTE* pSection							= 0;
	DWORD SizeOfSection						= 0;
	for (int i = 0; i < NumberOfSections; i++)
	{
		printf("%s\n", pSectionHeader->Name);
		pSection		= (BYTE*)pDos + pSectionHeader->VirtualAddress;
		SizeOfSection	= pSectionHeader->Misc.VirtualSize;

		// ����Ʈ�� �� �ٴ� 0x20�� ������ ��� ���
		for (int j = 0; j < SizeOfSection; j += 0x20)
		{
			printf("%08X:  ", (DWORD)hModule + j);
			for (int k = 0; k < 0x20; k++)
			{
				printf("%02X ", *(pSection + j + k));
			}
			printf("\n");
		}
		pSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)pSectionHeader + 0x28);	// IMAGE_SECTION_HEADER32 ����ü�� ũ���� 0x28 ����Ʈ�� ���ؼ� ���� ���� ����� ����Ų��
		printf("\n");
	}

	CloseHandle(hSnap);
	CloseHandle(hProc);

	return 0;
}