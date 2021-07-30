#include <stdio.h>
#include <Windows.h>

int main(void)
{
	// 
	WCHAR szPath[100];
	ZeroMemory(szPath, 100);
	GetModuleFileNameW(NULL, szPath, sizeof(szPath));
	

	printf("%ws\n", szPath);

	return 0;
}