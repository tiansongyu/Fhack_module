#include<Windows.h>
#include"Patternscan.h"
#include<iostream>
using namespace std;

DWORD FindProcessName(const char *__ProcessName)
{
	PROCESSENTRY32 __ProcessEntry;
	__ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;        if (!Process32First(hSnapshot, &__ProcessEntry))
	{
		CloseHandle(hSnapshot);
		return 0;
	}
	do {
		if (!_strcmpi(__ProcessEntry.szExeFile, __ProcessName))
		{
			//memcpy((void *)pEntry, (void *)&__ProcessEntry, sizeof(PROCESSENTRY32));
			CloseHandle(hSnapshot);
			return __ProcessEntry.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &__ProcessEntry));
	CloseHandle(hSnapshot);
	return 0;
}
int main()
{
	DWORD sun = 0;
	DWORD pid = 0;
	DWORD Entity = 0;
	char shellcode[] = "\x90\x90\x90\x90\x90\x90";
	//char shellcode[] = "\x89\xB7\x78\x55\x00\x00";
	pid = FindProcessName("PlantsVsZombies.exe");
	if (pid == 0)
	{
		cout << "fail to find pid" << endl;
		return 0;
	}
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, 0, pid);
	sun = (DWORD)PatternScanExModule(hProcess, L"PlantsVsZombies.exe", L"PlantsVsZombies.exe",
		"\x89\xB7\x78\x55\x00\x00", "xxxxxx");
	if (sun)
	{
		cout << "success" << endl;
		ReadProcessMemory(hProcess, (PBYTE*)(sun), &Entity, sizeof(int), NULL);
		cout << "entity" << Entity << endl;
		WriteProcessMemory(hProcess, (PBYTE*)(sun), shellcode,sizeof(shellcode)-1, NULL);
		
		ReadProcessMemory(hProcess, (PBYTE*)(sun), &Entity, sizeof(int), NULL);
		cout << "changed entity" << Entity << endl;
	}
	else
		cout << "fail to find address of sun" << endl;
	system("pause");
	return 0;
}