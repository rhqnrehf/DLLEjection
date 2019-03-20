#include "pch.h"

using namespace std;
vector<DWORD> FindProcessId(LPCTSTR szProcessName) {
	vector<DWORD> vc;
	DWORD dwPID = 0xffffffff;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	Process32First(hSnapShot, &pe);
	do {
		dwPID = pe.th32ProcessID;
		vc.push_back(pe.th32ProcessID);
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);

	return vc;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		wcout << L"OpenProcessToken Error: " << GetLastError() << endl;
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL,
		lpszPrivilege,
		&luid)) {
		wcout << L"LookipPrivilegeValue Error: " << GetLastError() << endl;
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		tp.Privileges[0].Attributes = 0;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		wcout << L"AdjustTokenPrivileges Error: " << GetLastError() << endl;
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		wcout << L"The Token does not have the specified privilege. " << endl;
		return FALSE;
	}
	return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllName) {
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	LPTHREAD_START_ROUTINE pThreadProc;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

	bMore = Module32First(hSnapshot, &me);

	for (; bMore; bMore = Module32Next(hSnapshot, &me)) {
		if (!_tcsicmp(me.szModule, szDllName) || !_tcsicmp(me.szExePath, szDllName)) {
			bFound = TRUE;
			break;
		}
	}

	if (!bFound) {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		wcout << L"OpenProcess(" << dwPID << L") failed!!! [" << GetLastError() << L"]" << endl;
		return FALSE;
	}

	hModule = GetModuleHandle(L"kernel32.dll");
	pThreadProc = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(hModule, "FreeLibrary"));

	hThread = CreateRemoteThread(hProcess, NULL, NULL, pThreadProc, me.modBaseAddr, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}
int _tmain(int argc, TCHAR *argv)
{
	wcout.imbue(locale("kor"));
	vector<DWORD> vc;
	WCHAR name[50] = { NULL };
	wcout << L"want Ejection DLL NAME:";
	wcin >> name;
	if (name[0] == NULL)
		return NULL;
	vc = FindProcessId(name);
	if (vc.empty()) {
		wcout << L"There is no " << name << L" process" << endl;
		return NULL;
	}

	for (DWORD dwPID : vc) {
		wcout << L"PID of " << name << L" is " << dwPID << endl;
	}

	if (!SetPrivilege(SE_DEBUG_NAME, TRUE)) {
		return NULL;
	}

	for (DWORD dwPID : vc) {
		if (EjectDll(dwPID, name)) {
			wcout << L"EjectDll(" << dwPID << L", " << name << L" success!!" << endl;
		}
		else {
			wcout << L"EjectDll(" << dwPID << L", " << name << L") failed!!" << endl;
		}
	}

	return 1;

}
