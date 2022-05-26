// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Userenv.h>
#include <windows.h>
#include <string.h>
#include "Fileapi.h"
#include <aclapi.h>
#include <atlstr.h>
#include<map>
#include<fstream>
#include <string.h>
#include<vector>
#include <sddl.h>
#include<Tlhelp32.h>
//#include "zlib.h"
#include <sstream>
#include <Processthreadsapi.h>
#include<iostream>
using namespace std;
#define	MASKLENGTH		10
#define _CRT_SECURE_NO_WARNINGS 1
typedef unsigned long  uLong; /* 32 bits or more */
typedef uLong FAR uLongf;
typedef unsigned char  Byte;  /* 8 bits */
typedef Byte  FAR Bytef;

Bytef	Source[1800000];
Bytef	Dest[1850000];

CString cstrNetLogonPath;
bool isEngineDecryptedSuccessfully;
CString  cstrTempDirPath("C:\\TEMPPATH");
CString csTempKixFilePath;
BOOL CreateMyDACL(SECURITY_ATTRIBUTES*);
char		chResourceString[512];
char        chResourceString2[512];
char		chEMask[MASKLENGTH];
// Set ScriptLogic Path
// This function will set temp directory path
string convertCStringTostdString(CString inputString) {
	CT2CA pszConvertedAnsiString(inputString);
	std::string strOutputString(pszConvertedAnsiString);
	return strOutputString;
}











bool _IsNewProcessLaunched( CString exe)
{
	// Create the restricted token.

	SAFER_LEVEL_HANDLE hLevel = NULL;
	if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, &hLevel, NULL))
	{
		return false;
	}

	HANDLE hRestrictedToken = NULL;
	if (!SaferComputeTokenFromLevel(hLevel, NULL, &hRestrictedToken, 0, NULL))
	{
		SaferCloseLevel(hLevel);
		return false;
	}

	SaferCloseLevel(hLevel);

	// Set the token to medium integrity.

	TOKEN_MANDATORY_LABEL tml = { 0 };
	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	// alternatively, use CreateWellKnownSid(WinMediumLabelSid) instead...
	if (!ConvertStringSidToSid(TEXT("S-1-16-8192"), &(tml.Label.Sid)))
	{
		CloseHandle(hRestrictedToken);
		return false;
	}

/*	if (!SetTokenInformation(
, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(tml.Label.Sid)))
	{
	LocalFree(tml.Label.Sid);
	CloseHandle(hRestrictedToken);
	return false;
	}*/

	LocalFree(tml.Label.Sid);

	// Create startup info

	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	//si.lpDesktop =LPWSTR("winsta0\\default");

	PROCESS_INFORMATION pi = { 0 };

	// Get the current executable's name
	TCHAR exePath[MAX_PATH + 1] = { 0 };
	//GetModuleFileName(NULL, exePath, MAX_PATH);

	// Start the new (non-elevated) restricted process
	char exe1[] = "c:\\windows\\notepad.exe";
	LPWSTR ss = exe.GetBuffer();
	if (!CreateProcessAsUser(hRestrictedToken, ss, NULL, NULL, NULL, TRUE, CREATE_NEW_CONSOLE| NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi))
	{
		CloseHandle(hRestrictedToken);
		return false;
	}

	CloseHandle(hRestrictedToken);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return true;
}
DWORD MyGetProcessId(LPCTSTR ProcessName) // non-conflicting function name
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) { // must call this first
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap); // close handle on failure
	return 0;
}

void nonelevated()
{

	
	HWND hwnd = GetDesktopWindow();
	LPCTSTR app(TEXT("vcpkgsrv.exe"));
	DWORD pid= MyGetProcessId(app);
	//GetWindowThreadProcessId(hwnd, &pid);
	//pid = 7004;
	HANDLE process =
		OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	PHANDLE TokenHandle=NULL;
	PHANDLE newTokenHandle = NULL;

	OpenProcessToken(process, TOKEN_DUPLICATE , TokenHandle);
	DuplicateTokenEx(TokenHandle, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY , NULL, SecurityImpersonation, TokenPrimary, newTokenHandle);
//	PSID integritySid = nullptr;
	//WCHAR lowIntegrityLevelSid[20] = _T("S-1-16-4096");
  // ConvertStringSidToSid(lowIntegrityLevelSid, &integritySid);
   //TOKEN_MANDATORY_LABEL til = { 0 };
   //til.Label.Attributes = SE_GROUP_INTEGRITY;
   //til.Label.Sid = integritySid;
   //SetTokenInformation(newTokenHandle, TokenIntegrityLevel, &til, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(integritySid));
	/*SIZE_T size;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
	auto p = (PPROC_THREAD_ATTRIBUTE_LIST)new char[size];

	InitializeProcThreadAttributeList(p, 1, 0, &size);
	UpdateProcThreadAttribute(p, 0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&process, sizeof(process),
		nullptr, nullptr);

	wchar_t cmd[] = L"C:\\Windows\\System32\\cmd.exe";
	STARTUPINFOEX siex = {};
	siex.lpAttributeList = p;
	siex.StartupInfo.cb = sizeof(siex);
	PROCESS_INFORMATION pi;
	
	if (!CreateProcess(NULL, exe.GetBuffer(), nullptr, nullptr, FALSE,
		CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT,
		nullptr, nullptr, &siex.StartupInfo, &pi))
	{
	
		cout <<"\n" << "error" << GetLastError();
	
	}

	//CloseHandle(pi.hProcess);
	//CloseHandle(pi.hThread);
	delete[](char*)p;
	CloseHandle(process);*/
	STARTUPINFO si = { 0 };
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(si);
	//si.lpDesktop =LPWSTR("winsta0\\default");
	CString exe("c:\\windows\\system32\\cmd.exe");
	PROCESS_INFORMATION pi = { 0 };
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	//LPVOID pEnvironmentBlock;
	//CreateEnvironmentBlock(&pEnvironmentBlock, TokenHandle, FALSE);
	TCHAR szCommandLine[MAX_PATH];
	_tcscpy_s(szCommandLine, MAX_PATH, _T("C:\\Windows\\system32\\cmd.exe"));

	if (!CreateProcessWithTokenW(newTokenHandle, NULL, NULL, szCommandLine,  CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		cout << "erro is " << GetLastError();
	}
	ImpersonateLoggedOnUser(newTokenHandle);
	if (!CreateProcessAsUser(newTokenHandle, exe.GetBuffer(), NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		CloseHandle(newTokenHandle);
		cout << "erro is " << GetLastError();
		//return false;
	}
	
}


int main()
{
	CString null("tmpFilePath.txt");
	string filepath("\\\\AbhijeetDC1\\netlogon\\");
	setNetLogonPath(CString(filepath.c_str()));
	//ReadFromFile(null);
	setTempKixFileName(null);
	char chTempKixFilePath[512];

	char kix[2048];
	char commandline1[2048] = { "C:\\tempfiles\\wkix32.exe"};
	char commandline[2048];
	STARTUPINFO			starti;
	PROCESS_INFORMATION	pi;

	ZeroMemory(&starti, sizeof(STARTUPINFO));
	starti.cb = sizeof(STARTUPINFO);

	nonelevated();


	

	
	getchar();
}


// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
