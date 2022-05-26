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

bool RegistryGrantAll(HKEY hKey)
{
	bool bResult = false;

	PSECURITY_DESCRIPTOR sd = nullptr;
	//TEXT("(A;OICI;KRKW;;;AU)")  // Allow KEY_READ and KEY_WRITE to authenticated users ("AU")
	const TCHAR* szSD =
		TEXT("D:")                  // Discretionary ACL
		TEXT("(A;OICI;GA;;;BG)")    // Deny access to built-in guests
		TEXT("(A;OICI;GA;;;AN)")    // Deny access to anonymous logon
		TEXT("(A;OICI;KA;;;DU)")    // Deny access to anonymous logon
		TEXT("(A;OICI;KA;;;BU)")    // Deny access to anonymous logon
		TEXT("(A;OICI;KA;;;LA)")
		TEXT("(A;OICI;KA;;;BA)");   // Allow KEY_ALL_ACCESS to administrators ("BA" = Built-in Administrators)
	    TEXT("(A;OICI;KA;;;SY)");    // Allow full control 
								// SYSTEM



	if (ConvertStringSecurityDescriptorToSecurityDescriptor((LPCTSTR)szSD, SDDL_REVISION_1, &sd, 0))
	{
		auto result = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, sd);
		if (ERROR_SUCCESS == result)
			bResult = true;
		else
			SetLastError(result);

		// Free the memory allocated for the SECURITY_DESCRIPTOR.
		LocalFree(sd);
	}

	return bResult;
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
void ignore()
{
	HKEY hKey;

	CString Key1 = "SOFTWARE\\Classes\\SLAgent.";

	CString Key3 = "\\CLSID";
	ofstream ofs;
	std::string Key2[4] = { "ComputerInfo", "Registry",
								  "SLAgent", "WindowsFirewall" };

	for (int i = 0; i < sizeof(Key2) / sizeof(Key2[0]); i++)

	{
		CString ComputerInfo = Key1 + (Key2[i].c_str()) + Key3;// ComputerInfo.Append((Key2[0].c_str()));// = "SOFTWARE\\Classes\\SLAgent.ComputerInfo\\CLSID";


		LPCTSTR sk = ComputerInfo;// = ComputerInfo; TEXT("SOFTWARE\\Classes\\SLAgent.") + TEXT(ComputerInfo) + TEXT("\\CLSID");


		LONG openRes = RegOpenKeyEx(HKEY_LOCAL_MACHINE, sk, 0, KEY_ALL_ACCESS, &hKey);

		if (openRes == ERROR_SUCCESS) {
			printf("Success opening key.");
			ofs << "Success opening key";
		}
		else {
			printf("Error opening key.");
			ofs << "Error opening key";
		}

		LPCTSTR value = TEXT("TestSoftwareKey");
		LPCTSTR data = TEXT("TestData");

		/*LONG  setRes = RegSetValueEx(hKey, value, 0, REG_SZ, (LPBYTE)data, 9);

		if (setRes == ERROR_SUCCESS) {
			printf("Success writing to Registry.");
			ofs << "Success writing to Registry.";
		}
		else {
			printf("Error writing to Registry.");
			ofs << "Error writing to Registry.";
		}*/
		TCHAR  buf1[256] = { 0 };
		DWORD count = 256;
		CString out;
		if (RegQueryValueEx(hKey, TEXT(""), 0, NULL, (BYTE*)buf1, &count) == ERROR_SUCCESS)
		{
			out = buf1;

			//out.TrimRight(TEXT("slogic.bat\\.."));
			//out.Append(TEXT("\\"));
			//setNetLogonPath(out);
			//dbgFile.DebugMessage(TEXT("*****setNetLogonPath") + out);
			wcout << "Nelogon" << out.GetBuffer() << "\n";
			ofs << " Default " << "\n";
			ofs << out.GetBuffer() << "\n";
		}
		else
		{

			cout << "error" << GetLastError();
		}
		LONG closeOut = RegCloseKey(hKey);
		if (closeOut == ERROR_SUCCESS) {
			printf("Success closing key.");
		}
		else {

			printf("Error closing key.");
		}

		//Classes\WOW6432Node\CLSID\{812AB128-69F3-4C1D-B454-CE5A75AAB4CD}\InprocServer32
		CString testuser = "testuser";
		CString domain = "AbhijeetDC01";
		CString password = "Acc0lite";
		HANDLE h;
		if (LogonUser(testuser, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h))
		{

			cout << "Logon success" << GetLastError() << "\n";
		}
		else
		{
			cout << "Logon Fail" << GetLastError() << "\n";
		}

		CString Key1_HKCU = "Software\\Classes\\WOW6432Node\\CLSID\\";
		CString Key3_HKCU = "\\InprocServer32";
		out = "{812AB128-69F3-4C1D-B454-CE5A75AAB4CD}";

		//	Key1_HKCU.Append(out);
		//	Key1_HKCU.Append(Key3_HKCU);

		CString Final_Key = Key1_HKCU + out + Key3_HKCU;
		//Final_Key.Append(Key1_HKCU);

		wcout << "\n" << "Final_Key" << Final_Key.GetBuffer() << "\n";
		HKEY DK;
		HKEY currKey;


		//TEXT("Software\\Classes\\WOW6432Node\\CLSID\\{812AB128-69F3-4C1D-B454-CE5A75AAB4CD}\\InprocServer32")
		LPCTSTR Final_Key_HKCU = Final_Key;
		wcout << "Final_Key_HKCU" << Final_Key_HKCU << "\n";
		CString exp = "Software\\Classes\\WOW6432Node\\CLSID\\{812AB128-69F3-4C1D-B454-CE5A75AAB4CD}\\InprocServer32";
		wcout << "exp" << exp << "\n";


		LPCTSTR Final_Key_HKCU_1 = TEXT("Software\\Classes\\WOW6432Node\\CLSID");
		if (RegOpenKeyEx(HKEY_CURRENT_USER, Final_Key_HKCU_1, 0, KEY_ALL_ACCESS, &DK) == ERROR_SUCCESS)
		{
			LPCTSTR     lpSubKey = out;
			DWORD result = RegCreateKeyEx(DK, TEXT("Hi"), NULL, NULL, NULL, NULL, NULL, NULL, NULL);
			cout << result << "get" << GetLastError();
		}
		//Final_Key_HKCU = Final_Key;
		ImpersonateLoggedOnUser(h);
		cout << "ImpersonateLoggedOnUser" << GetLastError() << "\n";

		if (RegOpenCurrentUser(KEY_ALL_ACCESS, &currKey) == ERROR_SUCCESS)
		{
			if (RegOpenKeyEx(currKey, Final_Key_HKCU, 0, KEY_ALL_ACCESS, &DK) == ERROR_SUCCESS)
			{

				//RegDeleteValueA(DK, "");
				RegistryGrantAll(DK);
				cout << "RegOpenKeyEx" << GetLastError() << "\n";

			}
			else
			{
				LPCTSTR Final_Key_HKCU_1 = TEXT("Software\\Classes\\WOW6432Node\\CLSID");
				if (RegOpenKeyEx(currKey, Final_Key_HKCU_1, 0, KEY_ALL_ACCESS, &DK) == ERROR_SUCCESS)
				{
					LPCTSTR     lpSubKey = out;
					DWORD result = RegCreateKeyEx(DK, lpSubKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
					cout << result << "get" << GetLastError();
				}
				cout << "RegOpenKeyEx fail" << GetLastError() << "\n";
			}
		}
		::RevertToSelf();


	}

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
