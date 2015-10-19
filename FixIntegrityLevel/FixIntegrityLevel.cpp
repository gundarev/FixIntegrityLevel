// Copyright © Microsoft Corporation.  All Rights Reserved.
// This code released under the terms of the 
// Microsoft Public License (MS-PL, https://urldefense.proofpoint.com/v2/url?u=http-3A__opensource.org_licenses_ms-2Dpl.html&d=BQIG-g&c=Sqcl0Ez6M0X8aeM67LKIiDJAXVeAw-YihVMNtXt-uEs&r=GcQMmHE4qg3pLxgxA1QUaA7vepR2Nduaa-y4HqvuSTM&m=UNs3kiPJ1dbuCVP83ARFQaQwz1a0Q2uIQyJMcAJdH5I&s=hAvqctQX5YC8l1g1-TUFjSwoByU8nKV8rLML3w8MBjA&e= .)

/*
Sample Code is provided for the purpose of illustration only and is not intended
to be used in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION
ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free right to
use and modify the Sample Code and to reproduce and distribute the object code
form of the Sample Code, provided that. You agree: (i) to not use Our name, logo,
or trademarks to market Your software product in which the Sample Code is embedded;
(ii) to include a valid copyright notice on Your software product in which the
Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us
and Our suppliers from and against any claims or lawsuits, including attorneys’
fees, that arise or result from the use or distribution of the Sample Code
*/


// LowereApp.cpp : Defines the entry point for the console application.

//



#include "stdafx.h"



#include <windows.h>

#include <stdio.h>

#include <sddl.h>

#include <AccCtrl.h>

#include <Aclapi.h>
#include <string>
#include <atlstr.h>


// The LABEL_SECURITY_INFORMATION SDDL SACL to be set for low integrity 

#define LOW_INTEGRITY_SDDL_SACL_W L"S:(ML;;NW;;;LW)"



void wmain(int argc, WCHAR *argv[])

{

	DWORD                dwError = ERROR_SUCCESS;

	PSECURITY_DESCRIPTOR pSD = NULL;



	PACL    pSacl = NULL; // not allocated

	BOOL    fSaclPresent = FALSE;

	BOOL    fSaclDefaulted = FALSE;
#define BUFSIZE 4096
	LPCWSTR pwszFileName;


	wchar_t buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	wchar_t volumebuffer[MAX_PATH];
	DWORD  retval = 0;
	TCHAR** lppPart = { NULL };
	TCHAR  buffer2[BUFSIZE] = TEXT("");
	GetVolumePathName(buffer, volumebuffer, MAX_PATH);
	retval = GetVolumeNameForVolumeMountPoint(volumebuffer, buffer2, BUFSIZE);
	WCHAR  DeviceName[MAX_PATH];
	DWORD  CharCount = 0;
	size_t Index = 0;
	Index = wcslen(buffer2) - 1;
	buffer2[Index] = L'\0';
	CharCount = QueryDosDeviceW(&buffer2[4], DeviceName, ARRAYSIZE(DeviceName));






	CString cFileName;

	if (DeviceName && (DeviceName[0] != 0))
	{
		cFileName = CString(DeviceName);
	}
	cFileName.Replace(L"Device", L"\\.");
	pwszFileName = CT2CW(cFileName);
	wprintf(L"Changing integrity level of  with %s\n", pwszFileName);


	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(LOW_INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, NULL))

	{

		wprintf(L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed with %u\n", GetLastError());

		return;

	}



	if (!GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))

	{

		wprintf(L"GetSecurityDescriptorSacl failed with %u\n", GetLastError());

		return;

	}



	// Note that psidOwner, psidGroup, and pDacl are 

	// all NULL and set the new LABEL_SECURITY_INFORMATION

	dwError = SetNamedSecurityInfoW((LPWSTR)pwszFileName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pSacl);

	if (dwError != ERROR_SUCCESS)

	{

		wprintf(L"SetNamedSecurityInfoW failed with %u\n", dwError);

		return;

	}

	else

		wprintf(L"SetNamedSecurityInfoW success\n");



	LocalFree(pSD);

}
