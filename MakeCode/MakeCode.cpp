// GotoCode.cpp : 定义控制台应用程序的入口点。
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

	//自定位
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

	//得到Kernel32句柄和GetProcAddress地址
	__asm{

		pushad    //保存寄存器

		mov eax, dword ptr fs:[0x30];  
		mov eax, dword ptr [eax+0xC];  
		mov eax, dword ptr [eax+0xC];  
		mov eax, dword ptr [eax];  
		mov eax, dword ptr [eax];  
		mov eax, dword ptr [eax+0x18];  

		mov hMod,eax
		mov myGetProcAddress,eax

		push ebp

		mov ebp,eax                         // Kernel.dll基址  
		mov eax,dword ptr ss:[ebp+3CH]      // eax=PE首部  
		mov edx,dword ptr ds:[eax+ebp+78H]  //  
		add edx,ebp                         // edx=引出表地址  
		mov ecx,dword ptr ds:[edx+18H]      // ecx=导出函数个数，NumberOfFunctions  
		mov ebx,dword ptr ds:[edx+20H]      //  
		add ebx,ebp                         // ebx=函数名地址，AddressOfName  
start:                                      //  
		dec ecx                             // 循环的开始  
		mov esi,dword ptr ds:[ebx+ecx*4]    //  
		add esi,ebp                         //  
		mov eax,0x50746547                  //  
		cmp dword ptr ds:[esi],eax          // 比较PteG  
		jnz start                           //  
		mov eax,0x41636F72                  //  
		cmp dword ptr ds:[esi+4],eax        // 比较Acor，通过GetProcA几个字符就能确定是GetProcAddress  
		jnz start                           //  
		mov ebx,dword ptr ds:[edx+24H]      //  
		add ebx,ebp                         //  
		mov cx,word ptr ds:[ebx+ecx*2]      //  
		mov ebx,dword ptr ds:[edx+1CH]      //  
		add ebx,ebp                         //  
		mov eax,dword ptr ds:[ebx+ecx*4]    //  
		add eax,ebp                         // eax 现在是GetProcAddress地址  
		mov ebx,eax                         // GetProcAddress地址存入ebx，如果写ShellCode的话以后还可以

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
	/*                        检查数据有效性，并初始化                      */
	/************************************************************************/

	//检查长度
	if (nDataLength < sizeof(IMAGE_DOS_HEADER))
	{
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)lpFileData;  // DOS头
	//检查dos头的标记
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return;  //0x5A4D : MZ
	}

	//检查长度
	if ((DWORD)nDataLength < (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
	{
		return;
	}
	//取得pe头
	pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)lpFileData + pDosHeader->e_lfanew); // PE头
	//检查pe头的合法性
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return;  //0x00004550 : PE00
	}
	if ((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) //0x2000  : File is a DLL
	{
		return;  
	}
	if ((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) //0x0002 : 指出文件可以运行
	{
		return;
	}
	if (pNTHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
	{
		return;
	}	

	//取得节表（段表）
	pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNTHeader + sizeof(IMAGE_NT_HEADERS));
	//验证每个节表的空间
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
	/*                          计算所需的加载空间                          */
	/************************************************************************/
	int nImageSize = 0;

	if (pNTHeader == NULL)
	{
		return;
	}

	int nAlign = pNTHeader->OptionalHeader.SectionAlignment; //段对齐字节数

	// 计算所有头的尺寸。包括dos, coff, pe头 和 段表的大小
	nImageSize = GetAlignedSize(pNTHeader->OptionalHeader.SizeOfHeaders, nAlign);
	// 计算所有节的大小
	for (int i=0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
	{
		//得到该节的大小
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
	// 分配虚拟内存
	void *pMemoryAddress = myVirtualAlloc(NULL, nImageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pMemoryAddress == NULL)
	{
		return;
	}
	else
	{
		/************************************************************************/
		/*                       复制dll数据，并对齐每个段                      */
		/************************************************************************/

		LPVOID pDest = pMemoryAddress;
		LPVOID pSrc = lpFileData;

		// 计算需要复制的PE头+段表字节数
		int  nHeaderSize = pNTHeader->OptionalHeader.SizeOfHeaders;
		int  nSectionSize = pNTHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
		int  nMoveSize = nHeaderSize + nSectionSize;
		//复制头和段信息
		//memcpy(pDest, pSrc, nMoveSize);

		for (int i = 0; i < nMoveSize ; i++)
		{
			((char*)pDest)[i] = ((char*)pSrc)[i];
		}

		//复制每个节
		for (int i=0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
		{
			if (pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)
			{
				continue;
			}
			// 定位该节在内存中的位置
			void *pSectionAddress = (void *)((PBYTE)pDest + pSectionHeader[i].VirtualAddress);
			
			
			// 复制段数据到虚拟内存
// 			memcpy((void *)pSectionAddress, (void *)((PBYTE)pSrc + pSectionHeader[i].PointerToRawData),
// 				pSectionHeader[i].SizeOfRawData);

			for (int j = 0; j < pSectionHeader[i].SizeOfRawData ; j++)
			{
				((char*)pSectionAddress)[j] = ((char*)((PBYTE)pSrc + pSectionHeader[i].PointerToRawData))[j];
			}
		}

		//修正指针，指向新分配的内存
		//新的dos头
		pDosHeader = (PIMAGE_DOS_HEADER)pDest;
		//新的pe头地址
		pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDest + (pDosHeader->e_lfanew));
		//新的节表地址
		pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNTHeader + sizeof(IMAGE_NT_HEADERS));

		/************************************************************************/
		/*                                   OVER                               */
		/************************************************************************/

		//重定位信息
		if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
			&& pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
		{
			/************************************************************************/
			/*                          修复重定位信息                              */
			/************************************************************************/

			void *pNewBase  = pMemoryAddress;

			/* 重定位表的结构：
			// DWORD sectionAddress, DWORD size (包括本节需要重定位的数据)
			// 例如 1000节需要修正5个重定位数据的话，重定位表的数据是
			// 00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
			// -----------   -----------      ----
			// 给出节的偏移  总尺寸=8+6*2     需要修正的地址           用于对齐4字节
			// 重定位表是若干个相连，如果address 和 size都是0 表示结束
			// 需要修正的地址是12位的，高4位是形态字，intel cpu下是3
			*/
			//假设NewBase是0x600000,而文件中设置的缺省ImageBase是0x400000,则修正偏移量就是0x200000
	
			//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
			PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long)pNewBase 
				+ pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
			{
				WORD *pLocData = (WORD *)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
				//计算本节需要修正的重定位项（地址）的数目
				int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);

				for ( int i=0 ; i < nNumberOfReloc; i++)
				{
					// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
					// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。
					if ((DWORD)(pLocData[i] & 0x0000F000) == 0x0000A000)
					{
						// 64位dll重定位，IMAGE_REL_BASED_DIR64
						// 对于IA-64的可执行文件，重定位似乎总是IMAGE_REL_BASED_DIR64类型的。
		#ifdef _WIN64
						ULONGLONG* pAddress = (ULONGLONG *)((PBYTE)pNewBase + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
						ULONGLONG ullDelta = (ULONGLONG)pNewBase - pNTHeader->OptionalHeader.ImageBase;
						*pAddress += ullDelta;
		#endif
					}
					else if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
					{
						// 32位dll重定位，IMAGE_REL_BASED_HIGHLOW
						// 对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。
		#ifndef _WIN64
						DWORD* pAddress = (DWORD *)((PBYTE)pNewBase + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
						DWORD dwDelta = (DWORD)pNewBase - pNTHeader->OptionalHeader.ImageBase;
						*pAddress += dwDelta;
		#endif
					}
				}
				//转移到下一个节进行处理
				pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
			}

			/************************************************************************/
			/*                          OVER                                        */
			/************************************************************************/
		}

		/************************************************************************/
		/*                             填充引入地址表                           */
		/************************************************************************/
			
		void* pImageBase = pMemoryAddress;
		BOOL ret = FALSE;


		// 引入表实际上是一个 IMAGE_IMPORT_DESCRIPTOR 结构数组，全部是0表示结束
		// 数组定义如下：
		// 
		// DWORD   OriginalFirstThunk;         // 0表示结束，否则指向未绑定的IAT结构数组
		// DWORD   TimeDateStamp; 
		// DWORD   ForwarderChain;             // -1 if no forwarders
		// DWORD   Name;                       // 给出dll的名字
		// DWORD   FirstThunk;                 // 指向IAT结构数组的地址(绑定后，这些IAT里面就是实际的函数地址)
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
			//获取dll的名字
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
			//获取DLL中每个导出函数的地址，填入IAT
			//每个IAT结构是 ：
			// union { PBYTE  ForwarderString;
			//   PDWORD Function;
			//   DWORD Ordinal;
			//   PIMAGE_IMPORT_BY_NAME  AddressOfData;
			// } u1;
			// 长度是一个DWORD ，正好容纳一个地址。
			for (i=0; ; i++)
			{
				if (pOriginalIAT[i].u1.Function == 0)
				{
					break;
				}

				FARPROC lpFunction = NULL;

				if (pOriginalIAT[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) //这里的值给出的是导出序号
				{
					lpFunction = myGetProcAddress(hDll, (LPCSTR)(pOriginalIAT[i].u1.Ordinal & 0x0000FFFF));
				}
				else //按照名字导入
				{
					//获取此IAT项所描述的函数名称
					PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pImageBase + (pOriginalIAT[i].u1.AddressOfData));

					lpFunction = myGetProcAddress(hDll, (char *)pByName->Name);
				}
				if (lpFunction != NULL)   //找到了！
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

		if (!ret) //修正引入地址表失败
		{
			myVirtualFree(pMemoryAddress, 0, MEM_RELEASE);
			return;
		}
		//修改页属性。应该根据每个页的属性单独设置其对应内存页的属性。这里简化一下。
		//统一设置成一个属性PAGE_EXECUTE_READWRITE
		unsigned long unOld;

		myVirtualProtect(pMemoryAddress, nImageSize, PAGE_EXECUTE_READWRITE, &unOld);
	}
	//修正基地址
#ifdef WIN32
	pNTHeader->OptionalHeader.ImageBase = (DWORD)pMemoryAddress;
#else
	pNTHeader->OptionalHeader.ImageBase = (ULONGULONG)pMemoryAddress;
#endif
	//接下来要调用一下dll的入口函数，做初始化工作。
	ProcDllMain pDllMain = (ProcDllMain)(pNTHeader->OptionalHeader.AddressOfEntryPoint + (PBYTE)pMemoryAddress);

	BOOL InitResult = pDllMain((HINSTANCE)pMemoryAddress, DLL_PROCESS_ATTACH, 0);

	if (!InitResult) //初始化失败
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

