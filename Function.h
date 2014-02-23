/*-----------------------------------------------------------------------
* 文件名稱 : Function.h                                                 
* 編譯環境 : WDK 7600.16385.1
/-------------------------------------------------------------------------
* File Name            : Function.h  
* Building environment : WDK 7600.16385.1
-------------------------------------------------------------------------*/

#include <ntddk.h>
#include "ntimage.h"
#include "stdio.h"
#include <windef.h>
#include <string.h>

UCHAR MaxByte[4]={0xFF,0xFF,0xFF,0xFF};

//獲得由ntoskrnl.exe導出函數,以Zw*開頭函數的地址，這個函數的返回值就是Nt*函數，Nt*函數的地址就在SSDT中
#define SYSTEMSERVICE(_func) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_func+1)]

//獲得Zw*函數的地址並返回與之通信的函數在SSDT中的索引。
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)

//獲得Zw*函數的地址，取得他的索引，自動的交換SSDT中索引所對應的函數地址和我們hook函數的地址。
#define HOOK_SYSCALL(_Function, _Hook, _Orig ) _Orig = (PVOID) InterlockedExchange ((PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)
#define UNHOOK_SYSCALL(_Func, _Hook, _Orig ) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Func)], (LONG) _Hook)

typedef struct ServiceDescriptorEntry
{
        unsigned int *ServiceTableBase;
        unsigned int *ServiceCounterTableBase; //Used only in checked build
        unsigned int NumberOfServices;
        unsigned char *ParamTableBase;
} SSDTEntry;
__declspec(dllimport)  SSDTEntry KeServiceDescriptorTable;


typedef enum _SYSTEM_INFORMATION_CLASS {
 SystemBasicInformation, // 0 Y N
 SystemProcessorInformation, // 1 Y N
 SystemPerformanceInformation, // 2 Y N
 SystemTimeOfDayInformation, // 3 Y N
 SystemNotImplemented1, // 4 Y N
 SystemProcessesAndThreadsInformation, // 5 Y N
 SystemCallCounts, // 6 Y N
 SystemConfigurationInformation, // 7 Y N
 SystemProcessorTimes, // 8 Y N
 SystemGlobalFlag, // 9 Y Y
 SystemNotImplemented2, // 10 Y N
 SystemModuleInformation, // 11 Y N
 SystemLockInformation, // 12 Y N
 SystemNotImplemented3, // 13 Y N
 SystemNotImplemented4, // 14 Y N
 SystemNotImplemented5, // 15 Y N
 SystemHandleInformation, // 16 Y N
 SystemObjectInformation, // 17 Y N
 SystemPagefileInformation, // 18 Y N
 SystemInstructionEmulationCounts, // 19 Y N
 SystemInvalidInfoClass1, // 20
 SystemCacheInformation, // 21 Y Y
 SystemPoolTagInformation, // 22 Y N
 SystemProcessorStatistics, // 23 Y N
 SystemDpcInformation, // 24 Y Y
 SystemNotImplemented6, // 25 Y N
 SystemLoadImage, // 26 N Y
 SystemUnloadImage, // 27 N Y
 SystemTimeAdjustment, // 28 Y Y
 SystemNotImplemented7, // 29 Y N
 SystemNotImplemented8, // 30 Y N
 SystemNotImplemented9, // 31 Y N
 SystemCrashDumpInformation, // 32 Y N
 SystemExceptionInformation, // 33 Y N
 SystemCrashDumpStateInformation, // 34 Y Y/N
 SystemKernelDebuggerInformation, // 35 Y N
 SystemContextSwitchInformation, // 36 Y N
 SystemRegistryQuotaInformation, // 37 Y Y
 SystemLoadAndCallImage, // 38 N Y
 SystemPrioritySeparation, // 39 N Y
 SystemNotImplemented10, // 40 Y N
 SystemNotImplemented11, // 41 Y N
 SystemInvalidInfoClass2, // 42
 SystemInvalidInfoClass3, // 43
 SystemTimeZoneInformation, // 44 Y N
 SystemLookasideInformation, // 45 Y N
 SystemSetTimeSlipEvent, // 46 N Y
 SystemCreateSession, // 47 N Y
 SystemDeleteSession, // 48 N Y
 SystemInvalidInfoClass4, // 49
 SystemRangeStartInformation, // 50 Y N
 SystemVerifierInformation, // 51 Y Y
 SystemAddVerifier, // 52 N Y
 SystemSessionProcessesInformation // 53 Y N
}SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION { // Information Class 11
 ULONG Reserved[2];
 PVOID Base;
 ULONG Size;
 ULONG Flags;
 USHORT Index;
 USHORT Unknown;
 USHORT LoadCount;
 USHORT ModuleNameOffset;
 CHAR ImageName[256];

}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _tagSysModuleList {
    ULONG ulCount;
    SYSTEM_MODULE_INFORMATION smi[1];
} SYSMODULELIST, *PSYSMODULELIST;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
 IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
 IN OUT PVOID SystemInformation,
 IN ULONG SystemInformationLength,
 OUT PULONG ReturnLength OPTIONAL);

#define SEC_IMAGE  0x1000000  
//獲取SSDT_函數服務號(CN)
ULONG GetFunctionId( char* FunctionName )
{
NTSTATUS ntstatus;
HANDLE hFile = NULL; 
HANDLE hSection = NULL ;
OBJECT_ATTRIBUTES object_attributes;
IO_STATUS_BLOCK io_status = {0};
PVOID baseaddress = NULL;
SIZE_T size = 0;
//模塊基址
PVOID ModuleAddress = NULL;
//偏移量
ULONG dwOffset = 0;

PIMAGE_DOS_HEADER dos = NULL;
PIMAGE_NT_HEADERS nt = NULL; 
PIMAGE_DATA_DIRECTORY expdir = NULL;
PIMAGE_EXPORT_DIRECTORY exports = NULL;

ULONG addr;
ULONG Size;

PULONG functions;
PSHORT ordinals;
PULONG names;

ULONG max_name;
ULONG max_func;
ULONG i;

ULONG pFunctionAddress;

ULONG ServiceId;

UNICODE_STRING DllName;
RtlInitUnicodeString( &DllName, L"\\SystemRoot\\system32\\ntdll.dll");
//初始化OBJECT_ATTRIBUTES結構
InitializeObjectAttributes( 
   &object_attributes,
   &DllName,
   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
   NULL,
   NULL);
//打開文件
ntstatus = ZwCreateFile(
   &hFile,
   FILE_EXECUTE | SYNCHRONIZE,
   &object_attributes,
   &io_status,
   NULL,
   FILE_ATTRIBUTE_NORMAL,
   FILE_SHARE_READ,
   FILE_OPEN,
   FILE_NON_DIRECTORY_FILE |
   FILE_RANDOM_ACCESS |
   FILE_SYNCHRONOUS_IO_NONALERT,
   NULL,
   0);
if( !NT_SUCCESS( ntstatus ))
{
   KdPrint(("[GetFunctionAddress] error0\n"));
   KdPrint(("[GetFunctionAddress] ntstatus = 0x%x\n", ntstatus));
   return 0;
}
//創建區段
InitializeObjectAttributes(
   &object_attributes,
   NULL,
   OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
   NULL,
   NULL);

ntstatus = ZwCreateSection(
   &hSection,
   SECTION_ALL_ACCESS,
   &object_attributes,
   0,
   PAGE_EXECUTE,
   SEC_IMAGE,
   hFile);
if( !NT_SUCCESS( ntstatus ))
{
   KdPrint(("[GetFunctionAddress] error1\n"));
   KdPrint(("[GetFunctionAddress] ntstatus = 0x%x\n", ntstatus));
   return 0;
}
//映射區段到進程虛擬空間
ntstatus = ZwMapViewOfSection(
   hSection,
   NtCurrentProcess(), //ntddk.h定義的宏用來獲取當前進程句柄
   &baseaddress,
   0,
   1000,
   0,
   &size,
   (SECTION_INHERIT)1,
   MEM_TOP_DOWN,
   PAGE_READWRITE);
if( !NT_SUCCESS( ntstatus ))
{
   KdPrint(("[GetFunctionAddress] error2\n"));
   KdPrint(("[GetFunctionAddress] ntstatus = 0x%x\n", ntstatus));
   return 0;
}
//得到模塊基址
dwOffset = ( ULONG )baseaddress;
//驗證基址
//KdPrint(("[GetFunctionAddress] BaseAddress:0x%x\n", dwOffset));
dos =(PIMAGE_DOS_HEADER) baseaddress; 
nt =(PIMAGE_NT_HEADERS)((ULONG) baseaddress + dos->e_lfanew);
expdir = (PIMAGE_DATA_DIRECTORY)(nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);

addr = expdir->VirtualAddress;//數據塊起始RVA
Size = expdir->Size;    //數據塊長度

exports =(PIMAGE_EXPORT_DIRECTORY)((ULONG) baseaddress + addr);

functions =(PULONG)((ULONG) baseaddress + exports->AddressOfFunctions);
ordinals =(PSHORT)((ULONG) baseaddress + exports->AddressOfNameOrdinals);
names =(PULONG)((ULONG) baseaddress + exports->AddressOfNames);

max_name =exports->NumberOfNames;
max_func =exports->NumberOfFunctions;


for (i = 0; i < max_name; i++)
{
   ULONG ord = ordinals[i];
   if(i >= max_name || ord >= max_func) 
   {
    return 0;
   }
   if (functions[ord] < addr || functions[ord] >= addr + Size)
   {
    if (strcmp((PCHAR) baseaddress + names[i], FunctionName) == 0)
    {
     pFunctionAddress =(ULONG)((ULONG) baseaddress + functions[ord]);
     break;
    }
   }
}


//KdPrint(("[GetFunctionAddress] %s:0x%x\n",FunctionName, pFunctionAddress));
ServiceId = *(PSHORT)(pFunctionAddress + 1);
//打印導出函數服務號
//KdPrint(("[GetServiceId] ServiceId:0x%x\n",ServiceId));
//卸載區段，釋放內存,關閉句柄
ZwUnmapViewOfSection( NtCurrentProcess(), baseaddress);
ZwClose( hSection);
ZwClose( hFile );
return ServiceId;
}

//根據內存基址，得到RVA對應的文件偏移地址
ULONG FindFileOffsetByRva( ULONG ModuleAddress,ULONG Rva)
{
  PIMAGE_DOS_HEADER dos;
  PIMAGE_FILE_HEADER file;
  PIMAGE_SECTION_HEADER section;
  //區塊數目
  ULONG number;
  ULONG i;
  ULONG minAddress;
  ULONG maxAddress;
  ULONG SeFileOffset;
  ULONG FileOffset;

  dos = (PIMAGE_DOS_HEADER)ModuleAddress;
  file = (PIMAGE_FILE_HEADER)( ModuleAddress + dos->e_lfanew + 4 );
  //得到區塊數量
  number = file->NumberOfSections;
 // KdPrint(("[FindFileOffsetByRva] number :0x%x\n",number));
  //得到第一個區塊地址
  section = (PIMAGE_SECTION_HEADER)(ModuleAddress + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + file->SizeOfOptionalHeader);
  for( i=0;i<number;i++)
  {
    minAddress = section[i].VirtualAddress;
    maxAddress = minAddress + section[i].SizeOfRawData;
    SeFileOffset = section[i].PointerToRawData;
    if( Rva > minAddress && Rva < maxAddress)
    {
    //  KdPrint(("[FindFileOffsetByRva] minAddress :0x%x\n",minAddress));
    //  KdPrint(("[FindFileOffsetByRva] SeFileOffset :0x%x\n",SeFileOffset));
      FileOffset = Rva - ( minAddress - SeFileOffset);
    //  KdPrint(("[FindFileOffsetByRva] FileOffset :0x%x\n",FileOffset));
      break ;
    }
  }
  return FileOffset;
}

//根據路徑解析出子進程名
VOID  GetModuleName( char *ProcessPath, char *ProcessName)
{
  ULONG n = strlen( ProcessPath) - 1;
  ULONG i = n;
//  KdPrint(("%d",n));
  while( ProcessPath[i] != '\\')
  {
    i = i-1;
  }
  strncpy( ProcessName, ProcessPath+i+1,n-i);
}

ULONG KerBaseAddress;
//根據傳入的服務號得到函數原始地址
ULONG FindOriAddress( ULONG index )
{
  //根據傳入的index得到函數VA地址
  //重定位函數地址
  //BaseAddress - 0x00400000 + *(PULONG)(FileOffset+(index*4))
  //ZwQuerySystemInformation得到內核文件基地址
  //得到SSDT表的地址
  //得到SSDT RVA 查找SSDT RVA所在的節
  NTSTATUS status;
  ULONG size;
  ULONG BaseAddress;
  ULONG SsdtRva;
  ULONG FileOffset = 0;

  PSYSMODULELIST list;
  char Name[32]={0};
  char PathName[256] = "\\SystemRoot\\system32\\";
  ANSI_STRING name;
  UNICODE_STRING modulename;

  OBJECT_ATTRIBUTES  object_attributes;
  IO_STATUS_BLOCK io_status = {0};
  HANDLE hFile;
  //讀取的位置
  ULONG location;
  LARGE_INTEGER offset;
  ULONG address;

  //得到需要申請的內存大小
  ZwQuerySystemInformation( SystemModuleInformation,&size,0,&size );
  //申請內存
  list = (PSYSMODULELIST) ExAllocatePool( NonPagedPool,size );
  //驗證是否申請成功
  if( list == NULL)
  {
    //申請失敗
    KdPrint(("malloc memory failed\n"));
    ExFreePool(list);
    return 0;
  }
  status = ZwQuerySystemInformation( SystemModuleInformation,list,size,0);
  if( !NT_SUCCESS( status ))
  {
    //獲取信息失敗
    KdPrint(("query failed\n"));
    KdPrint(("status:0x%x\n",status));
    ExFreePool(list);
    return 0;
  }
  //得到模塊基址,第一個模塊為內核文件
  BaseAddress = (ULONG )list->smi[0].Base;
  
  //分離出內核文件名
  GetModuleName(list->smi[0].ImageName,Name);
//  KdPrint(("[Kernel Name]: %s\n",Name));
//  KdPrint(("[%s Base Address]: %X\n",Name,BaseAddress));
  
  
  strcat(PathName,Name);
  RtlInitAnsiString(&name,PathName);
  RtlAnsiStringToUnicodeString(&modulename,&name,TRUE);
//  KdPrint(("[Module Path]: %wZ\n",&modulename));
  ExFreePool(list);
  
  //經驗證地址正確
  //得到SSDT表的Rva
  SsdtRva = (ULONG)KeServiceDescriptorTable.ServiceTableBase - BaseAddress;
  //驗證
//  KdPrint(("[SsdtRva of Ntos]: %x\n",SsdtRva));
  //根據RVA查找文件偏移,//得到文件偏移了
  FileOffset= FindFileOffsetByRva( BaseAddress,SsdtRva);
//  KdPrint(("[FileOffset]: %X\n",FileOffset));
  //讀取的位置
  location = FileOffset + index * 4;
  
  //傳出內核基址
  KerBaseAddress = BaseAddress;
  
  
  offset.QuadPart =location;
//  KdPrint(("[ZwReadFile In Par:8]: %x\n",location));
  //利用ZwReadFile讀取文件
  //初始化OBJECT_ATTRIBUTES結構
  InitializeObjectAttributes( 
    &object_attributes,
    &modulename,
    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
    NULL,
    NULL);
  //打開文件
  status = ZwCreateFile(
    &hFile,
    FILE_EXECUTE | SYNCHRONIZE,
    &object_attributes,
    &io_status,
    NULL,
    FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ,
    FILE_OPEN,
    FILE_NON_DIRECTORY_FILE |
    FILE_RANDOM_ACCESS |
    FILE_SYNCHRONOUS_IO_NONALERT,
    NULL,
    0);
  if( !NT_SUCCESS( status ))
  {
    KdPrint(("[Open Error]\n"));
    KdPrint(("status = 0x%x\n", status));
    ZwClose( hFile );
    return 0;
  }
  status = ZwReadFile(
    hFile,
    NULL,
    NULL,
    NULL,
    NULL,
    &address,
    sizeof(ULONG),
    &offset,
    NULL);
  if( !NT_SUCCESS( status ))
  {
    KdPrint(("[read error]\n"));
    KdPrint(("status = 0x%x\n", status));
    ZwClose( hFile );
    return 0;
  }
//  KdPrint(("[Address Offset]: %x\n",address));
  //重定位
  address = BaseAddress - 0x00400000 + address;
  //釋放動態分配的內存
  RtlFreeUnicodeString(&modulename);
  ZwClose( hFile );
  return address;
}

//根據傳入的ntos內存地址。查找ntos原始數據
ULONG  Find_CurAddr_OriData(ULONG Addr)
{
  NTSTATUS status;
  ULONG size;
  ULONG BaseAddress;
  ULONG SsdtRva;
  ULONG FileOffset = 0;

  PSYSMODULELIST list;
  char Name[32]={0};
  char PathName[256] = "\\SystemRoot\\system32\\";
  ANSI_STRING name;
  UNICODE_STRING modulename;

  OBJECT_ATTRIBUTES  object_attributes;
  IO_STATUS_BLOCK io_status = {0};
  HANDLE hFile;
  //讀取的位置
  ULONG location;
  LARGE_INTEGER offset;
  ULONG address;

  //得到需要申請的內存大小
  ZwQuerySystemInformation( SystemModuleInformation,&size,0,&size );
  //申請內存
  list = (PSYSMODULELIST) ExAllocatePool( NonPagedPool,size );
  //驗證是否申請成功
  if( list == NULL)
  {
    //申請失敗
    KdPrint(("malloc memory failed\n"));
    ExFreePool(list);
    return 0;
  }
  status = ZwQuerySystemInformation( SystemModuleInformation,list,size,0);
  if( !NT_SUCCESS( status ))
  {
    //獲取信息失敗
    KdPrint(("query failed\n"));
    KdPrint(("status:0x%x\n",status));
    ExFreePool(list);
    return 0;
  }
  //得到模塊基址,第一個模塊為內核文件
  BaseAddress = (ULONG )list->smi[0].Base;
  
  //分離出內核文件名
  GetModuleName(list->smi[0].ImageName,Name);
//  KdPrint(("[Kernel Name]: %s\n",Name));
//  KdPrint(("[%s Base Address]: %X\n",Name,BaseAddress));
  
  
  strcat(PathName,Name);
  RtlInitAnsiString(&name,PathName);
  RtlAnsiStringToUnicodeString(&modulename,&name,TRUE);
//  KdPrint(("[Module Path]: %wZ\n",&modulename));
  ExFreePool(list);
  
  //經驗證地址正確
  //得到SSDT表的Rva
  SsdtRva = Addr - BaseAddress;
  //驗證
  //KdPrint(("[Rva of Ntos]: %X\n",SsdtRva));
  //根據RVA查找文件偏移,//得到文件偏移了
  
  FileOffset= FindFileOffsetByRva( BaseAddress,SsdtRva);
  //KdPrint(("[FileOffset]: %X\n",FileOffset));
  //讀取的位置
  location = FileOffset;
  
  
  offset.QuadPart = location;
  //KdPrint(("[ZwReadFile In Par:8]: %X\n",offset.QuadPart));
  //利用ZwReadFile讀取文件
  //初始化OBJECT_ATTRIBUTES結構
  InitializeObjectAttributes( 
    &object_attributes,
    &modulename,
    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
    NULL,
    NULL);
  //打開文件
  status = ZwCreateFile(
    &hFile,
    FILE_EXECUTE | SYNCHRONIZE,
    &object_attributes,
    &io_status,
    NULL,
    FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ,
    FILE_OPEN,
    FILE_NON_DIRECTORY_FILE |
    FILE_RANDOM_ACCESS |
    FILE_SYNCHRONOUS_IO_NONALERT,
    NULL,
    0);
  if( !NT_SUCCESS( status ))
  {
    KdPrint(("[Open Error]\n"));
    KdPrint(("status = 0x%x\n", status));
    ZwClose( hFile );
    return 0;
  }
  status = ZwReadFile(
    hFile,
    NULL,
    NULL,
    NULL,
    NULL,
    &address,
    sizeof(ULONG),
    &offset,
    NULL);
  if( !NT_SUCCESS( status ))
  {
    KdPrint(("[read error]\n"));
    KdPrint(("status = 0x%x\n", status));
    ZwClose( hFile );
    return 0;
  }
  //KdPrint(("[Address Offset]: %X\n",address));


  //重定位
//  address = BaseAddress - 0x00400000 + address;
  //釋放動態分配的內存
  RtlFreeUnicodeString(&modulename);
  ZwClose( hFile );
  return address;
}

ULONG SystemVersion;//系統版本
//判斷系統版本
VOID InitCallNumber()
{
 ULONG majorVersion, minorVersion;
 PsGetVersion( &majorVersion, &minorVersion, NULL, NULL );

    if ( majorVersion == 5 && minorVersion == 0 )
    {
	  DbgPrint("comint32: Running on Windows 2000\n");
	  SystemVersion = 1;
	}
	else if ( majorVersion == 5 && minorVersion == 1 )
	{
	  DbgPrint("comint32: Running on Windows XP\n");
	  SystemVersion = 2;
	}
	else if ( majorVersion == 5 && minorVersion == 2 )
	{
	  DbgPrint("comint32: Running on Windows 2003\n");
      SystemVersion = 3;
	}
	else if ( majorVersion == 6 && minorVersion == 1 )
	{
	  DbgPrint("comint32: Running on Windows 7\n");
	  SystemVersion = 4;
	}

 else 
 {
 DbgPrint("comint32: Running on Unknow System\n");
 SystemVersion = 0;
 }
}

//確認遊戲是否訪問中
NTKERNELAPI
UCHAR *
PsGetProcessImageFileName(
__in PEPROCESS Process
);

BOOL GameExecutionCheck()
{
PUCHAR pszCurName;
PEPROCESS PE;
PE=PsGetCurrentProcess();
pszCurName=PsGetProcessImageFileName(PE);
if (_stricmp((const char*)pszCurName,"MapleStory.exe")==0)
{
//DbgPrint("<<<<<<<<<<<MapleStory.exe訪問中........");
return TRUE;
}
else
{
return FALSE;
}
}

//處理內存.鎖.讀寫開關
__declspec(naked) VOID __stdcall  WPOFF()
{
 __asm
 {
 cli                   //dissable interrupt
 push eax
 mov  eax,cr0          //move CR0 register into EAX
 and  eax,not 10000h   //disable WP bit
 mov  cr0,eax          //write register back
 pop  eax
 ret
 }
}

__declspec(naked) VOID __stdcall  WPON()
{
 __asm
 {
 push eax
 mov  eax,cr0         //move CR0 register into EAX
 or  eax,10000h       //enable WP bit
 mov  cr0,eax         //write register back
 pop  eax
 sti                  //enable interrupt
 ret
 }
}