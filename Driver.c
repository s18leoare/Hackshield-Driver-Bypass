/*------------------------------------------------------------------------
* 文件名稱 : Driver.c                                                 
* 編譯環境 : WDK 7600.16385.1
/-------------------------------------------------------------------------
* File Name            : Driver.c
* Building environment : WDK 7600.16385.1
-------------------------------------------------------------------------*/

#include <ntddk.h>
#include <Function.h>
#include <NtOpenProcess.h>
#include <NtOpenProcess_Win7.h>
#include <NtReadVirtualMemory.h>
#include <NtWriteVirtualMemory.h>
#include <NtProtectVirtualMemory.h>
///////////////////////////////////////////////////
VOID OnUnload(IN PDRIVER_OBJECT DriverObject);
///////////////////////////////////////////////////
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 NTSTATUS status = STATUS_SUCCESS; 
 DriverObject->DriverUnload = OnUnload;
//DbgPrint("Driver Powered By Vip235689!\n");
 DbgPrint("Driver Load!\n");
 InitCallNumber();
//DbgPrint("[SystemVersion] : 0x%x\n",SystemVersion);

 if (SystemVersion == 2) //WinXp
 {
 NtOpenProcess_Hook();
 NtReadVirtualMemory_Hook();
 NtWriteVirtualMemory_Hook();
 NtProtectVirtualMemory_Hook();

 return status;
 }
 else if (SystemVersion == 4) //Win7
 {
 NtOpenProcess_Win7_Hook();
 NtReadVirtualMemory_Hook();
 NtWriteVirtualMemory_Hook();
 NtProtectVirtualMemory_Hook();

 return status;
 }

else
{
 DbgPrint("System Not Support! Driver Fail!!\n");
 return status;
}

}
/////////////////////////////////////////////////////
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
 if (SystemVersion == 2) //WinXp
 {
 NtOpenProcess_UnHook();
 NtReadVirtualMemory_UnHook();
 NtWriteVirtualMemory_UnHook();
 NtProtectVirtualMemory_UnHook();

 }
 else if (SystemVersion == 4) //Win7
 {
 NtOpenProcess_Win7_UnHook();
 NtReadVirtualMemory_UnHook();
 NtWriteVirtualMemory_UnHook();
 NtProtectVirtualMemory_UnHook();

 }

else
{
 //
}
 DbgPrint("Driver UnLoad!\n");
}
/////////////////////////////////////////////////////
