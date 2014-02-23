/*------------------------------------------------------------------------
* 文件名稱 : Driver.h                                                   
* 編譯環境 : WDK 7600.16385.1
/-------------------------------------------------------------------------
* File Name            : Driver.c
* Building environment : WDK 7600.16385.1
-------------------------------------------------------------------------*/

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#include <NTDDK.h>
#ifdef __cplusplus
}
#endif 

#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()
#define INITCODE code_seg("INIT")

#define PAGEDDATA data_seg("PAGE")
#define LOCKEDDATA data_seg()
#define INITDATA data_seg("INIT")

#define arraysize(p) (sizeof(p)/sizeof((p)[0]))

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;	//設備名稱
	UNICODE_STRING ustrSymLinkName;	//符號鏈接名
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// 函數聲明

NTSTATUS CreateDevice (IN PDRIVER_OBJECT pDriverObject);
VOID HelloDDKUnload (IN PDRIVER_OBJECT pDriverObject);
NTSTATUS HelloDDKDispatchRoutine(IN PDEVICE_OBJECT pDevObj,
								 IN PIRP pIrp);