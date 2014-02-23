/*------------------------------------------------------------------------
* 文件名稱 : NtReadVirtualMemory.h                                                 
* 編譯環境 : WDK 7600.16385.1
--------------------------------------------------------------------------
* File Name            : NtReadVirtualMemory.h 
* Building environment : WDK 7600.16385.1
-------------------------------------------------------------------------*/

ULONG NtReadVirtualMemory_CN;
ULONG NtReadVirtualMemory_Addr;
ULONG NtReadVirtualMemory_HookAddr;
UCHAR NtReadVirtualMemory_Hook_Org_Mem[5]={0x00,0x00,0x00,0x00,0x00};

ULONG MyNtReadVirtualMemory_JmpAddr;
ULONG MyNtReadVirtualMemoryCall;

ULONG NtReadVirtualMemory_Hook_Calc;
UCHAR NtReadVirtualMemory_Hook_Mem[5]={0xe9,0x00,0x00,0x00,0x00};

//////////////////////////////////////

__declspec(naked) NTSTATUS __stdcall MyNtReadVirtualMemory()
{
 __asm
 {
 _EMIT 0x90;
 _EMIT 0x90;
 _EMIT 0x90;
 _EMIT 0x90;
 _EMIT 0x90;
 }
  __asm
 {
 pushad
 pushf
 }
 if (GameExecutionCheck()) //HS會檢測Hook是否運作正常,不正常會跳 Error 0x10301.所以要把主程式設為黑名單
 {
 __asm
 {
 popf
 popad
 }
 __asm
 { 
 mov  eax,[MyNtReadVirtualMemory_JmpAddr]
 sub  eax,5 
 jmp  eax
 }
 }
 else
 {
 __asm
 {
 popf
 popad
 }
 __asm
  {
  call MyNtReadVirtualMemoryCall
  jmp  [MyNtReadVirtualMemory_JmpAddr] 
  }
 }
}

VOID NtReadVirtualMemory_Hook()
{
 //取得函數位子 Win7_x86 NtReadVirtualMemory序列號為 0x115
 //NtReadVirtualMemory_CN = 0x115;

//動態取得函數位子
 NtReadVirtualMemory_CN = GetFunctionId("NtReadVirtualMemory");
DbgPrint("[NtReadVirtualMemory_CN] : 0x%x\n",NtReadVirtualMemory_CN);
 NtReadVirtualMemory_Addr = FindOriAddress(NtReadVirtualMemory_CN);
DbgPrint("[NtReadVirtualMemory_Addr] : 0x%08X\n",NtReadVirtualMemory_Addr);

 //Jmp點
 MyNtReadVirtualMemory_JmpAddr = NtReadVirtualMemory_Addr + 0xC;
DbgPrint("[MyNtReadVirtualMemory_JmpAddr] : 0x%08X\n",MyNtReadVirtualMemory_JmpAddr);

 //Hook點
 NtReadVirtualMemory_HookAddr = NtReadVirtualMemory_Addr + 2;
DbgPrint("[NtReadVirtualMemory_HookAddr] : 0x%08X\n",NtReadVirtualMemory_HookAddr);

 //計算CALL
 MyNtReadVirtualMemoryCall = NtReadVirtualMemory_Addr + 8;
 MyNtReadVirtualMemoryCall = Find_CurAddr_OriData(MyNtReadVirtualMemoryCall); 
 MyNtReadVirtualMemoryCall = (ULONG)*((PULONG)MaxByte)-(ULONG)MyNtReadVirtualMemoryCall;   
 MyNtReadVirtualMemoryCall = MyNtReadVirtualMemory_JmpAddr-MyNtReadVirtualMemoryCall-0x1;  
DbgPrint("[MyNtReadVirtualMemoryCall] : 0x%08X\n",MyNtReadVirtualMemoryCall);

 //複製Hook點原始內容
 WPOFF();
 RtlCopyMemory (NtReadVirtualMemory_Hook_Org_Mem, (PVOID)NtReadVirtualMemory_HookAddr , 5);
 RtlCopyMemory((PVOID)MyNtReadVirtualMemory,NtReadVirtualMemory_Hook_Org_Mem,5); 
 WPON();
DbgPrint("[MyNtReadVirtualMemory] : 0x%08X\n",(PVOID)MyNtReadVirtualMemory);
 
 ////計算Jmp地址,並合成Jmp指令
 NtReadVirtualMemory_Hook_Calc = (PCHAR)MyNtReadVirtualMemory - (PCHAR)NtReadVirtualMemory_HookAddr - 5;
 RtlCopyMemory(NtReadVirtualMemory_Hook_Mem + 1,&NtReadVirtualMemory_Hook_Calc,4);

 //Hook
 WPOFF();
 RtlCopyMemory((PVOID)NtReadVirtualMemory_HookAddr,(PVOID)NtReadVirtualMemory_Hook_Mem,5);
 WPON();

 DbgPrint("NtReadVirtualMemory Hook Success!\n");

}

VOID NtReadVirtualMemory_UnHook()
{
  WPOFF();
  RtlCopyMemory((PVOID)NtReadVirtualMemory_HookAddr,NtReadVirtualMemory_Hook_Org_Mem,5);
  WPON(); 
  DbgPrint("NtReadVirtualMemory UnHook Success!\n");
}
