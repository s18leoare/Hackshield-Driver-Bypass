/*------------------------------------------------------------------------
* 文件名稱 : NtOpenProcess.h                                                 
* 編譯環境 : WDK 7600.16385.1
/-------------------------------------------------------------------------
* File Name            : NtOpenProcess.h 
* Building environment : WDK 7600.16385.1
-------------------------------------------------------------------------*/

ULONG NtOpenProcess_CN;
ULONG NtOpenProcess_Addr;
ULONG NtOpenProcess_HookAddr;
UCHAR NtOpenProcess_Hook_Org_Mem[5]={0x00,0x00,0x00,0x00,0x00};

ULONG MyNtOpenProcess_JmpAddr;
ULONG MyNtOpenProcessCall;

ULONG NtOpenProcess_Hook_Calc;
UCHAR NtOpenProcess_Hook_Mem[5]={0xe9,0x00,0x00,0x00,0x00};

//////////////////////////////////////

__declspec(naked) NTSTATUS __stdcall MyNtOpenProcess()
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
 mov  eax,[MyNtOpenProcess_JmpAddr]
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
  call MyNtOpenProcessCall
  jmp  [MyNtOpenProcess_JmpAddr] 
  }
 }
}

VOID NtOpenProcess_Hook()
{
 //取得函數位子 WinXp_x86 NtOpenProcess序列號為 0x7A
 //NtOpenProcess_CN = 0x7A;

//動態取得函數位子
 NtOpenProcess_CN = GetFunctionId("NtOpenProcess");
DbgPrint("[NtOpenProcess_CN] : 0x%x\n",NtOpenProcess_CN);
 NtOpenProcess_Addr = FindOriAddress(NtOpenProcess_CN);
DbgPrint("[NtOpenProcess_Addr] : 0x%08X\n",NtOpenProcess_Addr);


 //Jmp點
 MyNtOpenProcess_JmpAddr = NtOpenProcess_Addr + 0xF;
DbgPrint("[MyNtOpenProcess_JmpAddr] : 0x%08X\n",MyNtOpenProcess_JmpAddr);

 //Hook點
 NtOpenProcess_HookAddr = NtOpenProcess_Addr + 0x5;
DbgPrint("[NtOpenProcess_HookAddr] : 0x%08X\n",NtOpenProcess_HookAddr);

 //計算CALL
 MyNtOpenProcessCall = NtOpenProcess_Addr + 0xB;
 MyNtOpenProcessCall = Find_CurAddr_OriData(MyNtOpenProcessCall); 
 MyNtOpenProcessCall = (ULONG)*((PULONG)MaxByte)-(ULONG)MyNtOpenProcessCall;   
 MyNtOpenProcessCall = MyNtOpenProcess_JmpAddr-MyNtOpenProcessCall-0x1;  
DbgPrint("[MyNtOpenProcessCall] : 0x%08X\n",MyNtOpenProcessCall);

 //複製Hook點原始內容
 WPOFF();
 RtlCopyMemory (NtOpenProcess_Hook_Org_Mem, (PVOID)NtOpenProcess_HookAddr , 5);
 RtlCopyMemory((PVOID)MyNtOpenProcess,NtOpenProcess_Hook_Org_Mem,5); 
 WPON();
DbgPrint("[MyNtOpenProcess] : 0x%08X\n",(PVOID)MyNtOpenProcess);
 
 ////計算Jmp地址,並合成Jmp指令
 NtOpenProcess_Hook_Calc = (PCHAR)MyNtOpenProcess - (PCHAR)NtOpenProcess_HookAddr - 5;
 RtlCopyMemory(NtOpenProcess_Hook_Mem + 1,&NtOpenProcess_Hook_Calc,4);

 //Hook
 WPOFF();
 RtlCopyMemory((PVOID)NtOpenProcess_HookAddr,(PVOID)NtOpenProcess_Hook_Mem,5);
 WPON();

 DbgPrint("NtOpenProcess Hook Success!\n");

}

VOID NtOpenProcess_UnHook()
{
  WPOFF();
  RtlCopyMemory((PVOID)NtOpenProcess_HookAddr,NtOpenProcess_Hook_Org_Mem,5);
  WPON(); 
  DbgPrint("NtOpenProcess UnHook Success!\n");
}

