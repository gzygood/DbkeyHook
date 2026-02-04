// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <wincrypt.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <tchar.h>
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>  
#include <random>
#include <algorithm>

//x64汇编
#include "wrapper.h"


// 劫持mmmojo_64.dll -> mmmojo_64_true.dll
#pragma comment(linker, "/EXPORT:AppendMMSubProcessSwitchNative=mmmojo_64_true.AppendMMSubProcessSwitchNative,@1")
#pragma comment(linker, "/EXPORT:CreateMMMojoEnvironment=mmmojo_64_true.CreateMMMojoEnvironment,@2")
#pragma comment(linker, "/EXPORT:CreateMMMojoWriteInfo=mmmojo_64_true.CreateMMMojoWriteInfo,@3")
#pragma comment(linker, "/EXPORT:GetHandleVerifier=mmmojo_64_true.GetHandleVerifier,@4")
#pragma comment(linker, "/EXPORT:GetMMMojoReadInfoAttach=mmmojo_64_true.GetMMMojoReadInfoAttach,@5")
#pragma comment(linker, "/EXPORT:GetMMMojoReadInfoMethod=mmmojo_64_true.GetMMMojoReadInfoMethod,@6")
#pragma comment(linker, "/EXPORT:GetMMMojoReadInfoRequest=mmmojo_64_true.GetMMMojoReadInfoRequest,@7")
#pragma comment(linker, "/EXPORT:GetMMMojoReadInfoSync=mmmojo_64_true.GetMMMojoReadInfoSync,@8")
#pragma comment(linker, "/EXPORT:GetMMMojoWriteInfoAttach=mmmojo_64_true.GetMMMojoWriteInfoAttach,@9")
#pragma comment(linker, "/EXPORT:GetMMMojoWriteInfoRequest=mmmojo_64_true.GetMMMojoWriteInfoRequest,@10")
#pragma comment(linker, "/EXPORT:InitializeMMMojo=mmmojo_64_true.InitializeMMMojo,@11")
#pragma comment(linker, "/EXPORT:IsSandboxedProcess=mmmojo_64_true.IsSandboxedProcess,@12")
#pragma comment(linker, "/EXPORT:RemoveMMMojoEnvironment=mmmojo_64_true.RemoveMMMojoEnvironment,@13")
#pragma comment(linker, "/EXPORT:RemoveMMMojoReadInfo=mmmojo_64_true.RemoveMMMojoReadInfo,@14")
#pragma comment(linker, "/EXPORT:RemoveMMMojoWriteInfo=mmmojo_64_true.RemoveMMMojoWriteInfo,@15")
#pragma comment(linker, "/EXPORT:SendMMMojoWriteInfo=mmmojo_64_true.SendMMMojoWriteInfo,@16")
#pragma comment(linker, "/EXPORT:SetMMMojoConfiguration=mmmojo_64_true.SetMMMojoConfiguration,@17")
#pragma comment(linker, "/EXPORT:SetMMMojoEnvironmentCallbacks=mmmojo_64_true.SetMMMojoEnvironmentCallbacks,@18")
#pragma comment(linker, "/EXPORT:SetMMMojoEnvironmentInitParams=mmmojo_64_true.SetMMMojoEnvironmentInitParams,@19")
#pragma comment(linker, "/EXPORT:SetMMMojoWriteInfoMessagePipe=mmmojo_64_true.SetMMMojoWriteInfoMessagePipe,@20")
#pragma comment(linker, "/EXPORT:SetMMMojoWriteInfoResponseSync=mmmojo_64_true.SetMMMojoWriteInfoResponseSync,@21")
#pragma comment(linker, "/EXPORT:ShutdownMMMojo=mmmojo_64_true.ShutdownMMMojo,@22")
#pragma comment(linker, "/EXPORT:StartMMMojoEnvironment=mmmojo_64_true.StartMMMojoEnvironment,@23")
#pragma comment(linker, "/EXPORT:StopMMMojoEnvironment=mmmojo_64_true.StopMMMojoEnvironment,@24")
#pragma comment(linker, "/EXPORT:SwapMMMojoWriteInfoCallback=mmmojo_64_true.SwapMMMojoWriteInfoCallback,@25")
#pragma comment(linker, "/EXPORT:SwapMMMojoWriteInfoMessage=mmmojo_64_true.SwapMMMojoWriteInfoMessage,@26")

extern "C" uint64_t HijackLogic(uint64_t key_class);    //劫持逻辑
extern "C" uint64_t g_imgbase = 0;                      //Weixin.dll的基址
extern "C" uint64_t g_hook_offset = 0;                  //要hook的偏移
extern "C" uint8_t * g_transfer_zone = 0;                //中转指令内存

struct OrgInfo
{
    uint64_t     addr;              //地址
    size_t      org_size;           //原始机器码长度
    uint8_t     org_opcodes[256];   //被HOOK之前原始的机器码
};
std::vector<OrgInfo> g_org_info;

void OutputDebugPrintf(const char* strOutputString, ...)
{
#define OUT_DEBUG_BUF_LEN   512
    char strBuffer[OUT_DEBUG_BUF_LEN] = { 0 };
    va_list vlArgs;
    va_start(vlArgs, strOutputString);
    _vsnprintf_s(strBuffer, sizeof(strBuffer) - 1, strOutputString, vlArgs);  //_vsnprintf_s  _vsnprintf
    va_end(vlArgs);
    OutputDebugStringA(strBuffer);  //OutputDebugString    // OutputDebugStringW
}


std::string toHexString(const uint8_t* data, size_t size) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

/**
 * @brief 恢复HOOK写入的字节.
 */
void HookEnd(uint8_t type)
{
    //写入原机器码
    if (g_org_info.size() != 0) {
        for (auto& org_info : g_org_info)
        {
            if (org_info.addr == 0) {
                OutputDebugString(TEXT("[DbkeyHook] Hook Addr is 0"));
                continue;
            }
            BOOL bRet = WriteProcessMemory(GetCurrentProcess(), (LPVOID)org_info.addr, org_info.org_opcodes, org_info.org_size, NULL);
            if (bRet == NULL)
                OutputDebugPrintf("[DbkeyHook] Write Hook Org Bytes Failed! [%d]", GetLastError());
        }
    }
    if (type == 2) {
        if (g_transfer_zone) {
            if (!VirtualFree(g_transfer_zone, 0, MEM_RELEASE)) {
                OutputDebugPrintf("[DbkeyHook] Free Transfer Mem Failed! [%d]", GetLastError());
                return;
            }
        }
    }
}


uint64_t HijackLogic(uint64_t struct_addr) 
{
    if (!struct_addr) return 0;

    uint64_t key_class = struct_addr;
    uint64_t Dbkey_addr_offset = key_class + 0x08, DbkeyAddr = 0;


    BOOL bReadPtr = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)Dbkey_addr_offset, &DbkeyAddr, 8, NULL);

    if (!bReadPtr || !DbkeyAddr)
    {
        OutputDebugPrintf("[DbkeyHook] Failed to read RealKey Pointer or Pointer is NULL!");
        return 0;
    }

    uint8_t db_key[32];
    BOOL bReadKey = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)DbkeyAddr, db_key, 32, NULL);

    if (!bReadKey)
    {
        OutputDebugPrintf("[DbkeyHook] Read RealKey Bytes Failed! LastError: [%d]", GetLastError());
        return 0;
    }

    std::string db_key_Str = toHexString(db_key, sizeof(db_key));
    OutputDebugPrintf("[DbkeyHook] SUCCESS! Real Key: [%s]", db_key_Str.c_str());

    HookEnd(1); // 写微信安装目录很可能不成功，但是并不代表hook失败了！！  卸载指令

    std::ofstream file("dbkey.txt");
    if (file.is_open())
    {
        file << db_key_Str;
        file.close();
        OutputDebugPrintf("[DbkeyHook] Write RealKey to dbkey.txt Success.");
    }
    else
    {
        OutputDebugPrintf("[DbkeyHook] Write dbkey.txt Failed! LastError: [%d]", GetLastError());
    }

    return 0;
}


void HookStart(HMODULE hModule)
{
    HMODULE weixin_dll_base = GetModuleHandle(_T("Weixin.dll"));
    if (weixin_dll_base == NULL)
    {
        OutputDebugPrintf("[DbkeyHook] Get Weixin.dll's ImgBase Failed! [%d]", GetLastError());
        return;
    }
    g_imgbase = (uint64_t)weixin_dll_base;
	g_hook_offset = 0x05325CC;// 这个是4.1.7.30的        4.0.3.43 = 0x0BC91A6    4.0.5.13=0xC0CC76   4.0.6.17=0xCF1F16   4.0.5.7=0x0C0A9A6

    //读取Hook点原机器码
    uint64_t hook_addr = g_imgbase + g_hook_offset;
    uint8_t hook_opcode[] = {/*mov rax, 地址*/0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*jmp rax*/0xFF, 0xE0, /*NOP 对齐13字节*/0x90};
    size_t hook_size = sizeof(hook_opcode); //13个字节

    OrgInfo hook_org_info;// 记录原始字节信息
    hook_org_info.addr = hook_addr;         //记录地址
    hook_org_info.org_size = hook_size;     //记录要写多少个字节
    BOOL bRet = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)hook_addr, hook_org_info.org_opcodes, hook_size, NULL);
    if (!bRet)
    {
        OutputDebugPrintf("[DbkeyHook] Read Hook Org Bytes Failed! [%d]", GetLastError());
        return;
    }
    g_org_info.push_back(hook_org_info); //记录

  

    //构造中转区机器码 原指令 + jmp far
    size_t org_insns_len = hook_size;  //暂时先写死
    g_transfer_zone = (uint8_t*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_transfer_zone) {
        OutputDebugPrintf("[DbkeyHook] Alloc Transfer Mem Failed! [%d]", GetLastError());
        return;
    }

    bRet = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)hook_addr, g_transfer_zone, org_insns_len, NULL);
    if (!bRet)
    {
        OutputDebugPrintf("[DbkeyHook] Read Transfer Zone Org Bytes Failed! [%d]", GetLastError());
        return;
    }

    uint8_t jmp_org_opcode[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x90 };
    uint64_t next_insn_addr = hook_addr + org_insns_len;
    for (size_t i = 0; i < sizeof(uint64_t); i++) //跳回去
        jmp_org_opcode[i + 2] = *((uint8_t*)(&next_insn_addr) + i);
    memcpy(g_transfer_zone + org_insns_len, jmp_org_opcode, sizeof(jmp_org_opcode));
    OutputDebugPrintf("[DbkeyHook] g_transfer_zone Addr: 0x%llX", g_transfer_zone);



    //写入劫持机器码 跳转到HijackLogicWarpper函数处
    uint64_t hijacklogic_addr = (uint64_t)(&HijackLogicWarpper);
    for (size_t i = 0; i < sizeof(uint64_t); i++)
    {
        hook_opcode[i + 2] = *((uint8_t*)(&hijacklogic_addr) + i);
    }
    bRet = WriteProcessMemory(GetCurrentProcess(), (LPVOID)hook_addr, hook_opcode, hook_size, NULL);
    if (bRet == NULL)
    {
        OutputDebugPrintf("[DbkeyHook] Write Hook Bytes Failed! [%d]", GetLastError());
        return;
    }


}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule); //防止多次调用
        //不知道为什么不会自动加载mmmojo_64_true.dll 直接手动加载
        OutputDebugPrintf("[DbkeyHook] Load mmmojo_64_true.dll: 0x%llX", LoadLibrary(TEXT("mmmojo_64_true.dll")));
        OutputDebugString(TEXT("[DbkeyHook] Begin Hook and Hijack!"));
        HookStart(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        OutputDebugString(TEXT("[DbkeyHook] Restore Hook Bytes!"));
        HookEnd(2);
        break;
    }
    return TRUE;
}

