#include <Windows.h>
#include <string>
#include <iostream>

// Warning don't use this for you're p2c.
int IsDebuggerPresent(int argc, char** argv)
{
    //! Recall IsDebuggerPresent will return 0 if one wasn't found
    if (IsDebuggerPresent())
    {
        MessageBoxA(NULL, "There is currently a debugger attached to the process.", "Error: Debugger", MB_OK);
    }
    else
    {
        MessageBoxA(NULL, "No debugger detected.", "Debugger", MB_OK);
    }
    return 0;
}

int main()
{
    //! Windows types suck. You could make a std::wchar and convert it with .c_str()
    LPCWSTR windowName = L"x64dbg"; //! Window name of the debugger you are checking for
    //! LPCWSTR windowName = L"OllyDbg, IDA Pro, etc";

    //! Recall that FindWindow will return NULL if it wasn't found
    if (FindWindow(NULL, windowName))
    {
        MessageBoxA(NULL, "Debugger Found", "Notification", MB_OK);
    }
    return 0;
}
/* 

0:000 < u kernelbase!IsDebuggerPresent L3
    KERNELBASE!IsDebuggerPresent :
    751ca8d0 64a130000000    mov     eax, dword ptr fs : [00000030h]
    751ca8d6 0fb64002        movzx   eax, byte ptr[eax + 2]
    751ca8da c3              ret

*/


// Current PEB for 64bit and 32bit processes accordingly
PVOID GetPEB()
{
#ifdef _WIN64
    return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
    return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}
// Get PEB for WOW64 Process
PVOID GetPEB64()
{
    PVOID pPeb = 0;
#ifndef _WIN64
    // 1. There are two copies of PEB - PEB64 and PEB32 in WOW64 process
    // 2. PEB64 follows after PEB32
    // 3. This is true for versions lower than Windows 8, else __readfsdword returns address of real PEB64
    if (IsWow64Process);
    {
        BOOL isWow64 = FALSE;
        typedef BOOL(WINAPI* pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
        pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
            GetProcAddress(GetModuleHandleA("Kernel32.dll"), "IsWow64Process");
        if (fnIsWow64Process(GetCurrentProcess(), &isWow64))
        {
            if (isWow64)
            {
                pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
                pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
            }
        }
    }
#endif
    return pPeb;
}
int Blacklist(int argc, char** argv)
{
wchar_t const name[] = L"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\GlobalFlag]";
}
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
void CheckNtGlobalFlag()
{
    PVOID pPeb = GetPEB();
    PVOID pPeb64 = GetPEB64();
    DWORD offsetNtGlobalFlag = 0;
#ifdef _WIN64
    offsetNtGlobalFlag = 0xBC;
#else
    offsetNtGlobalFlag = 0x68;
#endif
    DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
    if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    if (pPeb64)
    {
        DWORD NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xBC);
        if (NtGlobalFlagWow64 & NT_GLOBAL_FLAG_DEBUGGED)
        {
            std::cout << "Stop debugging program!" << std::endl;
            exit(-1);
        }
    }
}
PIMAGE_NT_HEADERS GetImageNtHeaders(PBYTE pImageBase)
{
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    return (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);
}
PIMAGE_SECTION_HEADER FindRDataSection(PBYTE pImageBase)
{
    static const std::string rdata = ".rdata";
    PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
    PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
    int n = 0;
    for (; n < pImageNtHeaders->FileHeader.NumberOfSections; ++n)
    {
        if (rdata == (char*)pImageSectionHeader[n].Name)
        {
            break;
        }
    }
    return &pImageSectionHeader[n];
}
void CheckGlobalFlagsClearInProcess()
{
    PBYTE pImageBase = (PBYTE)GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
    PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pImageBase
        + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
}
void CheckGlobalFlagsClearInFile()
{
    HANDLE hExecutable = INVALID_HANDLE_VALUE;
    HANDLE hExecutableMapping = NULL;
    PBYTE pMappedImageBase = NULL;
    __try
    {
        PBYTE pImageBase = (PBYTE)GetModuleHandle(NULL);
        PIMAGE_SECTION_HEADER pImageSectionHeader = FindRDataSection(pImageBase);
        TCHAR pszExecutablePath[MAX_PATH];
        DWORD dwPathLength = GetModuleFileName(NULL, pszExecutablePath, MAX_PATH);
        if (0 == dwPathLength) __leave;
        hExecutable = CreateFile(pszExecutablePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (INVALID_HANDLE_VALUE == hExecutable) __leave;
        hExecutableMapping = CreateFileMapping(hExecutable, NULL, PAGE_READONLY, 0, 0, NULL);
        if (NULL == hExecutableMapping) __leave;
        pMappedImageBase = (PBYTE)MapViewOfFile(hExecutableMapping, FILE_MAP_READ, 0, 0,
            pImageSectionHeader->PointerToRawData + pImageSectionHeader->SizeOfRawData);
        if (NULL == pMappedImageBase) __leave;
        PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pMappedImageBase);
        PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pMappedImageBase
            + (pImageSectionHeader->PointerToRawData
                + (pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress - pImageSectionHeader->VirtualAddress)));
        if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
        {
            std::cout << "Stop debugging program!" << std::endl;
            exit(-1);
        }
    }
    __finally
    {
        if (NULL != pMappedImageBase)
            UnmapViewOfFile(pMappedImageBase);
        if (NULL != hExecutableMapping)
            CloseHandle(hExecutableMapping);
        if (INVALID_HANDLE_VALUE != hExecutable)
            CloseHandle(hExecutable);
    }
}




int main(int argc, char* argv[])
{
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent))
    {
        if (isDebuggerPresent)
        {
            std::cout << "Stop debugging program!" << std::endl;
            exit(-1);
        }
    }
    return 0;
}

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    _In_      HANDLE           ProcessHandle,
    _In_      UINT             ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
    );
const UINT ProcessDebugPort = 7;
int main(int argc, char* argv[])
{
    pfnNtQueryInformationProcess NtQueryInformationProcess = NULL;
    NTSTATUS status;
    DWORD isDebuggerPresent = 0;
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));

    if (NULL != hNtDll)
    {
        NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        if (NULL != NtQueryInformationProcess)
        {
            status = NtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &isDebuggerPresent,
                sizeof(DWORD),
                NULL);
            if (status == 0x00000000 && isDebuggerPresent != 0)
            {
                std::cout << "Stop debugging program!" << std::endl;
                exit(-1);
            }
        }
    }
    return 0;
}

DWORD CalcFuncCrc(PUCHAR funcBegin, PUCHAR funcEnd)
{
    DWORD crc = 0;
    for (; funcBegin < funcEnd; ++funcBegin)
    {
        crc += *funcBegin;
    }
    return crc;
}
#pragma auto_inline(off)
VOID DebuggeeFunction()
{
    int calc = 0;
    calc += 2;
    calc <<= 8;
    calc -= 3;
}
VOID DebuggeeFunctionEnd()
{
};
#pragma auto_inline(on)
DWORD g_origCrc = 0x2bd0;
int main()
{
    DWORD crc = CalcFuncCrc((PUCHAR)DebuggeeFunction, (PUCHAR)DebuggeeFunctionEnd);
    if (g_origCrc != crc)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    return 0;
}

BOOL g_isDebuggerPresent = TRUE;
EXCEPTION_DISPOSITION ExceptionRoutine(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID             EstablisherFrame,
    PCONTEXT          ContextRecord,
    PVOID             DispatcherContext)
{
    g_isDebuggerPresent = FALSE;
    ContextRecord->Eip += 1;
    return ExceptionContinueExecution;
}
int main()
{
    __asm
    {
        // set SEH handler
        push ExceptionRoutine
        push dword ptr fs : [0]
        mov  dword ptr fs : [0] , esp
        // generate interrupt
        int  3h
        // return original SEH handler
        mov  eax, [esp]
        mov  dword ptr fs : [0] , eax
        add  esp, 8
    }
    if (g_isDebuggerPresent)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    return 0;
}

PVOID WINAPI AddVectoredExceptionHandler(
    ULONG                       FirstHandler,
    PVECTORED_EXCEPTION_HANDLER VectoredHandler
);
ULONG WINAPI RemoveVectoredExceptionHandler(
    PVOID Handler
);
LONG CALLBACK VectoredHandler(
    PEXCEPTION_POINTERS ExceptionInfo
);

LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    ctx->Eip += 2;
    return EXCEPTION_CONTINUE_EXECUTION;
}
int main()
{
    AddVectoredExceptionHandler(0, ExceptionHandler);
    __asm int 1h;
    return 0;
}

typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG  ThreadInformationClass,
    _In_ PVOID  ThreadInformation,
    _In_ ULONG  ThreadInformationLength
    );
const ULONG ThreadHideFromDebugger = 0x11;
void HideFromDebugger()
{
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    pfnNtSetInformationThread NtSetInformationThread = (pfnNtSetInformationThread)
        GetProcAddress(hNtDll, "NtSetInformationThread");
    NTSTATUS status = NtSetInformationThread(GetCurrentThread(),
        ThreadHideFromDebugger, NULL, 0);
}
EXCEPTION_DISPOSITION ExceptionRoutine(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID             EstablisherFrame,
    PCONTEXT          ContextRecord,
    PVOID             DispatcherContext)
{
    if (EXCEPTION_INVALID_HANDLE == ExceptionRecord->ExceptionCode)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    return ExceptionContinueExecution;
}

int main()
{
    __asm
    {
        // set SEH handler
        push ExceptionRoutine
        push dword ptr fs : [0]
        mov  dword ptr fs : [0] , esp
    }
    CloseHandle((HANDLE)0xBAAD);
    __asm
    {
        // return original SEH handler
        mov  eax, [esp]
        mov  dword ptr fs : [0] , eax
        add  esp, 8
    }
    return 0;
}
__asm
{
    push ss
    pop  ss
    mov  eax, 0xC000C1EE // This line will be traced over by debugger
    xor edx, edx        // Debugger will step to this line
}
