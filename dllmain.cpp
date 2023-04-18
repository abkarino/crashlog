// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"

#include <Windows.h>
#include <Dbghelp.h>
#include <string>
#include <fstream>

void make_minidump(EXCEPTION_POINTERS* e)
{
    auto hDbgHelp = LoadLibraryA("dbghelp");
    if (hDbgHelp == nullptr)
        return;
    auto pMiniDumpWriteDump = (decltype(&MiniDumpWriteDump))GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (pMiniDumpWriteDump == nullptr)
        return;

    char name[MAX_PATH];
    {
        auto nameEnd = name + GetModuleFileNameA(GetModuleHandleA(0), name, MAX_PATH);
        SYSTEMTIME t;
        GetSystemTime(&t);
        wsprintfA(nameEnd - strlen(".exe"),
            "_%4d%02d%02d_%02d%02d%02d.dmp",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    }

    auto hFile = CreateFileA(name, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    MINIDUMP_EXCEPTION_INFORMATION exceptionInfo;
    exceptionInfo.ThreadId = GetCurrentThreadId();
    exceptionInfo.ExceptionPointers = e;
    exceptionInfo.ClientPointers = FALSE;

    auto dumped = pMiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hFile,
        MINIDUMP_TYPE(MiniDumpNormal),
        //MINIDUMP_TYPE(MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory),
        e ? &exceptionInfo : nullptr,
        nullptr,
        nullptr);

    CloseHandle(hFile);

    return;
}

void printStack(LPEXCEPTION_POINTERS e)
{
    auto hDbgHelp = LoadLibraryA("dbghelp");
    if (hDbgHelp == nullptr)
        return;
    auto pSymInitialize = (decltype(&SymInitialize))GetProcAddress(hDbgHelp, "SymInitialize");
    auto pStackWalk64 = (decltype(&StackWalk64))GetProcAddress(hDbgHelp, "StackWalk64");
    auto pSymFunctionTableAccess64 = (decltype(&SymFunctionTableAccess64))GetProcAddress(hDbgHelp, "SymFunctionTableAccess64");
    auto pSymGetModuleBase64 = (decltype(&SymGetModuleBase64))GetProcAddress(hDbgHelp, "SymGetModuleBase64");
    auto pSymGetModuleInfo64 = (decltype(&SymGetModuleInfo64))GetProcAddress(hDbgHelp, "SymGetModuleInfo64");
    auto pSymGetSymFromAddr64 = (decltype(&SymGetSymFromAddr64))GetProcAddress(hDbgHelp, "SymGetSymFromAddr64");

    //outfile << std::hex << hDbgHelp << " " << pStackWalk64 << " " << pSymFunctionTableAccess64 << " " << pSymGetModuleBase64 << " " << pSymGetModuleInfo64;

    char name[MAX_PATH];
    {
        auto nameEnd = name + GetModuleFileNameA(GetModuleHandleA(0), name, MAX_PATH);
        SYSTEMTIME t;
        GetSystemTime(&t);
        wsprintfA(nameEnd - strlen(".exe"),
            "_crashlog_%4d%02d%02d_%02d%02d%02d.txt",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    }
    std::ofstream out(name, std::ios::out | std::ios::app);
    ////outfile << "\nfile name " << name << "\n";
    //auto hFile = CreateFileA(name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    ////outfile << GetLastError();
    ////outfile << " file created " << hFile << "\n";
    //if (hFile == INVALID_HANDLE_VALUE)
    //    return;

    //std::string exceptionInfo;
    char buff[1024];

    out << "<Exception.Assertion:>\n";
    //exceptionInfo.append("<Exception.Assertion:>\n");

    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    snprintf(buff, sizeof(buff), "Thread 0x%04x\n", GetCurrentThreadId());
    out << buff;
    //exceptionInfo.append(buff);

    bool result = pSymInitialize(process, NULL, TRUE);

    STACKFRAME64        stack;
    PCONTEXT            ctx = e->ContextRecord;
    CONTEXT             ctxCopy;
    memcpy(&ctxCopy, ctx, sizeof(CONTEXT));

    ZeroMemory(&stack, sizeof(STACKFRAME64));
    stack.AddrPC.Offset = (*ctx).Eip;
    stack.AddrPC.Mode = AddrModeFlat;
    stack.AddrStack.Offset = (*ctx).Esp;
    stack.AddrStack.Mode = AddrModeFlat;
    stack.AddrFrame.Offset = (*ctx).Ebp;
    stack.AddrFrame.Mode = AddrModeFlat;

    char moduleName[MAX_PATH] = {0};
    IMAGEHLP_MODULE64 moduleInfo;

    while (pStackWalk64(
        IMAGE_FILE_MACHINE_I386,
        process,
        thread,
        &stack,
        &ctxCopy,
        NULL,
        pSymFunctionTableAccess64,
        pSymGetModuleBase64,
        NULL))
    {
        ZeroMemory(&moduleInfo, sizeof(moduleInfo));
        moduleInfo.SizeOfStruct = sizeof(moduleInfo);
        bool result = pSymGetModuleInfo64(process, stack.AddrPC.Offset, &moduleInfo);
        /*if (!result) {
            pSymGetSymFromAddr64
            result = pSymGetModuleInfo64(process, stack.AddrPC.Offset, &ModuleInfo);
        }*/
        /*HMODULE hModule = NULL;
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCTSTR)(stack.AddrPC.Offset), &hModule);
        if (hModule != NULL) GetModuleFileNameA(hModule, module, MAX_PATH);*/

        if (result) {
            snprintf(buff, sizeof(buff), "DBG-ADDR<%08llX><RVA:%08llX>(\"%s\")\n", stack.AddrPC.Offset, stack.AddrPC.Offset - moduleInfo.BaseOfImage, moduleInfo.ModuleName);
        }
        else {
            snprintf(buff, sizeof(buff), "DBG-ADDR<%08llX>\n", stack.AddrPC.Offset);
        }
        out << buff;
        //exceptionInfo.append(buff);
    }

    out << "<:Exception.Assertion>\n";
    //exceptionInfo.append("<:Exception.Assertion>\n");

    //out << exceptionInfo;
    out.close();
    //WriteFile(
    //    hFile,                // open file handle
    //    exceptionInfo.data(),      // start of data to write
    //    exceptionInfo.length(),  // number of bytes to write
    //    NULL, // number of bytes that were written
    //    NULL);
}

LONG CALLBACK unhandled_handler(EXCEPTION_POINTERS* e)
{
    make_minidump(e);
    printStack(e);
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        SetUnhandledExceptionFilter(unhandled_handler);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

