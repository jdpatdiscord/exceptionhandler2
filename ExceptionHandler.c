#include "ExceptionHandler.h"
#include <DbgHelp.h>
#include <processthreadsapi.h>

T_GetEnabledXStateFeatures F_GetEnabledXStateFeatures = NULL;
T_LocateXStateFeature F_LocateXStateFeature = NULL;

struct CallStackEntry g_CallStackEntries[192] = { };
unsigned g_CallStackEntryPtr = 0;

uintptr_t g_GPRegisterTable[16] = { 0 }; // rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r9, r10, r11, r12, r13, r14, r15, rip (CONTEXT layout)
float_t g_FPRegisterTable[512] = { 0.0f }; // zmm0 - zmm31 (includes xmm, ymm)

char ReportPrintBuffer[20480] = { 0 };
unsigned ReportPrintPointer = 0;

char TmpStringBuffer[10240] = { 0 };
unsigned TmpStringPointer = 0;

HMODULE g_CurrentModule = NULL;

struct ExceptionHandlerSettings g_settings;
struct ExceptionData g_data;

struct GPDisplayRegister g_GPisplayRegisters[] = {
    { g_GPRegisterTable + 0, "rax" },
    { g_GPRegisterTable + 1, "rcx" },
    { g_GPRegisterTable + 2, "rdx" },
    { g_GPRegisterTable + 3, "rbx" },
    { g_GPRegisterTable + 4, "rsp" },
    { g_GPRegisterTable + 5, "rbp" },
    { g_GPRegisterTable + 6, "rsi" },
    { g_GPRegisterTable + 7, "rdi" },
    { g_GPRegisterTable + 8, "r8" },
    { g_GPRegisterTable + 9, "r9" },
    { g_GPRegisterTable + 10, "r10" },
    { g_GPRegisterTable + 11, "r11" },
    { g_GPRegisterTable + 12, "r12" },
    { g_GPRegisterTable + 13, "r13" },
    { g_GPRegisterTable + 14, "r14" },
    { g_GPRegisterTable + 15, "r15" },
    { g_GPRegisterTable + 16, "rip" },
};

struct FPDisplayRegister g_FPDisplayRegisters[] = {
    { g_FPRegisterTable + (0 * NUM_ZMM_ELEMS),  16, "xmm0" },
    { g_FPRegisterTable + (1 * NUM_ZMM_ELEMS),  16, "xmm1" },
    { g_FPRegisterTable + (2 * NUM_ZMM_ELEMS),  16, "xmm2" },
    { g_FPRegisterTable + (3 * NUM_ZMM_ELEMS),  16, "xmm3" },
    { g_FPRegisterTable + (4 * NUM_ZMM_ELEMS),  16, "xmm4" },
    { g_FPRegisterTable + (5 * NUM_ZMM_ELEMS),  16, "xmm5" },
    { g_FPRegisterTable + (6 * NUM_ZMM_ELEMS),  16, "xmm6" },
    { g_FPRegisterTable + (7 * NUM_ZMM_ELEMS),  16, "xmm7" },
    { g_FPRegisterTable + (8 * NUM_ZMM_ELEMS),  16, "xmm8" },
    { g_FPRegisterTable + (9 * NUM_ZMM_ELEMS),  16, "xmm9" },
    { g_FPRegisterTable + (10 * NUM_ZMM_ELEMS), 16, "xmm10" },
    { g_FPRegisterTable + (11 * NUM_ZMM_ELEMS), 16, "xmm11" },
    { g_FPRegisterTable + (12 * NUM_ZMM_ELEMS), 16, "xmm12" },
    { g_FPRegisterTable + (13 * NUM_ZMM_ELEMS), 16, "xmm13" },
    { g_FPRegisterTable + (14 * NUM_ZMM_ELEMS), 16, "xmm14" },
    { g_FPRegisterTable + (15 * NUM_ZMM_ELEMS), 16, "xmm15" },
    { g_FPRegisterTable + (16 * NUM_ZMM_ELEMS), 16, "xmm16" },
    { g_FPRegisterTable + (17 * NUM_ZMM_ELEMS), 16, "xmm17" },
    { g_FPRegisterTable + (18 * NUM_ZMM_ELEMS), 16, "xmm18" },
    { g_FPRegisterTable + (19 * NUM_ZMM_ELEMS), 16, "xmm19" },
    { g_FPRegisterTable + (20 * NUM_ZMM_ELEMS), 16, "xmm20" },
    { g_FPRegisterTable + (21 * NUM_ZMM_ELEMS), 16, "xmm21" },
    { g_FPRegisterTable + (22 * NUM_ZMM_ELEMS), 16, "xmm22" },
    { g_FPRegisterTable + (23 * NUM_ZMM_ELEMS), 16, "xmm23" },
    { g_FPRegisterTable + (24 * NUM_ZMM_ELEMS), 16, "xmm24" },
    { g_FPRegisterTable + (25 * NUM_ZMM_ELEMS), 16, "xmm25" },
    { g_FPRegisterTable + (26 * NUM_ZMM_ELEMS), 16, "xmm26" },
    { g_FPRegisterTable + (27 * NUM_ZMM_ELEMS), 16, "xmm27" },
    { g_FPRegisterTable + (28 * NUM_ZMM_ELEMS), 16, "xmm28" },
    { g_FPRegisterTable + (29 * NUM_ZMM_ELEMS), 16, "xmm29" },
    { g_FPRegisterTable + (30 * NUM_ZMM_ELEMS), 16, "xmm30" },
    { g_FPRegisterTable + (31 * NUM_ZMM_ELEMS), 16, "xmm31" },
    { g_FPRegisterTable + (0 * NUM_ZMM_ELEMS),  32, "ymm0" },
    { g_FPRegisterTable + (1 * NUM_ZMM_ELEMS),  32, "ymm1" },
    { g_FPRegisterTable + (2 * NUM_ZMM_ELEMS),  32, "ymm2" },
    { g_FPRegisterTable + (3 * NUM_ZMM_ELEMS),  32, "ymm3" },
    { g_FPRegisterTable + (4 * NUM_ZMM_ELEMS),  32, "ymm4" },
    { g_FPRegisterTable + (5 * NUM_ZMM_ELEMS),  32, "ymm5" },
    { g_FPRegisterTable + (6 * NUM_ZMM_ELEMS),  32, "ymm6" },
    { g_FPRegisterTable + (7 * NUM_ZMM_ELEMS),  32, "ymm7" },
    { g_FPRegisterTable + (8 * NUM_ZMM_ELEMS),  32, "ymm8" },
    { g_FPRegisterTable + (9 * NUM_ZMM_ELEMS),  32, "ymm9" },
    { g_FPRegisterTable + (10 * NUM_ZMM_ELEMS), 32, "ymm10" },
    { g_FPRegisterTable + (11 * NUM_ZMM_ELEMS), 32, "ymm11" },
    { g_FPRegisterTable + (12 * NUM_ZMM_ELEMS), 32, "ymm12" },
    { g_FPRegisterTable + (13 * NUM_ZMM_ELEMS), 32, "ymm13" },
    { g_FPRegisterTable + (14 * NUM_ZMM_ELEMS), 32, "ymm14" },
    { g_FPRegisterTable + (15 * NUM_ZMM_ELEMS), 32, "ymm15" },
    { g_FPRegisterTable + (16 * NUM_ZMM_ELEMS), 32, "ymm16" },
    { g_FPRegisterTable + (17 * NUM_ZMM_ELEMS), 32, "ymm17" },
    { g_FPRegisterTable + (18 * NUM_ZMM_ELEMS), 32, "ymm18" },
    { g_FPRegisterTable + (19 * NUM_ZMM_ELEMS), 32, "ymm19" },
    { g_FPRegisterTable + (20 * NUM_ZMM_ELEMS), 32, "ymm20" },
    { g_FPRegisterTable + (21 * NUM_ZMM_ELEMS), 32, "ymm21" },
    { g_FPRegisterTable + (22 * NUM_ZMM_ELEMS), 32, "ymm22" },
    { g_FPRegisterTable + (23 * NUM_ZMM_ELEMS), 32, "ymm23" },
    { g_FPRegisterTable + (24 * NUM_ZMM_ELEMS), 32, "ymm24" },
    { g_FPRegisterTable + (25 * NUM_ZMM_ELEMS), 32, "ymm25" },
    { g_FPRegisterTable + (26 * NUM_ZMM_ELEMS), 32, "ymm26" },
    { g_FPRegisterTable + (27 * NUM_ZMM_ELEMS), 32, "ymm27" },
    { g_FPRegisterTable + (28 * NUM_ZMM_ELEMS), 32, "ymm28" },
    { g_FPRegisterTable + (29 * NUM_ZMM_ELEMS), 32, "ymm29" },
    { g_FPRegisterTable + (30 * NUM_ZMM_ELEMS), 32, "ymm30" },
    { g_FPRegisterTable + (31 * NUM_ZMM_ELEMS), 32, "ymm31" },
    { g_FPRegisterTable + (0 * NUM_ZMM_ELEMS),  64, "zmm0" },
    { g_FPRegisterTable + (1 * NUM_ZMM_ELEMS),  64, "zmm1" },
    { g_FPRegisterTable + (2 * NUM_ZMM_ELEMS),  64, "zmm2" },
    { g_FPRegisterTable + (3 * NUM_ZMM_ELEMS),  64, "zmm3" },
    { g_FPRegisterTable + (4 * NUM_ZMM_ELEMS),  64, "zmm4" },
    { g_FPRegisterTable + (5 * NUM_ZMM_ELEMS),  64, "zmm5" },
    { g_FPRegisterTable + (6 * NUM_ZMM_ELEMS),  64, "zmm6" },
    { g_FPRegisterTable + (7 * NUM_ZMM_ELEMS),  64, "zmm7" },
    { g_FPRegisterTable + (8 * NUM_ZMM_ELEMS),  64, "zmm8" },
    { g_FPRegisterTable + (9 * NUM_ZMM_ELEMS),  64, "zmm9" },
    { g_FPRegisterTable + (10 * NUM_ZMM_ELEMS), 64, "zmm10" },
    { g_FPRegisterTable + (11 * NUM_ZMM_ELEMS), 64, "zmm11" },
    { g_FPRegisterTable + (12 * NUM_ZMM_ELEMS), 64, "zmm12" },
    { g_FPRegisterTable + (13 * NUM_ZMM_ELEMS), 64, "zmm13" },
    { g_FPRegisterTable + (14 * NUM_ZMM_ELEMS), 64, "zmm14" },
    { g_FPRegisterTable + (15 * NUM_ZMM_ELEMS), 64, "zmm15" },
    { g_FPRegisterTable + (16 * NUM_ZMM_ELEMS), 64, "zmm16" },
    { g_FPRegisterTable + (17 * NUM_ZMM_ELEMS), 64, "zmm17" },
    { g_FPRegisterTable + (18 * NUM_ZMM_ELEMS), 64, "zmm18" },
    { g_FPRegisterTable + (19 * NUM_ZMM_ELEMS), 64, "zmm19" },
    { g_FPRegisterTable + (20 * NUM_ZMM_ELEMS), 64, "zmm20" },
    { g_FPRegisterTable + (21 * NUM_ZMM_ELEMS), 64, "zmm21" },
    { g_FPRegisterTable + (22 * NUM_ZMM_ELEMS), 64, "zmm22" },
    { g_FPRegisterTable + (23 * NUM_ZMM_ELEMS), 64, "zmm23" },
    { g_FPRegisterTable + (24 * NUM_ZMM_ELEMS), 64, "zmm24" },
    { g_FPRegisterTable + (25 * NUM_ZMM_ELEMS), 64, "zmm25" },
    { g_FPRegisterTable + (26 * NUM_ZMM_ELEMS), 64, "zmm26" },
    { g_FPRegisterTable + (27 * NUM_ZMM_ELEMS), 64, "zmm27" },
    { g_FPRegisterTable + (28 * NUM_ZMM_ELEMS), 64, "zmm28" },
    { g_FPRegisterTable + (29 * NUM_ZMM_ELEMS), 64, "zmm29" },
    { g_FPRegisterTable + (30 * NUM_ZMM_ELEMS), 64, "zmm30" },
    { g_FPRegisterTable + (31 * NUM_ZMM_ELEMS), 64, "zmm31" },
};

char* WriteString(char* s, size_t len)
{
    if (!s)
        return NULL;
    if (!len) 
        len = strlen(s);
    char* Loc = TmpStringBuffer + TmpStringPointer;
    memcpy(Loc, s, len);
    TmpStringPointer += len + 1;
    return Loc;
}

PCHAR GetExceptionSymbol(PEXCEPTION_POINTERS pExceptionInfo)
{
    // TODO: Unify this logic, it seems possible.
#if (INTPTR_MAX == INT32_MAX)
    uintptr_t L0 = (uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionInformation[2];
    if (!L0)
        return NULL;
    uintptr_t L1 = *((uintptr_t*)L0 + 3);
    if (!L1)
        return NULL;
    uintptr_t L2 = *((uintptr_t*)L1 + 1);
    if (!L2)
        return NULL;
    uintptr_t L3 = *((uintptr_t*)L2 + 1);
    return (char*)(L3[2]);
#elif (INTPTR_MAX == INT64_MAX)
    if (pExceptionInfo->ExceptionRecord->NumberParameters < 4)
        return NULL;
    uintptr_t L0 = (uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionInformation[2];
    if (!L0)
        return NULL;
    uint32_t L1off = *((uint32_t*)L0 + 3);
    uintptr_t L1 = pExceptionInfo->ExceptionRecord->ExceptionInformation[3];
    uintptr_t L2 = L1 + L1off;
    if (!L2)
        return NULL;
    uintptr_t L3 = L1 + *(uint32_t*)(L2 + 4);
    if (!L3)
        return NULL;
    uintptr_t L4 = L1 + *(uint32_t*)(L3 + 4);
    if (!L4)
        return NULL;
    
    return (char*)(L4 + 16);
#endif
}

PCHAR GetExceptionMessage(PEXCEPTION_POINTERS pExceptionRecord)
{
#if (INTPTR_MAX == INT32_MAX)
	PCHAR Message = NULL;

	PDWORD L0 = (PDWORD)pExceptionRecord->ExceptionRecord->ExceptionInformation[1];
	if (L0 != NULL)
	{
		Message = (PCHAR)L0[1];
		if (Message == NULL)
		{
			Message = (PCHAR)L0[3];
		}
	}
	return Message;
#elif (INTPTR_MAX == INT64_MAX)
	ULONG_PTR ExceptionInfo_Unk1 = pExceptionRecord->ExceptionRecord->ExceptionInformation[1];
	return *(PCHAR*)(ExceptionInfo_Unk1 + 0x08);
#endif
}

DWORD GetMachineType()
{
#if defined(_M_X64) || defined(_WIN64) || defined(__amd64__) || defined(__x86_64__)
    return IMAGE_FILE_MACHINE_AMD64;
#elif defined(__i386__) || defined(_M_IX86)
    return IMAGE_FILE_MACHINE_I386;
#elif defined(__aarch64__) || defined(_M_ARM64)
    return IMAGE_FILE_MACHINE_ARM64
#else
#error Unknown image
#endif
}

void EHBroadcastYmm2ZmmArray(const M128A* YmmN16)
{
    M128A* ZmmArray = (M128A*)g_FPRegisterTable;
    unsigned i;
    for (i = 0; i < 16; ++i) // ymm0 - ymm15
    {
        memcpy(ZmmArray, YmmN16, 32);
        YmmN16 += 2;
        ZmmArray += 1;
    }
}

void EHBroadcastXmm2ZmmArray(const M128A* XmmN16)
{
    M128A* ZmmArray = (M128A*)g_FPRegisterTable;\
    unsigned i;
    for (i = 0; i < 16; ++i) // xmm0 - xmm15
    {
        memcpy(ZmmArray, XmmN16, 16);
        XmmN16 += 1;
        ZmmArray += 1;
    }
}

struct ExceptionData* EHLibDataGenerator(PEXCEPTION_POINTERS pExceptionInfo)
{
    STACKFRAME stackFrame = { };
    
    // struct ExceptionData data;

    g_GPRegisterTable[0] = pExceptionInfo->ContextRecord->Rax;
    g_GPRegisterTable[1] = pExceptionInfo->ContextRecord->Rcx;
    g_GPRegisterTable[2] = pExceptionInfo->ContextRecord->Rdx;
    g_GPRegisterTable[3] = pExceptionInfo->ContextRecord->Rbx;
    g_GPRegisterTable[4] = pExceptionInfo->ContextRecord->Rsp;
    g_GPRegisterTable[5] = pExceptionInfo->ContextRecord->Rbp;
    g_GPRegisterTable[6] = pExceptionInfo->ContextRecord->Rsi;
    g_GPRegisterTable[7] = pExceptionInfo->ContextRecord->Rdi;
    g_GPRegisterTable[8] = pExceptionInfo->ContextRecord->R9;
    g_GPRegisterTable[9] = pExceptionInfo->ContextRecord->R10;
    g_GPRegisterTable[10] = pExceptionInfo->ContextRecord->R11;
    g_GPRegisterTable[11] = pExceptionInfo->ContextRecord->R12;
    g_GPRegisterTable[12] = pExceptionInfo->ContextRecord->R13;
    g_GPRegisterTable[13] = pExceptionInfo->ContextRecord->R14;
    g_GPRegisterTable[14] = pExceptionInfo->ContextRecord->R15;
    g_GPRegisterTable[15] = pExceptionInfo->ContextRecord->Rip;

	stackFrame.AddrPC.Offset = pExceptionInfo->ContextRecord->Rip;
	stackFrame.AddrStack.Offset = pExceptionInfo->ContextRecord->Rsp;
	stackFrame.AddrFrame.Offset = pExceptionInfo->ContextRecord->Rbp;

	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrStack.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Mode = AddrModeFlat;

    SymInitialize(GetCurrentProcess(), NULL, TRUE);

    while (StackWalk(
        GetMachineType(),
        GetCurrentProcess(),
        GetCurrentThread(),
        &stackFrame,
        pExceptionInfo->ContextRecord,
        NULL,
        SymFunctionTableAccess,
        SymGetModuleBase,
        NULL))
    {
        struct CallStackEntry entry;

        char ModuleName[MAX_PATH];

        HMODULE ModuleBase = (HMODULE)SymGetModuleBase(GetCurrentProcess(), stackFrame.AddrPC.Offset);
        if (ModuleBase)
        {
            GetModuleFileNameA(ModuleBase, ModuleName, sizeof(ModuleName));
            entry.ModuleBaseAddress = ModuleBase;
            entry.ModuleName = WriteString(ModuleName, 0);
        }

		IMAGEHLP_LINE line;
		line.SizeOfStruct = sizeof line;

		DWORD offset;
		if (SymGetLineFromAddr(GetCurrentProcess(), stackFrame.AddrPC.Offset, &offset, &line))
		{
            entry.SourceFileName = WriteString(line.FileName, strlen(line.FileName));
			entry.LineNumber = line.LineNumber;
		}

		CHAR symbolBuf[sizeof(IMAGEHLP_SYMBOL) + 0xFF];
		PIMAGEHLP_SYMBOL symbol = (PIMAGEHLP_SYMBOL)symbolBuf;
		symbol->SizeOfStruct = sizeof symbolBuf;
		symbol->MaxNameLength = 0xFE;

        uintptr_t Disp;
        if (SymGetSymFromAddr(GetCurrentProcess(), stackFrame.AddrPC.Offset, &Disp, symbol))
        {
            entry.FunctionSymbolName = WriteString(symbol->Name, strlen(symbol->Name));
        }

        uintptr_t FileAddress = stackFrame.AddrPC.Offset - (uintptr_t)ModuleBase;
        entry.ReturnAddress = FileAddress;

        g_CallStackEntries[g_CallStackEntryPtr++] = entry;
    }

    g_data.CallStackEntries = g_CallStackEntries;
    g_data.CallStackEntryCount = g_CallStackEntryPtr;
    g_data.ExceptionAddress = (uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionAddress;
    g_data.ExceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;

    if (g_data.ExceptionCode == 0xE06D7363)
    {
        char* MangledExceptionSymbol = GetExceptionSymbol(pExceptionInfo);
        if (MangledExceptionSymbol)
        {
            char DemangledExceptionSymbol[512];
            unsigned Flags = 0;
            Flags |= UNDNAME_NO_ARGUMENTS;
            if (EH_32BIT_MACHINE)
                Flags |= UNDNAME_32_BIT_DECODE;
            UnDecorateSymbolName(MangledExceptionSymbol + 1, DemangledExceptionSymbol, sizeof DemangledExceptionSymbol, Flags);
            
            // TODO: Reimplement symbol blacklist
            g_data.CppExceptionSymbol = WriteString(DemangledExceptionSymbol, 0);
        }
        g_data.CppExceptionMessage = WriteString(GetExceptionMessage(pExceptionInfo), 0);
    }

    if (F_GetEnabledXStateFeatures) // Windows 7 SP1+
    {
        DWORD64 FeatureMask = F_GetEnabledXStateFeatures();
        DWORD FeatureLength;
        PVOID FeatureDump;
        if (FeatureMask & XSTATE_MASK_AVX512)
        {
            FeatureDump = F_LocateXStateFeature(pExceptionInfo->ContextRecord, XSTATE_AVX512_ZMM, &FeatureLength);
            memcpy(g_FPRegisterTable, FeatureDump, sizeof(g_FPRegisterTable));
        }
        else if (FeatureMask & XSTATE_MASK_AVX)
        {
            FeatureDump = F_LocateXStateFeature(pExceptionInfo->ContextRecord, XSTATE_AVX, &FeatureLength);
            EHBroadcastYmm2ZmmArray(FeatureDump);
        }
        else if (FeatureMask & XSTATE_MASK_LEGACY_SSE)
        {
            FeatureDump = F_LocateXStateFeature(pExceptionInfo->ContextRecord, XSTATE_LEGACY_SSE, &FeatureLength);
            EHBroadcastXmm2ZmmArray(FeatureDump);
        }
    }
    else
    {
         // TODO, not Windows 7 SP1
    }

    SymCleanup(GetCurrentProcess());

    return &g_data;
}

struct ExceptionReport* EHLibDefaultReportGenerator(struct ExceptionData* data)
{
    static struct ExceptionReport report;

    // char tmpline[768];

    // int MaxNumFunctionSymbolChars = 0;
    // int MaxNumLineChars = 0;
    // int MaxNumSourceFileNameChars = 0;
    // int MaxNumModuleNameChars = 0;

    int tmp;
    // char tmpc[16];
    // for (unsigned i = 0; i < data->CallStackEntryCount; ++i)
    // {
    //     _itoa_s(data->CallStackEntries[i].LineNumber, tmpc, sizeof tmpc, 10);
    //     MaxNumFunctionSymbolChars = (tmp = strlen(data->CallStackEntries[i].FunctionSymbolName)) > MaxNumFunctionSymbolChars ? tmp : MaxNumFunctionSymbolChars;
    //     MaxNumLineChars = (tmp = strlen(tmpc)) > MaxNumLineChars ? tmp : MaxNumLineChars;
    //     MaxNumSourceFileNameChars = (tmp = strlen(data->CallStackEntries[i].ModuleName)) > MaxNumSourceFileNameChars ? tmp : MaxNumSourceFileNameChars;
    //     MaxNumModuleNameChars = (tmp = strlen(data->CallStackEntries[i].ModuleName)) > MaxNumModuleNameChars ? tmp : MaxNumModuleNameChars;
    // }
    unsigned i;
    for (i = 0; i < data->CallStackEntryCount; ++i)
    {
        struct CallStackEntry* entry = &data->CallStackEntries[i];
        // _itoa_s(entry->LineNumber, tmpc, sizeof tmpc, 10);

        tmp = sprintf_s(ReportPrintBuffer + ReportPrintPointer, sizeof(ReportPrintBuffer) - ReportPrintPointer, "%s@%p@%s:L%i: %s\n", 
            entry->ModuleName, 
            entry->ReturnAddress - (uintptr_t)entry->ModuleBaseAddress,
            entry->SourceFileName,
            entry->LineNumber,
            entry->FunctionSymbolName
        );
        ReportPrintPointer += tmp + 1;
    }
    
    report.ReportString = ReportPrintBuffer;
    report.ReportSize = ReportPrintPointer;

    return &report;
}

void EHLibDefaultReporter(struct ExceptionReport* report)
{
    fprintf(stdout, "%.*s\n", (int)report->ReportSize, report->ReportString);

    return;
}

DWORD EHLibHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    struct ExceptionData* data = EHLibDataGenerator(pExceptionInfo);

    unsigned i = 0;
    for (; i < g_settings.SkipExceptionCodesLength; ++i)
    {
        if (g_settings.SkipExceptionCodesArray[i] == pExceptionInfo->ExceptionRecord->ExceptionCode)
        {
            ZydisDecoder decoder;
            ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
            ZydisDecodedInstruction insn;
            ZydisDecoderDecodeInstruction(&decoder, NULL, (PVOID)pExceptionInfo->ContextRecord->Rip, 16, &insn);

            pExceptionInfo->ContextRecord->Rip += insn.length;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    struct ExceptionReport* report = EHLibDefaultReportGenerator(data);
    EHLibDefaultReporter(report);

    return EXCEPTION_NONCONTINUABLE_EXCEPTION;
}

LONG WINAPI VEHCallback(PEXCEPTION_POINTERS pExceptionInfo)
{
    DWORD ret = EHLibHandler(pExceptionInfo);
    Sleep(INFINITE);
    return ret;
}

LONG WINAPI SEHCallback(PEXCEPTION_POINTERS pExceptionInfo)
{
    DWORD ret = EHLibHandler(pExceptionInfo);
    Sleep(INFINITE);
    return ret;
}

void EHLibInit_NT35()
{
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");

    typedef void(WINAPI* T_KiUserExceptionDispatcher)(PEXCEPTION_POINTERS pExceptionInfo, PCONTEXT pContext);
    T_KiUserExceptionDispatcher F_KiUserExceptionDispatcher = NULL;

    F_KiUserExceptionDispatcher = (T_KiUserExceptionDispatcher)(PVOID)GetProcAddress(hNtDll, "KiUserExceptionDispatcher");
    
    // UNIMPLEMENTED FIXME
    // TODO: Hook KiUserExceptionDispatcher which provides a PEXCEPTION_POINTERS and PCONTEXT,
    //       determine if the exception is relevant or not, and if it isn't, call original

    
}

void EHLibInit(struct ExceptionHandlerSettings* settings)
{
    g_settings = *settings;

    HMODULE hKern32Dll = GetModuleHandleW(L"kernel32.dll");
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    typedef void(WINAPI* T_RtlSetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
    typedef void(WINAPI* T_RtlAddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER lpVectorExceptionFilter);
    T_RtlSetUnhandledExceptionFilter RtlSetUnhandledExceptionFilter = NULL;
    T_RtlAddVectoredExceptionHandler RtlAddVectoredExceptionHandler = NULL;
    
    F_GetEnabledXStateFeatures = (T_GetEnabledXStateFeatures)(PVOID)GetProcAddress(hKern32Dll, "GetEnabledXStateFeatures");
    F_LocateXStateFeature = (T_LocateXStateFeature)(PVOID)GetProcAddress(hKern32Dll, "LocateXStateFeature");
    if (g_settings.UseSEH)
    {
        RtlSetUnhandledExceptionFilter = (T_RtlSetUnhandledExceptionFilter)(PVOID)GetProcAddress(hNtDll, "RtlSetUnhandledExceptionFilter");
        if (!RtlSetUnhandledExceptionFilter)
        {
            EHLibInit_NT35(); // NT 3.5, 4.0, Windows 2000 (NT 5.0)
            return;
        }
        RtlSetUnhandledExceptionFilter(SEHCallback);
    }
    if (g_settings.UseVEH)
    {
        RtlAddVectoredExceptionHandler = (T_RtlAddVectoredExceptionHandler)(PVOID)GetProcAddress(hNtDll, "RtlAddVectoredExceptionHandler");
        RtlAddVectoredExceptionHandler(1, VEHCallback);
    }
    return;
}