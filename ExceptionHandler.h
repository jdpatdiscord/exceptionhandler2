#include <windows.h>

#include <Zydis/Zydis.h>

#ifdef __cplusplus
#include <cstdint>
#include <cstdbool>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cstdio>
#else
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#endif

#if !defined(XSTATE_AVX512_KMASK) && !defined(XSTATE_AVX512_ZMM_H) && !defined(XSTATE_AVX512_ZMM)
#define XSTATE_AVX512_KMASK                 (5)
#define XSTATE_AVX512_ZMM_H                 (6)
#define XSTATE_AVX512_ZMM                   (7)
#endif

#if !defined(XSTATE_MASK_AVX512)
#define XSTATE_MASK_AVX512 ((1ull << (XSTATE_AVX512_KMASK)) | \
                         (1ull << (XSTATE_AVX512_ZMM_H)) | \
                         (1ull << (XSTATE_AVX512_ZMM)))
#endif

#if !defined(XSTATE_AMX_TILE_CONFIG) && !defined(XSTATE_MASK_AMX_TILE_CONFIG)
    && !defined(XSTATE_AMX_TILE_DATA) && !defined(XSTATE_MASK_AMX_TILE_DATA)
#define XSTATE_AMX_TILE_CONFIG              (17)
#define XSTATE_AMX_TILE_DATA                (18)
#define XSTATE_MASK_AMX_TILE_CONFIG         (1ui64 << (XSTATE_AMX_TILE_CONFIG))
#define XSTATE_MASK_AMX_TILE_DATA           (1ui64 << (XSTATE_AMX_TILE_DATA))
#endif

#if defined(_M_X64) || defined(_WIN64) || defined(__amd64__) || defined(__x86_64__) || defined(__aarch64__) || defined(_M_ARM64)
#define EH_64BIT_MACHINE 1
#define EH_32BIT_MACHINE 0
#elif defined(__i386__) || defined(_M_IX86)
#define EH_64BIT_MACHINE 0
#define EH_32BIT_MACHINE 1
#endif

#ifndef UNUSED
#define UNUSED(x) (void)x;
#endif

#define NUM_XMM_ELEMS 4
#define NUM_YMM_ELEMS 8
#define NUM_ZMM_ELEMS 16

struct GPDisplayRegister
{
    uintptr_t* RegisterData;
    const char* RegisterName;
};

struct FPDisplayRegister
{
    void* RegisterData;
    unsigned char RegisterSize;
    const char* RegisterName;
};

struct CallStackEntry
{
    char* ModuleName;
    char* SourceFileName;
    char* FunctionSymbolName;
    int LineNumber;
    uintptr_t ReturnAddress;
    HMODULE ModuleBaseAddress;
};

struct ExceptionReport
{
    char* ReportString;
    size_t ReportSize;
};

struct ExceptionData
{
    struct CallStackEntry* CallStackEntries;
    unsigned CallStackEntryCount;
    struct GPDisplayRegister* GPDisplayRegisters;
    struct FPDisplayRegister* FPDisplayRegisters;
    uint32_t ExceptionCode;
    uintptr_t ExceptionAddress;
    char* CppExceptionSymbol;
    char* CppExceptionMessage;
    bool Ignore;
};

typedef void (*T_ReceiverCallback)(struct ExceptionReport*);
typedef struct ExceptionReport* (*T_ProcessorCallback)(struct ExceptionData*);

struct ExceptionHandlerSettings
{
    unsigned int SkipExceptionCodesLength;
    const unsigned int* SkipExceptionCodesArray;
    unsigned int SkipSymbolLength;
    const char** SkipSymbolArray;
    HMODULE ModuleBase;
    T_ReceiverCallback F_ReportHandler;
    T_ProcessorCallback F_ReportGenerator;
    bool UseVEH;
    bool UseSEH;
};

typedef DWORD64(WINAPI* T_GetEnabledXStateFeatures)();
typedef PVOID(WINAPI* T_LocateXStateFeature)(PCONTEXT Context, DWORD FeatureId, PDWORD Length);

extern T_GetEnabledXStateFeatures F_GetEnabledXStateFeatures;
extern T_LocateXStateFeature F_LocateXStateFeature;

extern struct ExceptionHandlerSettings g_settings;
extern struct ExceptionData g_data;

extern struct GPDisplayRegister g_GPDisplayRegisters[];
extern struct FPDisplayRegister g_FPDisplayRegisters[];

extern uintptr_t g_GPRegisterTable[16]; // rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15, rip (CONTEXT layout)
extern float_t g_FPRegisterTable[512]; // zmm0 - zmm31 (includes xmm, ymm)

extern struct CallStackEntry g_CallStackEntries[192];
extern unsigned g_CallStackEntryPtr;

extern char ReportPrintBuffer[20480];
extern unsigned ReportPrintPointer;

extern char TmpStringBuffer[10240];
extern unsigned TmpStringPointer;

extern HMODULE g_CurrentModule;

extern void EHLibInit(struct ExceptionHandlerSettings* settings);
extern struct ExceptionReport* EHLibDefaultReportGenerator(struct ExceptionData* data);
extern void EHLibDefaultReporter(struct ExceptionReport* report);
extern struct ExceptionData* EHLibDataGenerator(PEXCEPTION_POINTERS pExceptionInfo);