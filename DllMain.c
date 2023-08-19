#include "ExceptionHandler.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    UNUSED(lpReserved)

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);

        const unsigned int BlacklistCode[] = {
            0x80000004,
            0x80000006,
            0x40010006
        };
        struct ExceptionHandlerSettings settings = {
            sizeof(BlacklistCode),
            BlacklistCode,
            0,
            NULL,
            hinstDLL,
            EHLibDefaultReporter,
            EHLibDefaultReportGenerator,
            TRUE,
            TRUE
        };

        EHLibInit(&settings);
        Sleep(1000);
        *(volatile int*)1 = 0;
    }
    return TRUE;
}