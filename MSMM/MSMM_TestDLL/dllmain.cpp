#include <Windows.h>
#include <iostream>

#pragma code_seg(".test2")
void UsefullFunction()
{
	//auto pString = LoadLibraryA("pString");
	//std::cout << pString << std::endl;
	MessageBoxA(NULL, "Hello, World!", "MSMM_TestDLL.dll", NULL);
}

#pragma code_seg(".test1")
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		UsefullFunction();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

