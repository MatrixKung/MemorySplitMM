#include <pch.h>

namespace libMSMM::PE
{
	PIMAGE_DOS_HEADER GetDOSHeaders(void* pImage)
	{
		return (PIMAGE_DOS_HEADER)pImage;
	}
	PIMAGE_NT_HEADERS32 GetNTHeaders(void* pImage)
	{
		auto DosHeader = GetDOSHeaders(pImage);
		return (PIMAGE_NT_HEADERS32)((uint32_t)pImage + DosHeader->e_lfanew);
	}
}