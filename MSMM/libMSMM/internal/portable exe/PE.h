#pragma once

namespace libMSMM::PE
{
	PIMAGE_DOS_HEADER GetDOSHeaders(void* pImage);
	PIMAGE_NT_HEADERS32 GetNTHeaders(void* pImage);
}