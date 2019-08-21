#include <pch.h>

namespace libMSMM
{
	__declspec(dllexport) bool __stdcall MapImage(const void* pBinary, const unsigned int BinarySize, const char* TargetAppExeName)
	{
		log::Setup( LOG_DEBUG_LEVEL );

		return true;
	}
}
