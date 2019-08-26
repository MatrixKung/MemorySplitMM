#include <pch.h>

namespace libMSMM
{
	__declspec(dllexport) bool __stdcall MapImage(void* pBinary, const unsigned int BinarySize, const char* TargetAppExeName, const MappingOptions Options)
	{
		log::Setup( LOG_DEBUG_LEVEL );

		auto Process = process::Find(TargetAppExeName);
		if (!Process.is_valid())
		{
			LOG_ERROR("Could not open process: {}", TargetAppExeName);
			return false;
		}

		return mm::MapImage(pBinary, BinarySize, Process, Options);
	}
}
