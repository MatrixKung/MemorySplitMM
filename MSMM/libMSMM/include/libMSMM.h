#pragma once
// libMSMM include header - this is the only header you need to include in an external project
namespace libMSMM
{
	enum MappingOptions
	{
		CLEAR_FILE_MEMORY_FROM_LOCAL_BUFFER = (1 << 0),
		WIPE_IMPORTS = (1 << 1),
		WIPE_RELOCATIONS = (1 << 2),
		LAYOUT_RANDOMISATION = (1 << 3),

		MAP_ALL_OPTIONS = 0xFFFFFFFF
	};

	extern bool __stdcall MapImage(void* pBinary, const unsigned int BinarySize, const char* TargetAppExeName, const MappingOptions Options);
}

// make sure we include our library
#pragma comment(lib, "libMSMM.lib")