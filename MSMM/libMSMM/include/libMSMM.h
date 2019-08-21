#pragma once
// libMSMM include header - this is the only header you need to include in an external project
namespace libMSMM
{
	extern bool __stdcall MapImage(void* pBinary, const unsigned int BinarySize, const char* TargetAppExeName); 
}

// make sure we include our library
#pragma comment(lib, "libMSMM.lib")