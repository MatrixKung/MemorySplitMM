#pragma once

namespace libMSMM::ll
{
	HMODULE LoadLibraryRemote(process::Process& Process, const char* pModuleName);
};