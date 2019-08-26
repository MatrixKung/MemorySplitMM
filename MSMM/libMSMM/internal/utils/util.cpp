#include "pch.h"

bool libMSMM::util::isStringValid(const char* pStr)
{
	auto strLen = strlen(pStr);

	for (auto i = 0; i < strLen; i++)
	{
		auto chr = pStr[i];
		if (!(chr >= 0x20 && chr <= 0x7E))
		{
			return false;
		}
	}

	return true;
}
