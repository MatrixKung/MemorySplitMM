#include <pch.h>

#pragma comment(lib, "capstone.lib")

namespace libMSMM::disassembler
{
	bool disassemble(void* pCode, size_t CodeSize, instructions& output)
	{
		csh hCapstone;

		if (cs_open(CS_ARCH_X86, CS_MODE_32, &hCapstone) != CS_ERR_OK)
		{
			LOG_ERROR("failed to open capstone");
			return false;
		}

		cs_insn* CurrentInstruction = cs_malloc(hCapstone);
		
		uint8_t* pFirst = (uint8_t*)pCode;
		size_t InstrucitonSize = CodeSize;
		uint64_t Start = (uint64_t)pFirst;
		while (cs_disasm_iter(hCapstone, (const uint8_t**)&pFirst, &InstrucitonSize, &Start, CurrentInstruction))
		{
			output.push_back( *CurrentInstruction );
		}

		cs_free(CurrentInstruction, 1);
		cs_close(&hCapstone);
		hCapstone = NULL;

		return true;
	}
}