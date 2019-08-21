#pragma once

namespace libMSMM::disassembler
{
	typedef std::vector<cs_insn> instructions;
	bool disassemble(void* pCode, size_t CodeSize, instructions& output);
}