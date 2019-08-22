#pragma once

namespace libMSMM::disassembler
{
	typedef cs_insn instruction;
	typedef std::vector<instruction> instructions;
	bool disassemble(void* pCode, size_t CodeSize, instructions& output);
}