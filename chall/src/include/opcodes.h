
#ifndef OPCODES_H
#define OPCODES_H

#define FOREACH_INSTRUCTION(INS) \
  INS(nop) \
  \
  INS(push) \
  INS(pop) \
  INS(read) \
  INS(add) \
  INS(sub) \
  INS(mul) \
  INS(div) \
  INS(mod) \
  INS(itostr) \
  \
  INS(jmp) \
  INS(lt) \
  INS(gt) \
  INS(eq) \
  \
  INS(jnz) \
  INS(jz) \
  \
  INS(inc) \
  INS(dec) \
  INS(shl) \
  INS(shr) \
  \
  INS(cpy) \
  INS(swap) \
  \
  INS(pushs) \
  INS(pops) \
  INS(reads) \
  INS(strcat) \
  INS(strlen) \
  INS(strtoi) \
  INS(strcmp) \
  INS(instr) \
  \
  INS(writefile) \
  INS(readfile) \
  \
  INS(halt)

#define instr halt
#define instr_con(ins) exec_ ## ins

#define GENERATE_SYMBOL_LIST(ins) exec_ ## ins,
#define GENERATE_ENUM(ins) ins_ ## ins,



typedef enum e {
  FOREACH_INSTRUCTION(GENERATE_ENUM)
  NUM_INSTRUCTIONS
} InstrSet2;

#endif
