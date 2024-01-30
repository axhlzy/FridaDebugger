#include "fridaBind.h"

void frida_log(const char *) {

  // IMPL IN TS CODE
  // REPLACE WITH FRIDA CONSOLE.LOG

#ifdef __aarch64__

  asm("mov x0, #0x0\n"
      "mov x1, #0x0\n"
      "mov x1, #0x0\n"
      "mov x1, #0x0\n"
      "mov x1, #0x0\n"
      "mov x1, #0x0\n"
      "mov x1, #0x0\n"
      "mov x2, #0x0\n"
      "mov x3, #0x0\n"
      "mov x16, #0x3c\n");
#else
  asm("mov r0, #0x0\n"
      "mov r0, #0x0\n"
      "mov r0, #0x0\n"
      "mov r0, #0x0\n"
      "mov r0, #0x0\n"
      "mov r0, #0x0\n"
      "mov r0, #0x0\n"
      "mov r0, #0x0\n"
      "mov r0, #0x0\n");
#endif
}