package evasion

// C compiled into the build from a preamble: no .c file, no unsafe import.
// int poke(void) { return 10; }
import "C"
