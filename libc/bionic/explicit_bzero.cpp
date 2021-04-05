#include <string.h>

void __attribute__((noinline)) explicit_bzero(void* s, size_t n) __attribute__((disable_tail_calls)) {
  void *ptr = memset(s, 0, n);
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
  (void)ptr;
}
