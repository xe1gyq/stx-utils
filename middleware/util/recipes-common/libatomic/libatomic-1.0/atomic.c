/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include <stdio.h>

#include "atomic_types.h"

/* 
     Atomically complete the following:
    1. test if value at addr equals "old" 
    2. If equal, store "new" to addr and return 1
    3. Otherwise return 0
*/

#ifdef __i386__
atomic_type atomic_test_and_set_if_eq(atomic_type *p, 
                                      atomic_type  old_val,
                                      atomic_type  new_val)
    {

    atomic_type result;

    asm volatile(
                "      pushl %%ebx          \n\t" /* Save %ebx */
                "      mfence               \n\t" /* Complete all reads/writes */
                "      movl  %2,    %%eax   \n\t" /* store "old" in eax */
                "      movl  %3,    %%ecx   \n\t" /* store "new" in ecx */
                "lock; cmpxchg %%ecx, %1    \n\t" /* issue cmpxchg instr. */
                "      je     1f            \n\t" /* Success (eax==old) */
                "      movl   $0,    %0     \n\t" /* store failure return code */
                "      jmp    2f            \n\t" /* skip success path */
                " 1:   movl   $1,    %0     \n\t" /* store success return code */
                " 2:    cpuid               \n\t" /* Serialize */
                "      popl  %%ebx          \n\t"
                 :"=m"(result),
                  "=m" (*(p))
                 :"m" (old_val),
                  "m" (new_val)
                 : "%eax", "%ecx","%edx","%flags", "memory");

   return (int)result;
   }
#endif  /* __i386__ */

#ifdef __x86_64__
atomic_type atomic_test_and_set_if_eq(atomic_type *p,
                                      atomic_type  old_val,
                                      atomic_type  new_val)
    {

    atomic_type result;

    asm volatile(
                "      movq  %2,    %%rax   \n\t" /* store "old" in eax */
                "      movq  %3,    %%rcx   \n\t" /* store "new" in ecx */
                "lock; cmpxchg %%rcx, %1    \n\t" /* issue cmpxchg instr. */
                "      je     1f            \n\t" /* Success (eax==old) */
                "      movq   $0,    %0     \n\t" /* store failure return code */
                "      jmp    2f            \n\t" /* skip success path */
                " 1:   movq   $1,    %0     \n\t" /* store success return code */
                " 2:                        \n\t" 
                 :"=m"(result),
                  "=m" (*(p))
                 :"m" (old_val),
                  "m" (new_val)
                 : "%rax", "%rcx", "memory");

   return result;
   }
#endif  /* __x86_64__ */

