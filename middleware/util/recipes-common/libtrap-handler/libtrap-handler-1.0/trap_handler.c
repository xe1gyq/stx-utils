/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#define _GNU_SOURCE
#include <ucontext.h>


#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <syslog.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <elf.h>
#include <sys/time.h>

#define gettid() ((pid_t)syscall(SYS_gettid))

#if defined (__x86_64__)
    typedef unsigned long long address_type;
    #define ADDR_FORMAT "%016llx"
    #define INT_SIZE_FORMAT "llx"
#elif defined (__i386__)
    typedef unsigned long address_type;
    #define ADDR_FORMAT "%08lx"
    #define INT_SIZE_FORMAT "lx"
#else
    typedef unsigned long long address_type;
    #define ADDR_FORMAT "%016llx"
    #define INT_SIZE_FORMAT "llx"
#endif

#define NCODEOLD 0x100
#define NCODEOFFSET 16

char* si_old_code_names[NCODEOLD];

#define NCODE 10
char* si_code_names[NSIG][NCODE];

const char* trapinfo_prog_name = NULL;
int trapinfo_argc = 0;
char **trapinfo_argv = NULL;


#define PRINT_TRAP(format, ...) \
    ({ \
    char buf[512]; \
    char buf2[1024]; \
    struct timespec t; \
    struct timeval tv; \
    struct tm lt; \
    pid_t pid; \
    pid_t tid; \
    pid = getpid(); \
    tid = gettid(); \
    gettimeofday(&tv, NULL); \
    localtime_r(&tv.tv_sec, &lt); \
    strftime(buf, sizeof(buf), "%T", &lt); \
    snprintf(buf2, sizeof(buf2), \
            "%s.%09ld %s[%d:%d] TRAP:  " format, \
            buf, tv.tv_usec, trapinfo_prog_name, pid, tid, ##__VA_ARGS__); \
    fprintf(stderr, "%s", buf2); \
    syslog(LOG_USER | LOG_CRIT, "%s", buf2); \
    t.tv_sec=0; \
    t.tv_nsec=10000; \
    nanosleep(&t, NULL); \
    })


#if defined (__x86_64__)
void print_regs(ucontext_t* u)
    {
    greg_t *gregs;

    gregs =  u->uc_mcontext.gregs;
    PRINT_TRAP("Registers:\n");
    PRINT_TRAP("   RIP = " ADDR_FORMAT " (instruction ptr)\n",                                       (long long)gregs[REG_RIP]);
    PRINT_TRAP("   RDI = " ADDR_FORMAT " (arg 1)            RSP = " ADDR_FORMAT " (stack ptr)\n",            (long long)gregs[REG_RDI], (long long)gregs[REG_RSP]);
    PRINT_TRAP("   RSI = " ADDR_FORMAT " (arg 2)            RBP = " ADDR_FORMAT " (stack base ptr - opt)\n", (long long)gregs[REG_RSI], (long long)gregs[REG_RBP]);
    PRINT_TRAP("   RDX = " ADDR_FORMAT " (arg 3)            RAX = " ADDR_FORMAT " (return arg, temp)\n",     (long long)gregs[REG_RDX], (long long)gregs[REG_RAX]);
    PRINT_TRAP("   RCX = " ADDR_FORMAT " (arg 4)            RBX = " ADDR_FORMAT " (base ptr - opt)\n",       (long long)gregs[REG_RCX], (long long)gregs[REG_RBX]);
    PRINT_TRAP("   R8  = " ADDR_FORMAT " (arg 5)            R12 = " ADDR_FORMAT " (temp)\n",                 (long long)gregs[REG_R8],  (long long)gregs[REG_R12]);
    PRINT_TRAP("   R9  = " ADDR_FORMAT " (arg 6)            R13 = " ADDR_FORMAT " (temp)\n",                 (long long)gregs[REG_R9],  (long long)gregs[REG_R13]);
    PRINT_TRAP("   R10 = " ADDR_FORMAT " (static chain ptr) R14 = " ADDR_FORMAT " (temp)\n",                 (long long)gregs[REG_R10], (long long)gregs[REG_R14]);
    PRINT_TRAP("   R11 = " ADDR_FORMAT " (temp)             R15 = " ADDR_FORMAT " (temp)\n",                 (long long)gregs[REG_R11], (long long)gregs[REG_R15]);
    PRINT_TRAP("   ERR = " ADDR_FORMAT "                    TRAPNO =  " ADDR_FORMAT "\n",                    (long long)gregs[REG_ERR], (long long)gregs[REG_TRAPNO]);
    PRINT_TRAP("   CR2 = " ADDR_FORMAT "                    OLDMASK = " ADDR_FORMAT "\n",                    (long long)gregs[REG_CR2], (long long)gregs[REG_OLDMASK]);
    PRINT_TRAP("\n");
    }
#elif defined (__i386__)
void print_regs(ucontext_t* u)
    {
    greg_t *gregs;

    gregs =  u->uc_mcontext.gregs;
    PRINT_TRAP("Registers:\n");
    PRINT_TRAP("   EIP = %08lx (instruction ptr)\n",                                     (long)gregs[REG_EIP]);
    PRINT_TRAP("   EDI = %08lx                    ESP = %08lx (stack ptr)\n",            (long)gregs[REG_EDI], (long)gregs[REG_ESP]);
    PRINT_TRAP("   ESI = %08lx                    EBP = %08lx (stack base ptr - opt)\n", (long)gregs[REG_ESI], (long)gregs[REG_EBP]);
    PRINT_TRAP("   EDX = %08lx                    EAX = %08lx (return arg, temp)\n",     (long)gregs[REG_EDX], (long)gregs[REG_EAX]);
    PRINT_TRAP("   ECX = %08lx                    EBX = %08lx (base ptr - opt)\n",       (long)gregs[REG_ECX], (long)gregs[REG_EBX]);
    PRINT_TRAP("   ERR = %08lx                    TRAPNO =  %08lx\n",                    (long)gregs[REG_ERR], (long)gregs[REG_TRAPNO]);
    PRINT_TRAP("\n");
    }
#else
void print_regs(ucontext_t* u)
    {
    PRINT_TRAP("Registers:\n");
    PRINT_TRAP("\n");
    }
#endif

const char* get_si_code_name(siginfo_t *si)
    {
    if (si->si_code < 0 || si->si_code >= NCODE)
        {
        if (si->si_code + NCODEOFFSET < 0 || si->si_code + NCODEOFFSET >= NCODEOLD)
            return "???";

        return si_old_code_names[si->si_code + NCODEOFFSET];
        }

    if (si->si_signo < 0 || si->si_signo >= NSIG ||
        si->si_code < 0 || si->si_code >= NCODE)
        return "???";

    return si_code_names[si->si_signo][si->si_code];
    }

void init_si_codes()
    {
    int s,c;

    for(c=0;c<NCODEOLD;c++)
        si_old_code_names[c]="???";

    si_old_code_names[NCODEOFFSET+SI_USER]       = "SI_USER        kill/raise";
    si_old_code_names[NCODEOFFSET+SI_KERNEL]     = "SI_KERNEL      Sent by the kernel";
    si_old_code_names[NCODEOFFSET+SI_QUEUE]      = "SI_QUEUE       sigqueue";
    si_old_code_names[NCODEOFFSET+SI_TIMER]      = "SI_TIMER       POSIX timer expired";
    si_old_code_names[NCODEOFFSET+SI_MESGQ]      = "SI_MESGQ       POSIX  message  queue  state  changed";
    si_old_code_names[NCODEOFFSET+SI_ASYNCIO]    = "SI_ASYNCIO     AIO completed";
    si_old_code_names[NCODEOFFSET+SI_SIGIO]      = "SI_SIGIO       Queued  SIGIO";
    si_old_code_names[NCODEOFFSET+SI_TKILL]      = "SI_TKILL       tkill/tgkill";
    #ifdef SI_DETHREAD
    si_old_code_names[NCODEOFFSET+SI_DETHREAD]   = "SI_DETHREAD    execve() killing subsidiary threads";
    #endif

    for(s=0;s<NSIG;s++)
        for(c=0;c<NCODE;c++)
            si_code_names[s][c]="???";

    si_code_names[SIGILL][ILL_ILLOPC]    = "ILL_ILLOPC     illegal opcode";
    si_code_names[SIGILL][ILL_ILLOPN]    = "ILL_ILLOPN     illegal operand";
    si_code_names[SIGILL][ILL_ILLADR]    = "ILL_ILLADR     illegal addressing mode";
    si_code_names[SIGILL][ILL_ILLTRP]    = "ILL_ILLTRP     illegal trap";
    si_code_names[SIGILL][ILL_PRVOPC]    = "ILL_PRVOPC     privileged opcode";
    si_code_names[SIGILL][ILL_PRVREG]    = "ILL_PRVREG     privileged register";
    si_code_names[SIGILL][ILL_COPROC]    = "ILL_COPROC     coprocessor error";
    si_code_names[SIGILL][ILL_BADSTK]    = "ILL_BADSTK     internal stack error";
    si_code_names[SIGFPE][FPE_INTDIV]    = "FPE_INTDIV     integer divide by zero";
    si_code_names[SIGFPE][FPE_INTOVF]    = "FPE_INTOVF     integer overflow";
    si_code_names[SIGFPE][FPE_FLTDIV]    = "FPE_FLTDIV     floating-point divide by zero";
    si_code_names[SIGFPE][FPE_FLTOVF]    = "FPE_FLTOVF     floating-point overflow";
    si_code_names[SIGFPE][FPE_FLTUND]    = "FPE_FLTUND     floating-point underflow";
    si_code_names[SIGFPE][FPE_FLTRES]    = "FPE_FLTRES     floating-point inexact result";
    si_code_names[SIGFPE][FPE_FLTINV]    = "FPE_FLTINV     floating-point invalid operation";
    si_code_names[SIGFPE][FPE_FLTSUB]    = "FPE_FLTSUB     subscript out of range";
    si_code_names[SIGSEGV][SEGV_MAPERR]   = "SEGV_MAPERR    address not mapped to object";
    si_code_names[SIGSEGV][SEGV_ACCERR]   = "SEGV_ACCERR    invalid permissions for mapped object";
    si_code_names[SIGBUS][BUS_ADRALN]    = "BUS_ADRALN     invalid address alignment";
    si_code_names[SIGBUS][BUS_ADRERR]    = "BUS_ADRERR     nonexistent physical address";
    si_code_names[SIGBUS][BUS_OBJERR]    = "BUS_OBJERR     object-specific hardware error";
    #ifdef BUS_MCEERR_AR
    si_code_names[SIGBUS][BUS_MCEERR_AR] = "BUS_MCEERR_AR  Hardware memory error, action required";
    #endif
    #ifdef BUS_MCEERR_AO
    si_code_names[SIGBUS][BUS_MCEERR_AO] = "BUS_MCEERR_AO  Hardware memory error, action optional";
    #endif
    si_code_names[SIGTRAP][TRAP_BRKPT]    = "TRAP_BRKPT     process breakpoint";
    si_code_names[SIGTRAP][TRAP_TRACE]    = "TRAP_TRACE     process trace trap";
    #ifdef TRAP_BRANCH
    si_code_names[SIGTRAP][TRAP_BRANCH]   = "TRAP_BRANCH    process taken branch trap";
    #endif
    #ifdef TRAP_HWBKPT
    si_code_names[SIGTRAP][TRAP_HWBKPT]   = "TRAP_HWBKPT    hardware breakpoint/watchpoint";
    #endif
    si_code_names[SIGCHLD][CLD_EXITED]    = "CLD_EXITED     child has exited";
    si_code_names[SIGCHLD][CLD_KILLED]    = "CLD_KILLED     child was killed";
    si_code_names[SIGCHLD][CLD_DUMPED]    = "CLD_DUMPED     child terminated abnormally";
    si_code_names[SIGCHLD][CLD_TRAPPED]   = "CLD_TRAPPED    traced child has trapped";
    si_code_names[SIGCHLD][CLD_STOPPED]   = "CLD_STOPPED    child has stopped";
    si_code_names[SIGCHLD][CLD_CONTINUED] = "CLD_CONTINUED  stopped child has continued";
    si_code_names[SIGPOLL][POLL_IN]       = "POLL_IN        data input available";
    si_code_names[SIGPOLL][POLL_OUT]      = "POLL_OUT       output buffers available";
    si_code_names[SIGPOLL][POLL_MSG]      = "POLL_MSG       input message available";
    si_code_names[SIGPOLL][POLL_ERR]      = "POLL_ERR       I/O error";
    si_code_names[SIGPOLL][POLL_PRI]      = "POLL_PRI       high priority input available";
    si_code_names[SIGPOLL][POLL_HUP]      = "POLL_HUP       device disconnected";
    #ifdef SYS_SECCOMP
    si_code_names[SIGSYS][SYS_SECCOMP]    = "SYS_SECCOMP    seccomp triggered";
    #endif
    }


void print_siginfo(int        signum,
                   siginfo_t *si)
    {
    PRINT_TRAP("SigInfo:\n");
    PRINT_TRAP("   SigNum:  %d (%s)\n", signum, strsignal(signum));
    PRINT_TRAP("   Code:    %d (%s)\n", si->si_code, get_si_code_name(si));
    PRINT_TRAP("   Addr:    %p\n", si->si_addr);
    #ifdef __ARCH_SIGSYS
    PRINT_TRAP("   CallAddr:%p\n", si->si_call_addr);
    #endif
    PRINT_TRAP("   ErrNum:  %d\n", si->si_errno);
    #ifdef __ARCH_SI_TRAPNO
    PRINT_TRAP("   TrapNum: %d\n", si->si_trapno);
    #endif
    PRINT_TRAP("   Pid:     %d\n", si->si_pid);
    PRINT_TRAP("   Value:   %d %p\n", si->si_value.sival_int, si->si_value.sival_ptr);
    PRINT_TRAP("   Status:  %d\n", si->si_status);
    PRINT_TRAP("\n");
    }

#define TRACEBACK_MAX 32
void print_trace()
    {
    void    *addr_array[TRACEBACK_MAX];    /* Array to store backtrace symbols */
    int      size;       /* To store the exact no of values stored */
    char   **strings;    /* To store functions from the backtrace list in ARRAY */
    int      i;

    size = backtrace(addr_array, TRACEBACK_MAX);

    strings = backtrace_symbols(addr_array, size);

    PRINT_TRAP("Traceback:\n");

    /* prints each string of function names of trace*/
    for (i = 3; i < size; i++)
        PRINT_TRAP("   %s\n", strings[i]);

    PRINT_TRAP("\n");
    }

int src_info(void* addr, Dl_info* dl_info, char* src_file_buf, int src_file_buf_size, int* src_file_line)
    {
    address_type offset;
    char cmd[256];
    char buffer[256];
    FILE* file;
    char *s;
    int rc=0;
    char *p;

    if (0==strcmp(dl_info->dli_fname, trapinfo_prog_name))
        offset = (address_type)addr;
    else
        offset = (address_type)addr - (address_type)dl_info->dli_fbase;

    snprintf(cmd, sizeof(cmd), "addr2line --exe=%s 0x" ADDR_FORMAT, dl_info->dli_fname, offset);
    file = popen(cmd, "r");
    if (!file)
        return -1;

    s = fgets(buffer, sizeof(buffer), file);
    if (!s)
       {
       pclose(file);
       return -1;
       }
    rc = sscanf(s, "%m[^:]:%d", &p, src_file_line);
    if (rc < 2)
       {
       pclose(file);
       return -1;
       }
    strncpy(src_file_buf, p, src_file_buf_size);
    pclose(file);
    return 0;
    }

int cpp_demangle(const char* mangled_name, char* mangled_name_buf, int mangled_name_buf_size)
    {
    char cmd[256];
    char buffer[256];
    FILE* file;
    char *s;

    if (!mangled_name)
        return -1;

    if (mangled_name[0] != '_' || mangled_name[1] != 'Z')
        return -1;

    snprintf(cmd, sizeof(cmd), "c++filt %s", mangled_name);
    file = popen(cmd, "r");
    if (!file)
        return -1;

    s = fgets(buffer, sizeof(buffer), file);
    if (!s)
       {
       pclose(file);
       return -1;
       }
    strncpy(mangled_name_buf, s, mangled_name_buf_size);
    pclose(file);
    return 0;
    }


int print_trace2(void** addr_p, Dl_info* dl_info_p)
    {
    void         *addr_array[TRACEBACK_MAX];    /* Array to store backtrace symbols */
    int           size;     /* To store the exact no of values stored */
    Dl_info       dl_info[TRACEBACK_MAX];
    char          src_file_buf[256];
    int           src_file_line;
    char          demangled_name[256];
    char*         func_names[TRACEBACK_MAX];
    address_type  func_offset[TRACEBACK_MAX];
    int           func_max = 0;
    char*         obj_names[TRACEBACK_MAX];
    address_type  obj_offset[TRACEBACK_MAX];
    int           obj_max = 0;
    char*         src_files[TRACEBACK_MAX];
    int           src_lines[TRACEBACK_MAX];
    int           src_max = 0;
    int           rc;
    int           rc2;
    int           final_rc = -1;
    int           i;
    
    PRINT_TRAP("Traceback:\n");

    size = backtrace(addr_array, TRACEBACK_MAX);
    for (i = 3; i < size; i++)
        {
        rc = dladdr(addr_array[i], &(dl_info[i]));
        // rc2 = dladdr1(addr_array[i], &(dl_info[i]), (void**)&velfsym, RTLD_DL_SYMENT);
        if (rc == 0)
            {
            PRINT_TRAP("   " ADDR_FORMAT ": ???\n", (address_type)addr_array[i]);
            continue;
            }
        if (i==3)
            {
            *addr_p = addr_array[i];
            *dl_info_p = dl_info[i];
            final_rc = 0;
            }
        rc = src_info(addr_array[i], &(dl_info[i]), src_file_buf, sizeof(src_file_buf), &src_file_line);
        rc2 = cpp_demangle(dl_info[i].dli_sname, demangled_name, sizeof(demangled_name));
       
        func_names[i] = strdup(rc2<0 ? (dl_info[i].dli_sname ? dl_info[i].dli_sname : "??") : demangled_name);
        func_offset[i] = dl_info[i].dli_sname ? (address_type)addr_array[i] - (address_type)dl_info[i].dli_saddr : 0;
        src_files[i] = strdup(basename(rc<0 ? "??" : src_file_buf)); 
        src_lines[i] = rc<0 ? 0 : src_file_line;
        obj_names[i] = strdup(basename(dl_info[i].dli_fname));
        obj_offset[i] = (address_type)addr_array[i] - (address_type)dl_info[i].dli_fbase;
        }

    for (i = 3; i < size; i++)
        {
        int l;
        l = strlen(func_names[i]);
        if (func_max < l)
           func_max = l;
        l = strlen(obj_names[i]);
        if (obj_max < l)
           obj_max = l;
        l = strlen(src_files[i]);
        if (src_max < l)
           src_max = l;
        }

    for (i = 3; i < size; i++)
        {
        PRINT_TRAP(
                 "   " ADDR_FORMAT ": %*s+0x%04" INT_SIZE_FORMAT ":  %*s+0x%05" INT_SIZE_FORMAT ":  %*s:%d\n", 
                (address_type)addr_array[i],
                func_max,
                func_names[i],
                func_offset[i],
                obj_max,
                obj_names[i],
                obj_offset[i],
                src_max,
                src_files[i],
                src_lines[i]
                );
        }

    PRINT_TRAP("\n");
    return final_rc;
    }

void print_dissassm(void* addr, Dl_info* dl_info)
    {
    address_type file_offset;
    char         cmd[256];
    char         buffer[256];
    FILE        *file;
    char        *s;

    PRINT_TRAP("Disassembly:\n");

    file_offset = (address_type)addr - (address_type)dl_info->dli_fbase;

    if (dl_info->dli_sname)
        snprintf(cmd, sizeof(cmd), "objdump -D -S -z %s --start-address=0x" ADDR_FORMAT " --stop-address=0x" ADDR_FORMAT " --line-numbers",
                 dl_info->dli_fname, 
                 (address_type)dl_info->dli_saddr, 
                 0x10+(address_type)addr);
    else
        snprintf(cmd, sizeof(cmd), "objdump -D -S -z %s --start-address=0x" ADDR_FORMAT " --stop-address=0x" ADDR_FORMAT " --line-numbers",
                 dl_info->dli_fname, 
                 (address_type)dl_info->dli_fbase + file_offset - (0x100 > file_offset ? 0x100 : file_offset),
                 0x10+(address_type)addr);

    file = popen(cmd, "r");
    while ((s = fgets(buffer, sizeof(buffer), file)))
        {
        if (s[strlen(s)-1] == '\n')
           s[strlen(s)-1] = '\0';
        PRINT_TRAP("   %s\n", s);
        }

    pclose(file);
    PRINT_TRAP("\n");
    }

void print_arg()
    {
    int i;

    PRINT_TRAP("Command: \n");
    PRINT_TRAP("   %s\n", trapinfo_prog_name);
    for(i=1; i<trapinfo_argc; i++)
       PRINT_TRAP("      %s\n", trapinfo_argv[i]);
    PRINT_TRAP("\n");
    }

void handle_fault_sig(int        signum, 
                      siginfo_t *siginfo,
                      void      *v)
    {
    ucontext_t *u = (ucontext_t *)v;
    void* addr;
    Dl_info dl_info;
    int rc;

    print_arg();
    print_siginfo(signum, siginfo);
    rc = print_trace2(&addr, &dl_info);
    if (rc==0)
       print_dissassm(addr, &dl_info);
    print_regs(u);
    exit(-1);
    }


void init_trap_handler()
    {
    struct sigaction sa;

    init_si_codes();
    sa.sa_sigaction = handle_fault_sig;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGSYS, &sa, NULL);
    }

__attribute__((constructor))
void init_trap_handler2(int argc, char **argv)
    {
    if (argc > 0 && argv)
       {
       trapinfo_prog_name = argv[0];
       trapinfo_argc = argc;
       trapinfo_argv = argv;
       }
    else
       trapinfo_prog_name = program_invocation_short_name;
       
    init_trap_handler();
    }

