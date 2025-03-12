#include "common.h"

#pragma once

#define PAGE_SIZE 4096       // 4kb
#define PROCS_MAX 8          // 최대 프로세스 개수
#define PROC_UNUSED 0        // 사용되지 않는 프로세스 구조체
#define PROC_RUNNABLE 1      // 실행 가능한(runnale) 프로세스
#define PROC_EXITED 2        // 프로세스 종료
#define SATP_SV32 (1u << 31) // Sv32 mode paging 활성화
#define PAGE_V (1 << 0)      // Valid bit
#define PAGE_R (1 << 1)      // 읽기 가능
#define PAGE_W (1 << 2)      // 쓰기 가능
#define PAGE_X (1 << 3)      // 실행 가능
#define PAGE_U (1 << 4)      // 사용자 모드 접근 가능
#define USER_BASE 0x1000000
#define SSTATUS_SPIE (1 << 5) // U-Mode 진입 시 인터럽트 활성화
#define SCAUSE_ECALL 8

#define PANIC(fmt, ...)                                                        \
  do {                                                                         \
    printf("PANIC: %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__);      \
    while (1) {                                                                \
    }                                                                          \
  } while (0)

struct sbiret {
  long error;
  long value;
};

struct trap_frame {
  uint32_t ra;
  uint32_t gp;
  uint32_t tp;
  uint32_t t0;
  uint32_t t1;
  uint32_t t2;
  uint32_t t3;
  uint32_t t4;
  uint32_t t5;
  uint32_t t6;
  uint32_t a0;
  uint32_t a1;
  uint32_t a2;
  uint32_t a3;
  uint32_t a4;
  uint32_t a5;
  uint32_t a6;
  uint32_t a7;
  uint32_t s0;
  uint32_t s1;
  uint32_t s2;
  uint32_t s3;
  uint32_t s4;
  uint32_t s5;
  uint32_t s6;
  uint32_t s7;
  uint32_t s8;
  uint32_t s9;
  uint32_t s10;
  uint32_t s11;
  uint32_t sp;
} __attribute__((packed));

#define READ_CSR(reg)                                                          \
  ({                                                                           \
    unsigned long __tmp;                                                       \
    __asm__ __volatile__("csrr %0, " #reg : "=r"(__tmp));                      \
    __tmp;                                                                     \
  })

#define WRITE_CSR(reg, value)                                                  \
  do {                                                                         \
    uint32_t __tmp = (value);                                                  \
    __asm__ __volatile__("csrw " #reg ", %0" ::"r"(__tmp));                    \
  } while (0)

struct process {
  int pid;              // 프로세스 ID
  int state;            // 프로세스 상태: PROC_UNUSED 또는 PROC_RUNNABE
  vaddr_t sp;           // 스택 포인터
  uint32_t *page_table; // 1단계 page table 주소(물리 == 가상)
  uint8_t stack[8192];  // 커널 스택
};
