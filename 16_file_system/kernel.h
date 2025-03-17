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
#define SSTATUS_SUM (1 << 18) // 커널에서 유저 페이지에 접근 가능
#define SCAUSE_ECALL 8

#define SECTOR_SIZE 512
#define VIRTQ_ENTRY_NUM 16
#define VIRTIO_DEVICE_BLK 2
#define VIRTIO_BLK_PADDR 0x10001000
#define VIRTIO_REG_MAGIC 0x00
#define VIRTIO_REG_VERSION 0x04
#define VIRTIO_REG_DEVICE_ID 0x08
#define VIRTIO_REG_QUEUE_SEL 0x30
#define VIRTIO_REG_QUEUE_NUM_MAX 0x34
#define VIRTIO_REG_QUEUE_NUM 0x38
#define VIRTIO_REG_QUEUE_ALIGN 0x3c
#define VIRTIO_REG_QUEUE_PFN 0x40
#define VIRTIO_REG_QUEUE_READY 0x44
#define VIRTIO_REG_QUEUE_NOTIFY 0x50
#define VIRTIO_REG_DEVICE_STATUS 0x70
#define VIRTIO_REG_DEVICE_CONFIG 0x100
#define VIRTIO_STATUS_ACK 1
#define VIRTIO_STATUS_DRIVER 2
#define VIRTIO_STATUS_DRIVER_OK 4
#define VIRTIO_STATUS_FEAT_OK 8
#define VIRTQ_DESC_F_NEXT 1
#define VIRTQ_DESC_F_WRITE 2
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1
#define VIRTIO_BLK_T_IN 0
#define VIRTIO_BLK_T_OUT 1

#define FILES_MAX 2
#define DISK_MAX_SIZE align_up(sizeof(struct file) * FILES_MAX, SECTOR_SIZE)

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

// Virtqueue Descriptor area entry - 디스크립터 영역의 각 엔트리를 정의
struct virtq_desc {
  uint64_t addr;  // 버퍼의 물리 메모리 주소
  uint32_t len;   // 버퍼의 길이(바이트)
  uint16_t flags; // 디스크립터 플래그 (NEXT, WRITE 등)
  uint16_t next;  // 체인에서 다음 디스크립터의 인덱스
} __attribute__((packed));

// Virtqueue Available Ring - 드라이버가 장치에게 사용 가능한 버퍼를 알리는 링
struct virtq_avail {
  uint16_t flags;                 // 인터럽트 제어 플래그
  uint16_t index;                 // 다음에 사용할 ring[] 배열의 인덱스
  uint16_t ring[VIRTQ_ENTRY_NUM]; // 사용 가능한 디스크립터의 인덱스 배열
} __attribute__((packed));

// Virtqueue Used Ring entry - 장치가 처리 완료한 버퍼 정보
struct virtq_used_elem {
  uint32_t id;  // 처리 완료된 디스크립터 체인의 첫 번째 디스크립터 인덱스
  uint32_t len; // 처리된 바이트 수
} __attribute__((packed));

// Virtqueue Used Ring - 장치가 드라이버에게 처리 완료를 알리는 링
struct virtq_used {
  uint16_t flags; // 인터럽트 제어 플래그
  uint16_t index; // 다음에 사용할 ring[] 배열의 인덱스
  struct virtq_used_elem ring[VIRTQ_ENTRY_NUM]; // 처리 완료된 버퍼 정보 배열
} __attribute__((packed));

// Virtqueue - 전체 가상 큐 구조체
struct virtio_virtq {
  struct virtq_desc descs[VIRTQ_ENTRY_NUM]; // 디스크립터 영역
  struct virtq_avail avail;                 // Available Ring
  struct virtq_used used
      __attribute__((aligned(PAGE_SIZE))); // Used Ring (페이지 정렬)
  int queue_index;                         // 큐 인덱스
  volatile uint16_t *used_index; // 장치가 실시간으로 업데이트하는 Used Ring의
                                 // index 필드에 대한 포인터
  uint16_t last_used_index; // 드라이버가 마지막으로 확인한 마지막으로 처리된
                            // Used Ring 인덱스
} __attribute__((packed));

// Virtio-blk request - 블록 장치 요청 구조체
struct virtio_blk_req {
  uint32_t type;     // 요청 타입 (읽기/쓰기)
  uint32_t reserved; // 예약됨 (사용되지 않음)
  uint64_t sector;   // 접근할 디스크 섹터 번호
  uint8_t data[512]; // 데이터 버퍼 (섹터 크기)
  uint8_t status;    // 요청 처리 결과 (0: 성공, 다른 값: 실패)
} __attribute__((packed));

struct tar_header {
  char name[100];
  char mode[8];
  char uid[8];
  char gid[8];
  char size[12];
  char mtime[12];
  char checksum[8];
  char type;
  char linkname[100];
  char magic[6];
  char version[2];
  char uname[32];
  char gname[32];
  char devmajor[8];
  char devminor[8];
  char prefix[155];
  char padding[12];
  char data[]; // Array pointing to the data area following the header
               // (flexible array member)
} __attribute__((packed));

struct file {
  bool in_use;     // Indicates if this file entry is in use
  char name[100];  // File name
  char data[1024]; // File content
  size_t size;     // File size
};
