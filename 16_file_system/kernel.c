#include "kernel.h"
#include "common.h"

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

extern char __kernel_base[], __bss[], __bss_end[], __stack_top[], __free_ram[],
    __free_ram_end[], _binary_shell_bin_start[], _binary_shell_bin_size[];

struct process procs[PROCS_MAX];     // 모든 프로세스 제어 구조체 배열
struct process *current_proc;        // 현재 실행 중인 프로세스
struct process *idle_proc;           // Idle 프로세스
struct virtio_virtq *blk_request_vq; // disk io를 위한 virtqueue
struct virtio_blk_req *blk_req;      // disk io를 위한 요청 구조체
struct file files[FILES_MAX];
uint8_t disk[DISK_MAX_SIZE];
paddr_t blk_req_paddr;
unsigned blk_capacity;

////////////////////////////////////////////////////////////////////////////////////

int oct2int(char *oct, int len) {
  int dec = 0;
  for (int i = 0; i < len; i++) {
    if (oct[i] < '0' || oct[i] > '7')
      break;

    dec = dec * 8 + (oct[i] - '0');
  }
  return dec;
}

__attribute__((naked)) void switch_context(uint32_t *prev_sp,
                                           uint32_t *next_sp) {
  __asm__ __volatile__(
      // 현재 프로세스의 스택에 callee-saved 레지스터 저장
      "addi sp, sp, -13 * 4\n" // 13개(4바이트씩) 레지스터 공간 확보
      "sw ra,  0  * 4(sp)\n"   // callee-saved 레지스터만 저장
      "sw s0,  1  * 4(sp)\n"
      "sw s1,  2  * 4(sp)\n"
      "sw s2,  3  * 4(sp)\n"
      "sw s3,  4  * 4(sp)\n"
      "sw s4,  5  * 4(sp)\n"
      "sw s5,  6  * 4(sp)\n"
      "sw s6,  7  * 4(sp)\n"
      "sw s7,  8  * 4(sp)\n"
      "sw s8,  9  * 4(sp)\n"
      "sw s9,  10 * 4(sp)\n"
      "sw s10, 11 * 4(sp)\n"
      "sw s11, 12 * 4(sp)\n"

      // 스택 포인터 교체
      "sw sp, (a0)\n" // *prev_sp = sp
      "lw sp, (a1)\n" // sp를 다음 프로세스의 값으로 변경

      // 다음 프로세스 스택에서 callee-saved 레지스터 복원
      "lw ra,  0  * 4(sp)\n"
      "lw s0,  1  * 4(sp)\n"
      "lw s1,  2  * 4(sp)\n"
      "lw s2,  3  * 4(sp)\n"
      "lw s3,  4  * 4(sp)\n"
      "lw s4,  5  * 4(sp)\n"
      "lw s5,  6  * 4(sp)\n"
      "lw s6,  7  * 4(sp)\n"
      "lw s7,  8  * 4(sp)\n"
      "lw s8,  9  * 4(sp)\n"
      "lw s9,  10 * 4(sp)\n"
      "lw s10, 11 * 4(sp)\n"
      "lw s11, 12 * 4(sp)\n"
      "addi sp, sp, 13 * 4\n"
      "ret\n");
}

void yield(void) {
  // 실행 가능한 프로세스 탐색
  struct process *next = idle_proc;
  for (int i = 0; i < PROCS_MAX; i++) {
    struct process *proc = &procs[(current_proc->pid + i) % PROCS_MAX];
    if (proc->state == PROC_RUNNABLE && proc->pid > 0) {
      next = proc;
      break;
    }
  }

  // 현재 프로세스 말고는 실행 가능한 프로세스가 없으면, 그냥 리턴
  if (next == current_proc)
    return;

  // 예외 처리 시 사용할 스택 포인터
  // 예외가 발생했을 때의 스택 포인터를 신뢰할 수 없기에 매번 커널 스택의 최상위
  // 주소로 리셋
  __asm__ __volatile__(
      "sfence.vma\n"
      "csrw satp, %[satp]\n"
      "sfence.vma\n"
      "csrw sscratch, %[sscratch]\n"
      :
      : [satp] "r"(SATP_SV32 | ((uint32_t)next->page_table / PAGE_SIZE)),
        [sscratch] "r"((uint32_t)&next->stack[sizeof(next->stack)]));

  struct process *prev = current_proc;
  current_proc = next;
  switch_context(&prev->sp, &next->sp);
}

////////////////////////////////////////////////////////////////////////////////////

struct sbiret sbi_call(long arg0, long arg1, long arg2, long arg3, long arg4,
                       long arg5, long fid, long eid) {
  register long a0 __asm__("a0") = arg0;
  register long a1 __asm__("a1") = arg1;
  register long a2 __asm__("a2") = arg2;
  register long a3 __asm__("a3") = arg3;
  register long a4 __asm__("a4") = arg4;
  register long a5 __asm__("a5") = arg5;
  register long a6 __asm__("a6") = fid;
  register long a7 __asm__("a7") = eid;

  __asm__ __volatile__("ecall"
                       : "=r"(a0), "=r"(a1)
                       : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5),
                         "r"(a6), "r"(a7)
                       : "memory");
  return (struct sbiret){.error = a0, .value = a1};
}

void putchar(char ch) {
  sbi_call(ch, 0, 0, 0, 0, 0, 0, 1 /* Console Putchar */);
}

long getchar(void) {
  struct sbiret ret = sbi_call(0, 0, 0, 0, 0, 0, 0, 2);
  return ret.error;
}

paddr_t alloc_pages(uint32_t n) {
  static paddr_t next_paddr = (paddr_t)__free_ram;
  paddr_t paddr = next_paddr;
  next_paddr += n * PAGE_SIZE;

  if (next_paddr > (paddr_t)__free_ram_end)
    PANIC("out of memory");

  memset((void *)paddr, 0, n * PAGE_SIZE);
  return paddr;
}

void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags) {
  if (!is_aligned(vaddr, PAGE_SIZE))
    PANIC("unaligned vaddr $x", vaddr);

  if (!is_aligned(paddr, PAGE_SIZE))
    PANIC("unaligned paddr $x", paddr);

  uint32_t vpn1 = (vaddr >> 22) & 0x3ff; // 1단계 페이지 테이블 인덱스 값
  if ((table1[vpn1] & PAGE_V) == 0) {
    // Create the non-existent 2nd level page table.
    uint32_t pt_paddr = alloc_pages(1);
    table1[vpn1] =
        ((pt_paddr / PAGE_SIZE) << 10) | PAGE_V; // save page number of 2nd
  }

  // Set the 2nd level page table entry to map the physical page.
  uint32_t vpn0 = (vaddr >> 12) & 0x3ff;
  uint32_t *table0 = (uint32_t *)((table1[vpn1] >> 10) * PAGE_SIZE);
  table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V;
}

////////////////////////////////////////////////////////////////////////////////////

uint32_t virtio_reg_read32(unsigned offset) {
  return *((volatile uint32_t *)(VIRTIO_BLK_PADDR + offset));
}

uint64_t virtio_reg_read64(unsigned offset) {
  return *((volatile uint64_t *)(VIRTIO_BLK_PADDR + offset));
}

void virtio_reg_write32(unsigned offset, uint32_t value) {
  *((volatile uint32_t *)(VIRTIO_BLK_PADDR + offset)) = value;
}

void virtio_reg_fetch_and_or32(unsigned offset, uint32_t value) {
  virtio_reg_write32(offset, virtio_reg_read32(offset) | value);
}

struct virtio_virtq *virtq_init(unsigned index) {
  // virtqueue를 위한 메모리 영역을 할당합니다.
  paddr_t virtq_paddr =
      alloc_pages(align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);
  struct virtio_virtq *vq = (struct virtio_virtq *)virtq_paddr;
  vq->queue_index = index;
  vq->used_index = (volatile uint16_t *)&vq->used.index;

  // 1. QueueSel 레지스터에 인덱스를 기록하여 큐 선택.
  virtio_reg_write32(VIRTIO_REG_QUEUE_SEL, index);
  // 5. QueueNum 레지스터에 큐의 크기를 기록하여 장치에 알림.
  virtio_reg_write32(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);
  // 6. QueueAlign 레지스터에 정렬값(바이트 단위)을 기록.
  virtio_reg_write32(VIRTIO_REG_QUEUE_ALIGN, 0);
  // 7. 할당한 큐 메모리의 첫 페이지의 물리적 번호를 QueuePFN 레지스터에 기록.
  virtio_reg_write32(VIRTIO_REG_QUEUE_PFN, virtq_paddr);
  return vq;
}

void virtio_blk_init(void) {
  if (virtio_reg_read32(VIRTIO_REG_MAGIC) != 0x74726976)
    PANIC("virtio: invalid magic value");
  if (virtio_reg_read32(VIRTIO_REG_VERSION) != 1)
    PANIC("virtio: invalid version");
  if (virtio_reg_read32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_BLK)
    PANIC("virtio: invalid device id");

  // 1. 장치를 리셋합니다.
  virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, 0);
  // 2. ACKNOWLEDGE 상태 비트를 설정합니다: 게스트 OS가 장치를 인식했음을 알림.
  virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
  // 3. DRIVER 상태 비트를 설정합니다.
  virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);
  // 5. FEATURES_OK 상태 비트를 설정합니다.
  virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_FEAT_OK);
  // 7. 장치별 설정 수행 (예, virtqueue 검색)
  blk_request_vq = virtq_init(0);
  // 8. DRIVER_OK 상태 비트를 설정합니다.
  virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);

  // 디스크 용량을 가져옵니다.
  blk_capacity = virtio_reg_read64(VIRTIO_REG_DEVICE_CONFIG + 0) * SECTOR_SIZE;
  printf("virtio-blk: capacity is %d bytes\n", blk_capacity);

  // 장치에 요청(request)을 저장할 영역을 할당합니다.
  blk_req_paddr =
      alloc_pages(align_up(sizeof(*blk_req), PAGE_SIZE) / PAGE_SIZE);
  blk_req = (struct virtio_blk_req *)blk_req_paddr;
}

// desc_index는 새로운 요청의 디스크립터 체인의 헤드 디스크립터 인덱스입니다.
// 장치에 새로운 요청이 있음을 알립니다.
void virtq_kick(struct virtio_virtq *vq, int desc_index) {
  vq->avail.ring[vq->avail.index % VIRTQ_ENTRY_NUM] = desc_index;
  vq->avail.index++;
  __sync_synchronize();
  virtio_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index);
  vq->last_used_index++;
}

// 장치가 요청을 처리 중인지 확인합니다.
bool virtq_is_busy(struct virtio_virtq *vq) {
  return vq->last_used_index != *vq->used_index;
}

// virtio-blk 장치로부터 읽기/쓰기를 수행합니다.
void read_write_disk(void *buf, unsigned sector, int is_write) {

  // sector가 (전체 용량/섹터 크기)보다 크다면 유효하지 않은 접근
  if (sector >= blk_capacity / SECTOR_SIZE) {
    printf("virtio: tried to read/write sector=%d, but capacity is %d\n",
           sector, blk_capacity / SECTOR_SIZE);
    return;
  }

  // virtio-blk 사양에 따라 요청을 구성합니다.
  blk_req->sector = sector;
  blk_req->type = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
  if (is_write)
    memcpy(blk_req->data, buf, SECTOR_SIZE);

  // virtqueue 디스크립터를 구성합니다 (3개의 디스크립터 사용).
  struct virtio_virtq *vq = blk_request_vq;
  vq->descs[0].addr = blk_req_paddr;
  vq->descs[0].len = sizeof(uint32_t) * 2 + sizeof(uint64_t);
  vq->descs[0].flags = VIRTQ_DESC_F_NEXT;
  vq->descs[0].next = 1;

  vq->descs[1].addr = blk_req_paddr + offsetof(struct virtio_blk_req, data);
  vq->descs[1].len = SECTOR_SIZE;
  vq->descs[1].flags = VIRTQ_DESC_F_NEXT | (is_write ? 0 : VIRTQ_DESC_F_WRITE);
  vq->descs[1].next = 2;

  vq->descs[2].addr = blk_req_paddr + offsetof(struct virtio_blk_req, status);
  vq->descs[2].len = sizeof(uint8_t);
  vq->descs[2].flags = VIRTQ_DESC_F_WRITE;

  // 장치에 새로운 요청이 있음을 알림.
  virtq_kick(vq, 0);

  // 장치가 요청 처리를 마칠 때까지 대기(바쁜 대기; busy-wait).
  while (virtq_is_busy(vq))
    ;

  // virtio-blk: 0이 아닌 값이 반환되면 에러입니다.
  if (blk_req->status != 0) {
    printf("virtio: warn: failed to read/write sector=%d status=%d\n", sector,
           blk_req->status);
    return;
  }

  // 읽기 작업의 경우, 데이터를 버퍼에 복사합니다.
  if (!is_write)
    memcpy(buf, blk_req->data, SECTOR_SIZE);
}

void fs_init(void) {
  for (unsigned sector = 0; sector < sizeof(disk) / SECTOR_SIZE; sector++)
    read_write_disk(&disk[sector * SECTOR_SIZE], sector, false);

  unsigned off = 0;
  for (int i = 0; i < FILES_MAX; i++) {
    struct tar_header *header = (struct tar_header *)&disk[off];
    if (header->name[0] == '\0')
      break;

    if (strcmp(header->magic, "ustar") != 0)
      PANIC("invalid tar header: magic=\"%s\"", header->magic);

    int filesz = oct2int(header->size, sizeof(header->size));
    struct file *file = &files[i];
    file->in_use = true;
    strcpy(file->name, header->name);
    memcpy(file->data, header->data, filesz);
    file->size = filesz;
    printf("file: %s, size=%d\n", file->name, file->size);

    off += align_up(sizeof(struct tar_header) + filesz, SECTOR_SIZE);
  }
}

void fs_flush(void) {
  // Copy all file contents into `disk` buffer.
  memset(disk, 0, sizeof(disk));
  unsigned off = 0;
  for (int file_i = 0; file_i < FILES_MAX; file_i++) {
    struct file *file = &files[file_i];
    if (!file->in_use)
      continue;

    struct tar_header *header = (struct tar_header *)&disk[off];
    memset(header, 0, sizeof(*header));
    strcpy(header->name, file->name);
    strcpy(header->mode, "000644");
    strcpy(header->magic, "ustar");
    strcpy(header->version, "00");
    header->type = '0';

    // Turn the file size into an octal string.
    int filesz = file->size;
    for (int i = sizeof(header->size); i > 0; i--) {
      header->size[i - 1] = (filesz % 8) + '0';
      filesz /= 8;
    }

    // Calculate the checksum.
    int checksum = ' ' * sizeof(header->checksum);
    for (unsigned i = 0; i < sizeof(struct tar_header); i++)
      checksum += (unsigned char)disk[off + i];

    for (int i = 5; i >= 0; i--) {
      header->checksum[i] = (checksum % 8) + '0';
      checksum /= 8;
    }

    // Copy file data.
    memcpy(header->data, file->data, file->size);
    off += align_up(sizeof(struct tar_header) + file->size, SECTOR_SIZE);
  }

  // Write `disk` buffer into the virtio-blk.
  for (unsigned sector = 0; sector < sizeof(disk) / SECTOR_SIZE; sector++)
    read_write_disk(&disk[sector * SECTOR_SIZE], sector, true);

  printf("wrote %d bytes to disk\n", sizeof(disk));
}

struct file *fs_lookup(const char *filename) {
  for (int i = 0; i < FILES_MAX; i++) {
    struct file *file = &files[i];
    if (!strcmp(file->name, filename))
      return file;
  }

  return NULL;
}

__attribute__((naked)) void user_entry(void) {
  __asm__ __volatile__(
      "csrw sepc, %[sepc]       \n"
      "csrw sstatus, %[sstatus] \n"
      "sret                     \n"
      :
      : [sepc] "r"(USER_BASE), [sstatus] "r"(SSTATUS_SPIE | SSTATUS_SUM));
}

void handle_syscall(struct trap_frame *f) {
  switch (f->a3) {
  case SYS_GETCHAR:
    while (1) {
      long ch = getchar();
      if (ch >= 0) { // 명령어 입력 끝
        f->a0 = ch;
        break;
      }

      yield();
    }
    break;
  case SYS_PUTCHAR:
    putchar(f->a0);
    break;
  case SYS_EXIT:
    printf("process %d exited\n", current_proc->pid);
    current_proc->state = PROC_EXITED;
    yield();
    PANIC("unreachable");
  case SYS_READFILE:
  case SYS_WRITEFILE: {
    // 시스템 콜 인자 추출
    const char *filename = (const char *)f->a0; // 파일 이름
    char *buf = (char *)f->a1;                  // 데이터 버퍼
    int len = f->a2;                            // 읽기/쓰기 길이

    // 파일 찾기
    struct file *file = fs_lookup(filename);
    if (!file) {
      printf("file not found: %s\n", filename);
      f->a0 = -1; // 에러 반환
      break;
    }

    // 버퍼 크기 제한
    if (len > (int)sizeof(file->data))
      len = file->size;

    // 읽기/쓰기 작업 수행
    if (f->a3 == SYS_WRITEFILE) {
      memcpy(file->data, buf, len); // 버퍼의 데이터를 파일에 복사
      file->size = len;             // 파일 크기 업데이트
      fs_flush();                   // 디스크에 변경사항 반영
    } else {
      memcpy(buf, file->data, len); // 파일의 데이터를 버퍼에 복사
    }

    f->a0 = len; // 처리된 바이트 수 반환
    break;
  }
  default:
    PANIC("unexpected syscall a3=%x\n", f->a3);
  }
}

void handle_trap(struct trap_frame *f) {
  uint32_t scause = READ_CSR(scause);
  uint32_t stval = READ_CSR(stval);
  uint32_t user_pc = READ_CSR(sepc);

  if (scause == SCAUSE_ECALL) { // ecall로 인한 예외
    handle_syscall(f);
    user_pc += 4;
  } else {
    PANIC("unexpected trap scause=%x, stval=%x, sepc=%x\n", scause, stval,
          user_pc);
  }

  WRITE_CSR(sepc, user_pc);
}

__attribute__((naked)) __attribute__((aligned(4))) void kernel_entry(void) {
  __asm__ __volatile__(

      "csrrw sp, sscratch, sp\n" // sp와 sscratch 값을 스왑

      "addi sp, sp, -4 * 31\n"
      "sw ra,  4 * 0(sp)\n"
      "sw gp,  4 * 1(sp)\n"
      "sw tp,  4 * 2(sp)\n"
      "sw t0,  4 * 3(sp)\n"
      "sw t1,  4 * 4(sp)\n"
      "sw t2,  4 * 5(sp)\n"
      "sw t3,  4 * 6(sp)\n"
      "sw t4,  4 * 7(sp)\n"
      "sw t5,  4 * 8(sp)\n"
      "sw t6,  4 * 9(sp)\n"
      "sw a0,  4 * 10(sp)\n"
      "sw a1,  4 * 11(sp)\n"
      "sw a2,  4 * 12(sp)\n"
      "sw a3,  4 * 13(sp)\n"
      "sw a4,  4 * 14(sp)\n"
      "sw a5,  4 * 15(sp)\n"
      "sw a6,  4 * 16(sp)\n"
      "sw a7,  4 * 17(sp)\n"
      "sw s0,  4 * 18(sp)\n"
      "sw s1,  4 * 19(sp)\n"
      "sw s2,  4 * 20(sp)\n"
      "sw s3,  4 * 21(sp)\n"
      "sw s4,  4 * 22(sp)\n"
      "sw s5,  4 * 23(sp)\n"
      "sw s6,  4 * 24(sp)\n"
      "sw s7,  4 * 25(sp)\n"
      "sw s8,  4 * 26(sp)\n"
      "sw s9,  4 * 27(sp)\n"
      "sw s10, 4 * 28(sp)\n"
      "sw s11, 4 * 29(sp)\n"

      "csrr a0, sscratch\n"  // sscratch(원래 프로세스의 sp)를 a0에 읽어옴
      "sw a0,  4 * 30(sp)\n" // 예외 발생 시점의 sp 값을 저장

      "addi a0, sp, 4 * 31\n" // a0에 (sp + 31*4)를 계산 후 저장
      "csrw sscratch, a0\n"   // 다음 예외를 위해 sscratch 레지스터 재설정

      "mv a0, sp\n"
      "call handle_trap\n"

      "lw ra,  4 * 0(sp)\n"
      "lw gp,  4 * 1(sp)\n"
      "lw tp,  4 * 2(sp)\n"
      "lw t0,  4 * 3(sp)\n"
      "lw t1,  4 * 4(sp)\n"
      "lw t2,  4 * 5(sp)\n"
      "lw t3,  4 * 6(sp)\n"
      "lw t4,  4 * 7(sp)\n"
      "lw t5,  4 * 8(sp)\n"
      "lw t6,  4 * 9(sp)\n"
      "lw a0,  4 * 10(sp)\n"
      "lw a1,  4 * 11(sp)\n"
      "lw a2,  4 * 12(sp)\n"
      "lw a3,  4 * 13(sp)\n"
      "lw a4,  4 * 14(sp)\n"
      "lw a5,  4 * 15(sp)\n"
      "lw a6,  4 * 16(sp)\n"
      "lw a7,  4 * 17(sp)\n"
      "lw s0,  4 * 18(sp)\n"
      "lw s1,  4 * 19(sp)\n"
      "lw s2,  4 * 20(sp)\n"
      "lw s3,  4 * 21(sp)\n"
      "lw s4,  4 * 22(sp)\n"
      "lw s5,  4 * 23(sp)\n"
      "lw s6,  4 * 24(sp)\n"
      "lw s7,  4 * 25(sp)\n"
      "lw s8,  4 * 26(sp)\n"
      "lw s9,  4 * 27(sp)\n"
      "lw s10, 4 * 28(sp)\n"
      "lw s11, 4 * 29(sp)\n"
      "lw sp,  4 * 30(sp)\n"
      "sret\n");
}

struct process *create_process(const void *image, size_t image_size) {
  // 미사용(UNUSED) 상태의 프로세스 구조체 찾기
  struct process *proc = NULL;
  int i;
  for (i = 0; i < PROCS_MAX; i++) {
    if (procs[i].state == PROC_UNUSED) {
      proc = &procs[i];
      break;
    }
  }

  if (!proc)
    PANIC("no free process slots");

  // 커널 스택에 callee-saved 레지스터 공간을 미리 준비
  uint32_t *sp = (uint32_t *)&proc->stack[sizeof(proc->stack)];
  *--sp = 0;                    // s11
  *--sp = 0;                    // s10
  *--sp = 0;                    // s9
  *--sp = 0;                    // s8
  *--sp = 0;                    // s7
  *--sp = 0;                    // s6
  *--sp = 0;                    // s5
  *--sp = 0;                    // s4
  *--sp = 0;                    // s3
  *--sp = 0;                    // s2
  *--sp = 0;                    // s1
  *--sp = 0;                    // s0
  *--sp = (uint32_t)user_entry; // ra (처음 실행 시 점프할 주소)

  // Map kernel pages.
  uint32_t *page_table = (uint32_t *)alloc_pages(1);
  for (paddr_t paddr = (paddr_t)__kernel_base; paddr < (paddr_t)__free_ram_end;
       paddr += PAGE_SIZE)
    map_page(page_table, paddr, paddr, PAGE_R | PAGE_W | PAGE_X);

  // Map MMIO pages.
  map_page(page_table, VIRTIO_BLK_PADDR, VIRTIO_BLK_PADDR, PAGE_R | PAGE_W);

  // Map user pages.
  for (uint32_t off = 0; off < image_size; off += PAGE_SIZE) {
    paddr_t page = alloc_pages(1);

    size_t remaining = image_size - off;
    size_t copy_size = PAGE_SIZE <= remaining ? PAGE_SIZE : remaining;

    // Fill and map the page.
    memcpy((void *)page, image + off, copy_size);
    map_page(page_table, USER_BASE + off, page,
             PAGE_U | PAGE_R | PAGE_W | PAGE_X);
  }

  // 구조체 필드 초기화
  proc->pid = i + 1;
  proc->state = PROC_RUNNABLE;
  proc->sp = (uint32_t)sp;
  proc->page_table = page_table;
  return proc;
}

////////////////////////////////////////////////////////////////////////////////////

void kernel_main(void) {
  memset(__bss, 0, (size_t)__bss_end - (size_t)__bss);

  printf("\n\n");

  WRITE_CSR(stvec, (uint32_t)kernel_entry);

  virtio_blk_init();

  fs_init();

  idle_proc = create_process(NULL, 0);
  idle_proc->pid = 0;
  current_proc = idle_proc;

  create_process(_binary_shell_bin_start, (size_t)_binary_shell_bin_size);

  yield();
  PANIC("unreachable");
}

__attribute__((section(".text.boot"))) __attribute__((naked)) void boot(void) {
  __asm__ __volatile__(
      "mv sp, %[stack_top]\n" // Set the stack pointer
      "j kernel_main\n"       // Jump to the kernel main function
      :
      : [stack_top] "r"(
          __stack_top) // Pass the stack top address as %[stack_top]
  );
}
