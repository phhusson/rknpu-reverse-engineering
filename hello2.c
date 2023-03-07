#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <libdrm/drm.h>
#include <sys/mman.h>

#include "rknpu-ioctl.h"

void* mem_allocate(int fd, size_t size, uint64_t *dma_addr, uint64_t *obj, int flags) {
    int ret;

    struct rknpu_mem_create mem_create = {
        .flags = RKNPU_MEM_IOMMU | RKNPU_MEM_ZEROING | flags | RKNPU_MEM_CACHEABLE,
        .size = size,
    };

    ret = ioctl(fd, DRM_IOCTL_RKNPU_MEM_CREATE, &mem_create);
    if(ret < 0) exit(2);
    fprintf(stderr, "mem create returned handle %08x, obj_addr %16llx dma_addr %16llx\n", mem_create.handle, mem_create.obj_addr, mem_create.dma_addr);

    struct rknpu_mem_map mem_map = { .handle = mem_create.handle };
    ret = ioctl(fd, DRM_IOCTL_RKNPU_MEM_MAP, &mem_map);
    printf("memmap returned %d %llx\n", ret, mem_map.offset);
    void *map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mem_map.offset);
    if(ret < 0) exit(2);
    printf("mmap returned %p\n", mmap);

    *dma_addr = mem_create.dma_addr;
    *obj = mem_create.obj_addr;

    return map;
}

void mem_sync(int fd, uint64_t obj_addr, uint64_t offset, uint64_t size) {
    int ret;

    struct rknpu_mem_sync m_sync = {
        .obj_addr = obj_addr,
        .offset = offset,
        .size = size,
		.flags = RKNPU_MEM_SYNC_TO_DEVICE,
    };
    ret = ioctl(fd, DRM_IOCTL_RKNPU_MEM_SYNC, &m_sync);
    printf("memsync returned %d\n", ret);
}

int main(int argc, char **argv) {
    char buf1[256], buf2[256], buf3[256];
    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));
    memset(buf3, 0, sizeof(buf3));

    int ret;
    // Open DRI called "rknpu"
    int fd = open("/dev/dri/card1", O_RDWR);
    if(fd<0) exit(1);
    struct drm_version dv;
    memset(&dv, 0, sizeof(dv));
    dv.name = buf1;
    dv.name_len = sizeof(buf1);
    dv.date = buf2;
    dv.date_len = sizeof(buf2);
    dv.desc = buf3;
    dv.desc_len = sizeof(buf3);

    ret = ioctl(fd, DRM_IOCTL_VERSION, &dv);
    printf("drm name is %s - %s - %s\n", dv.name, dv.date, dv.desc);
    if(ret < 0) exit(2);

    struct drm_unique du;
    du.unique = buf1;
    du.unique_len = sizeof(buf1);;
    ret = ioctl(fd, DRM_IOCTL_GET_UNIQUE, &du);
    printf("du is %s\n", du.unique);
    if(ret < 0) exit(2);

    uint64_t instr_dma, instr_obj;
    uint64_t *instrs = mem_allocate(fd, 1024*1024, &instr_dma, &instr_obj, 0);

	// Why is this a GEM?!?
    uint64_t tasks_dma, tasks_obj;
    struct rknpu_task *tasks = mem_allocate(fd, 1024*1024, &tasks_dma, &tasks_obj, RKNPU_MEM_KERNEL_MAPPING);

    uint64_t input_dma, input_obj;
    void *input = mem_allocate(fd, 1024*1024, &input_dma, &input_obj, 0);

    uint64_t weight_dma, weight_obj;
    void *weight = mem_allocate(fd, 1024*1024, &weight_dma, &weight_obj, 0);

    uint64_t output_dma, output_obj;
    void *output = mem_allocate(fd, 1024*1024, &output_dma, &output_obj, 0);

	struct rknpu_action act = {
		.flags = RKNPU_ACT_RESET,
	};
	ioctl(fd, DRM_IOCTL_RKNPU_ACTION, &act);

#define IRQ_CNA_FEATURE_GROUP0	(1 << 0)
#define IRQ_CNA_FEATURE_GROUP1	(1 << 1)
#define IRQ_CNA_WEIGHT_GROUP0	(1 << 2)
#define IRQ_CNA_WEIGHT_GROUP1	(1 << 3)
#define IRQ_CNA_CSC_GROUP0		(1 << 4)
#define IRQ_CNA_CSC_GROUP1		(1 << 5)
#define IRQ_CORE_GROUP0			(1 << 6)
#define IRQ_CORE_GROUP1			(1 << 7)
#define IRQ_DPU_GROUP0			(1 << 8)
#define IRQ_DPU_GROUP1			(1 << 9)
#define IRQ_PPU_GROUP0			(1 << 10)
#define IRQ_PPU_GROUP1			(1 << 11)
#define IRQ_DMA_READ_ERROR		(1 << 12)
#define IRQ_DMA_WRITE_ERROR		(1 << 13)

#define RKNPU_JOB_DONE (1 << 0)
#define RKNPU_JOB_ASYNC (1 << 1)
#define RKNPU_JOB_DETACHED (1 << 2)

#define RKNPU_CORE_AUTO_MASK 0x00
#define RKNPU_CORE0_MASK 0x01
#define RKNPU_CORE1_MASK 0x02
#define RKNPU_CORE2_MASK 0x04


#if 0
	for(int i=0; i<10; i++) {
		instrs[0 + 4 * i] = (0x0101 << 48) | 0x14 | (instr_dma << 8); // Jump to xxx
		instrs[1 + 4 * i] = 0x0101000000000014; // Write 0 instructions left (Write 0 to pc_register_amounts 0x14)
		instrs[2 + 4 * i] = 0x0041000000000000; // Documentation says that this is needed...
		instrs[3 + 4 * i] = 0x0101000000000014; // Write 0 instructions left (Write 0 to pc_register_amounts 0x14)
		//instrs[3 + 4 * i] = 0x00810000000d0008; // Set all block's op_en to true
	}
#else
#define INSTR(TGT, value, reg) (((uint64_t)TGT)<< 48) | ( ((uint64_t)value) << 16) | (uint64_t)reg
    int nInstrs = 0;

#include "instrs.h"
#endif

	tasks[0].flags  = 0;
	tasks[0].op_idx = 1;
	tasks[0].enable_mask = 0x7f; //unused?!?
	//tasks[0].int_mask = 0x1ffff; // Ask for any interrupt at all...?
	tasks[0].int_mask = 0x00c;
	tasks[0].int_clear = 0x1ffff;
	tasks[0].regcfg_amount = nInstrs - 0;
	tasks[0].regcfg_offset = 0;
	tasks[0].regcmd_addr = instr_dma;

	mem_sync(fd, tasks_obj, 0, 1024*1024);
	mem_sync(fd, instr_obj, 0, 1024*1024);

	struct rknpu_submit submit = {
		.flags = RKNPU_JOB_PC | RKNPU_JOB_BLOCK /*| RKNPU_JOB_PINGPONG*/,
		.timeout = 1000,
		.task_start = 0,
		.task_number = 1,
		.task_counter = 0,
		.priority = 0,
		.task_obj_addr = tasks_obj,
		.regcfg_obj_addr = 0, // unused?
		.task_base_addr = instr_dma,
		.user_data = 0, //unused
		.core_mask = 1, // = auto
		.fence_fd = 0, //unused because flags didn't ask for a fence in .flags
		.subcore_task = {
			// Only use core 1, nothing for core 2/3
			{
				.task_start = 0,
				.task_number = 1,
			}, { 0, 0}, {0, 0},
		},
	};

	ret = ioctl(fd, DRM_IOCTL_RKNPU_SUBMIT, &submit);
	printf("Submit returned %d\n", ret);

    return 0;
}
