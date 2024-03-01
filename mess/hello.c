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

void register3_stuff(int fd) {
    int ret;
    struct drm_gem_open gopen = { .name = 3 };
    ret = ioctl(fd, DRM_IOCTL_GEM_OPEN, &gopen);
    printf("gem open got %d %d %lld\n", ret, gopen.handle, gopen.size);
    if(ret < 0) exit(2);

    struct rknpu_mem_map mem_map = { .handle = gopen.handle };
    ret = ioctl(fd, DRM_IOCTL_RKNPU_MEM_MAP, &mem_map);
    printf("memmap returned %d %llx\n", ret, mem_map.offset);
    void *instr_map = mmap(NULL, gopen.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mem_map.offset);
    if(ret < 0) exit(2);
    printf("mmap returned %p\n", mmap);

    int fdo = open("/data/local/tmp/gem3-dump", O_WRONLY | O_CREAT, 0640);
    write(fdo, instr_map, gopen.size);
    close(fdo);

    uint32_t *instrs = (uint32_t*)instr_map;
    // Blocks of 10 * uint32
    uint32_t a;
    for(int i=0; i < (gopen.size / 40); i++) {
        uint32_t *instrs = (uint32_t*)(instr_map + i * 40);
        // instrs[0] always 0
        // instrs[1] increments non-monotenously ("1" appear three times, "0" never, and then one for each? and  then loops at &~0x1f)
        //     on 2 layers 5x5 it goes 1 2 3 3 1 2 3 3 1 2 3 3
        // instrs[2] == 0x1d || 0x60 || 0x18 || 0xd
        // instrs[3] == 0x300 || 0xc00 ||
        // instrs[4] == 0x1ffff
        // instrs[5] == 0 || 0x100 || 0x800 || 0x200 || 
        // instrs[6] == 0x7c | 0x1a | 0x45 | 0x6a 0x45
        // instrs[7] == ????? deltas ranging between 0x80 to 0x300, can be negative
        // instrs[8] == Some address in gem2
        printf("[%d] %d\n", i, instrs[7] - a);
        printf("\t%x\n", instrs[8]);
        a = instrs[7];
        if(instrs[8] == 0) break;
    }
}

void dump_gem(int fd, int id) {
    int ret;
    struct drm_gem_open gopen = { .name = id };
    ret = ioctl(fd, DRM_IOCTL_GEM_OPEN, &gopen);
    printf("gem open got %d %d %lld\n", ret, gopen.handle, gopen.size);
    if(ret < 0) exit(2);

    struct rknpu_mem_map mem_map = { .handle = gopen.handle };
    ret = ioctl(fd, DRM_IOCTL_RKNPU_MEM_MAP, &mem_map);
    printf("memmap returned %d %llx\n", ret, mem_map.offset);
    void *instr_map = mmap(NULL, gopen.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mem_map.offset);
    if(ret < 0) exit(2);
    printf("mmap returned %p\n", mmap);

    printf("Gem %d\n", id);
    for(int i=0; i < gopen.size ; i+= 4 * sizeof(uint32_t)) {
        uint32_t *here = (uint32_t*)(instr_map + i);
        printf("[%08x] = %08x %08x %08x %08x\n", i, here[0], here[1], here[2], here[3]);
    }
    munmap(instr_map, gopen.size);
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

#if 1
    for(int i=1; i<=6; i++) {
        dump_gem(fd, i);
    }
#endif

    register3_stuff(fd);

    struct drm_gem_open gopen = { .name = 2 };
    ret = ioctl(fd, DRM_IOCTL_GEM_OPEN, &gopen);
    printf("gem open got %d %d %lld\n", ret, gopen.handle, gopen.size);
    if(ret < 0) exit(2);

    struct rknpu_mem_map mem_map = { .handle = gopen.handle };
    ret = ioctl(fd, DRM_IOCTL_RKNPU_MEM_MAP, &mem_map);
    printf("memmap returned %d %llx\n", ret, mem_map.offset);
    void *instr_map = mmap(NULL, gopen.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mem_map.offset);
    if(ret < 0) exit(2);
    printf("mmap returned %p\n", mmap);

    int fdo = open("/data/local/tmp/gem2-dump", O_WRONLY | O_CREAT, 0640);
    write(fdo, instr_map, gopen.size);
    close(fdo);

    // blocks of 64bits
    uint64_t *instrs = (uint32_t*)instr_map;
    for(int i=0; i < (gopen.size / 8); i++) {
        uint64_t instr = instrs[i];
        uint32_t val = (instr >> 16) & 0xffffffff;

        //high/low remaining after extracting paddr
        uint16_t high = (instr >> 48) & 0xffff;
        uint16_t low = (instr) & 0xffff;

        char *op_en = (instr >> 55) & 1 ? "Enable op" : "";
        char *dst = "noone";
        if( (instr >> 56) & 1)
            dst = "pc";
        else if( (instr >> 57) & 1)
            dst = "cna";
        else if( (instr >> 59) & 1)
            dst = "core";
        else if( (instr >> 60) & 1)
            dst = "dpu";
        else if( (instr >> 61) & 1)
            dst = "dpu_rdma";
        else if( (instr >> 62) & 1)
            dst = "ppu";
        else if( (instr >> 63) & 1)
            dst = "ppu_rdma";

        char *regName = NULL;
        switch (low) {
            case 0x1004: regName = "cna_s_pointer"; break;
            case 0x100c: regName = "cna_conv_reg1"; break;
            case 0x1010: regName = "cna_conv_reg2"; break;
            case 0x1014: regName = "cna_conv_reg3"; break;
            case 0x1020: regName = "cna_data_size0"; break;
            case 0x1024: regName = "cna_data_size1"; break;
            case 0x1028: regName = "cna_data_size2"; break;
            case 0x102C: regName = "cna_data_size3"; break;
            case 0x1030: regName = "cna_weight_size0"; break;
            case 0x1034: regName = "cna_weight_size1"; break;
            case 0x1038: regName = "cna_weight_size2"; break;
            case 0x3004: regName = "core_s_pointer"; break;
            case 0x4004: regName = "dpu_s_pointer"; break;
        }

        printf("[%x] lsb %016llx - tgt %s %s [%04x - %s] = %08x\n", 8 * i + 0xffef0000, instrs[i], dst, op_en, low, regName, val);
    }

    return 0;
}
