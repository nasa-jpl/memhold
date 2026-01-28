// stuck_bit_injector.cpp
//#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <cctype>

#define LOOP_HZ        10
#define NSEC_PER_SEC 1000000000L

#define PAGE_SIZE 4096ULL
#define PFN_MASK  ((1ULL<<55)-1)

bool is_mapped_by_any_user(off_t addr) {
    uint64_t target_pfn = (uint64_t)addr / PAGE_SIZE;
    DIR *d = opendir("/proc");
    if(!d) return true;  /* conservative */
    struct dirent *e;
    while((e = readdir(d))) {
        if (!isdigit(e->d_name[0])) continue;
        char maps_path[64], pagemap_path[64];
        snprintf(maps_path, sizeof(maps_path),
                 "/proc/%s/maps", e->d_name);
        snprintf(pagemap_path, sizeof(pagemap_path),
                 "/proc/%s/pagemap", e->d_name);

        FILE *maps = fopen(maps_path,"r");
        int pm_fd = open(pagemap_path,O_RDONLY);
        if (!maps || pm_fd<0) {
            if(maps) fclose(maps);
            if(pm_fd>=0) close(pm_fd);
            continue;
        }

        char line[256];
        while(fgets(line,sizeof(line),maps)) {
            uint64_t vstart, vend;
            if (sscanf(line, "%" SCNx64 "-%" SCNx64,
                       &vstart, &vend)!=2)
                continue;
            /* only one page needs checking */
            uint64_t v = vstart + ((addr - vstart) & (PAGE_SIZE-1));
            off_t index = (v / PAGE_SIZE) * sizeof(uint64_t);
            uint64_t entry;
            if (pread(pm_fd, &entry, sizeof(entry), index)
                == sizeof(entry))
            {
                uint64_t pfn = entry & PFN_MASK;
                if (pfn == target_pfn) {
                    fclose(maps);
                    close(pm_fd);
                    closedir(d);
                    return true;
                }
            }
        }
        fclose(maps);
        close(pm_fd);
    }
    closedir(d);
    return false;
}


bool is_in_iomem_reserved(off_t addr) {
    FILE *f = fopen("/proc/iomem","r");
    if(!f) return true;  /* be conservative */
    char line[256];
    while(fgets(line,sizeof(line),f)) {
        /* lines look like: "1a2b2000-1a2b3fff : System RAM" */
        uint64_t lo, hi;
        char tag[64];
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " : %63[^\n]",
                   &lo, &hi, tag)==3)
        {
            if ((uint64_t)addr >= lo && (uint64_t)addr <= hi) {
                /* if not plain “System RAM”, it’s in use */
                if (strstr(tag,"System RAM")==NULL) {
                    fclose(f);
                    return true;
                }
            }
        }
    }
    fclose(f);
    return false;
}


typedef struct {
    off_t    phys_addr;   // exact byte address
    uint8_t  fill;        // 0x00 or 0xFF
    void    *map_base;    // mmap base of the page
    off_t    page_off;    // phys_addr % pagesize
} stuck_t;

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr,"Usage: %s stuck_bits.conf\n", argv[0]);
        return 1;
    }

    // --- 1) Read config ---
    FILE *f = fopen(argv[1],"r");
    if (!f) { perror("fopen"); return 1; }

    size_t cap = 16, n = 0;
    stuck_t *arr = (stuck_t*)calloc(cap, sizeof(*arr));
    while (1) {
        char line[128];
        if (!fgets(line, sizeof(line), f)) break;
        // skip comments/blank
        if (line[0]=='#' || line[0]=='\n') continue;

        off_t addr;
        int bit;
        if (sscanf(line, "%li %d", &addr, &bit) != 2) {
            fprintf(stderr,"bad line: %s", line);
            continue;
        }

        if (is_in_iomem_reserved(addr)) {
            fprintf(stderr,"skip 0x%lx: kernel-reserved\n",addr);
            continue;
        }
        if (is_mapped_by_any_user(addr)) {
            fprintf(stderr,"skip 0x%lx: in use by a process\n",addr);
            continue;
        }
        /* safe to mmap and inject now */
        
        if (n >= cap) {
            cap *= 2;
            arr = (stuck_t*)realloc(arr, cap * sizeof(*arr));
        }
        arr[n].phys_addr = addr;
        arr[n].fill      = bit ? 0xFF : 0x00;
        n++;
    }
    fclose(f);
    if (n == 0) {
        fprintf(stderr,"no valid entries in config\n");
        return 1;
    }

    // --- 2) Open /dev/mem and mmap each page ---
    int memfd = open("/dev/mem", O_RDWR|O_SYNC);
    if (memfd < 0) { perror("open /dev/mem"); return 1; }

    long pg = sysconf(_SC_PAGESIZE);
    for (size_t i = 0; i < n; i++) {
        off_t pa = arr[i].phys_addr;
        off_t page_base = pa & ~(pg - 1);
        arr[i].page_off  = pa - page_base;
        arr[i].map_base = mmap(NULL, pg,
                               PROT_READ|PROT_WRITE,
                               MAP_SHARED, memfd,
                               page_base);
        if (arr[i].map_base == MAP_FAILED) {
            fprintf(stderr,"mmap(0x%lx): %s\n",
                    page_base, strerror(errno));
            return 1;
        }
    }
    close(memfd);

    // --- 3) Write loop ---
    struct timespec delay = {
        .tv_sec  = 0,
        .tv_nsec = NSEC_PER_SEC / LOOP_HZ
    };

    printf("Beginning stuck bit injection with the following %d addresses and patterns\n", n);
    for (size_t i = 0; i < n; i++) {
        //uint8_t *ptr = (uint8_t*)arr[i].map_base + arr[i].page_off;
        printf("0x%lx : 0x%02X\n", arr[i].phys_addr, arr[i].fill);
    }
    fflush(NULL);
    
    while (1) {
        for (size_t i = 0; i < n; i++) {
            uint8_t *ptr = (uint8_t*)arr[i].map_base + arr[i].page_off;
            *ptr = arr[i].fill;
            // no mlock or msync: just hammer the DRAM
        }
        nanosleep(&delay, NULL);
    }

    return 0;
}
