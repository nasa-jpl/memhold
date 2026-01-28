#include <cassert>
#include <csignal>
#include <ctime>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <fstream>
#include <sstream>
#include <iostream>
#include <system_error>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include <algorithm>
#include <map>
#include <vector>

#include "pfn_utils.hpp"

/* Print the location of all PFNs in pfn_list.txt within the system
 *
 * Example output:
 * root@linaro-developer:/video# ./pfn_find pfn_list.txt 0
 * PID 1980 (bash)
 *  PFN 046447: c4000 (000b3000-000e6000 rw-p 00000000 00:00 0          [heap])
 * PID 1999 (pfn_find)
 *  PFN 064a28: d6000 (000d6000-000fd000 rw-p 00000000 00:00 0          [heap])
 *  PFN 0464ff: da000 (000d6000-000fd000 rw-p 00000000 00:00 0          [heap])
 *  PFN 04672d: dc000 (000d6000-000fd000 rw-p 00000000 00:00 0          [heap])
 *  PFN 046c7a: dd000 (000d6000-000fd000 rw-p 00000000 00:00 0          [heap])
 *  PFN 04dca8: de000 (000d6000-000fd000 rw-p 00000000 00:00 0          [heap])
 *  PFN 04dc7b: e5000 (000d6000-000fd000 rw-p 00000000 00:00 0          [heap])
 *  PFN 050c08: e6000 (000d6000-000fd000 rw-p 00000000 00:00 0          [heap])
 *  PFN 062e1c: b6ef7000 (b6ef7000-b6efa000 rw-p 00000000 00:00 0 )
 *  PFN 05afb1: b6ef8000 (b6ef7000-b6efa000 rw-p 00000000 00:00 0 )
 *  PFN 05ab2e: b6ef9000 (b6ef7000-b6efa000 rw-p 00000000 00:00 0 )
 *  PFN 051f53: b6fc7000 (b6fc7000-b6fcd000 rw-p 00000000 00:00 0 )
 */


static bool g_verbose = false;

void print_help() {

    fprintf(stderr, "pfn_find: pfn_list.txt verbose\n");
    fprintf(stderr, "pfn_list.txt: List of Page Frame Numbers to find. File should have one pfn per line. PFN are expected to be hexadecimal\n");
    fprintf(stderr, "verbose: verbose printing\n");
}

/* Mapping of kpageflags bits to strings.
 * See https://github.jpl.nasa.gov/Leonardo/leonardo-nav-linux/blob/LNX.LER.1.0/Documentation/vm/pagemap.txt
 */
const std::map<uint64_t, const char*> kpageflags_map = {
    {0, "LOCKED"},
    {1, "ERROR"},
    {2, "REFERENCED"},
    {3, "UPTODATE"},
    {4, "DIRTY"},
    {5, "LRU"},
    {6, "ACTIVE"},
    {7, "SLAB"},
    {8, "WRITEBACK"},
    {9, "RECLAIM"},
    {10, "BUDDY"},
    {11, "MMAP"},
    {12, "ANON"},
    {13, "SWAPCACHE"},
    {14, "SWAPBACKED"},
    {15, "COMPOUND_HEAD"},
    {16, "COMPOUND_TAIL"},
    {17, "HUGE"},
    {18, "UNEVICTABLE"},
    {19, "HWPOISON"},
    {20, "NOPAGE"},
    {21, "KSM"},
    {22, "THP"},
};

/* Print the current value of kpageflags for
 * each PFN that is mapped somewhere in the system
 * If the PFN is not mapped (flags==0), then do
 * not print anything
 */
void print_pfn_flags(const std::vector<int64_t>& pfn_list) {

    /* From man proc_kpageflags
     *  This file contains 64-bit masks corresponding to each
     *  physical page frame; it is indexed by page frame number
     *  (see the discussion of /proc/pid/pagemap). 
     */
    int kpageflags_fd = open("/proc/kpageflags", O_RDONLY);
    if (kpageflags_fd < 0) { 
        fprintf(stderr, "Unable to open kpageflags\n");
        perror("open: ");
        exit(-1);
    }

    int64_t loop_counter = 0;
    for (const int64_t pfn : pfn_list) {

        if (loop_counter >= MAX_PFN) {
            fprintf(stderr, "Loop Counter Exceeded at %s:%d",
                    __FILE__, __LINE__);
            exit(-1);
        }
        loop_counter++;

        off_t pfn_off = pfn * sizeof(uint64_t);
        off_t lseek_ok = lseek(kpageflags_fd, pfn_off, SEEK_SET);
        if (lseek_ok == (off_t)-1) {
            fprintf(stderr, "Unabled to lseek to pfn %lld in kpageflags\n",
                    pfn);
            perror("lseek: ");
            exit(-1);
        }

        uint64_t flags;
        ssize_t read_ok = read(kpageflags_fd, &flags, sizeof(flags));
        if (read_ok != sizeof(flags)) {
            fprintf(stderr, "Unable to read kpageflags for pfn %lld\n",
                    pfn);
            perror("read: ");
            exit(-1);
        }

        bool printed_pfn = false;

        for (uint64_t idx = 0; idx <= 22; idx++) {
            const uint64_t mask = (1ULL << idx);
            if (flags & mask) {

                if (!printed_pfn) {
                    printf("PFN %06llx: %08llx ",
                           pfn, flags);
                    printed_pfn = true;
                }
                printf("%s ", kpageflags_map.at(idx));
            }
        }
        if (printed_pfn) {
            printf("\n");
        }
    }

    close(kpageflags_fd);
}

/* Print the PFNs in the pfn_list that are currently
 * mapped in the address space for (pid)
 *
 * Optionally filter out any process which is not named (filter_comm)
 *
 * Return a list of PFNs found for the process
 */
std::vector<int64_t> print_pfns_for_pid(const std::vector<int64_t>& pfn_list,
                                        const int64_t pid,
                                        const std::string filter_comm) {

    assert(pid > 0);

    std::vector<int64_t> found_pfns;

    std::stringstream comm_fname;
    comm_fname << "/proc/" << pid << "/comm";
    std::string comm_str;
    std::ifstream comm_f(comm_fname.str().c_str(), std::ios::in);
    if (comm_f.is_open()) {
        std::getline(comm_f, comm_str);
        comm_f.close();
    } else {
        // Use a token name "???" if the comm file could not be opened
        comm_str = "???";
    }

    // If filter_comm is valid and it does not match
    // the current process name, exit
    if (filter_comm != "" &&
        filter_comm != comm_str) {
        return found_pfns;
    }

    bool pid_printed = false;
    if (g_verbose) {
        pid_printed = true;
        printf("PID %lld (%s)\n",
               pid, comm_str.c_str());
    }

    /* Use the /proc/pid/maps file to locate
     * valid virual address spaces within the process
     */
    std::stringstream maps_fname;
    maps_fname << "/proc/" << pid << "/maps";
    std::fstream maps_f(maps_fname.str().c_str(), std::ios::in);
    if (!maps_f.is_open()) {
        fprintf(stderr, "Unable to open %s\n",
                maps_fname.str().c_str());
        exit(-1);
    }

    std::stringstream pagemap_fname;
    pagemap_fname << "/proc/" << pid << "/pagemap";
    int pagemap_fd = open(pagemap_fname.str().c_str(),
                          O_RDONLY);
    if (pagemap_fd < 0) {
        fprintf(stderr, "Unable to open %s\n",
                pagemap_fname.str().c_str());
        perror("open: ");
        exit(-1);
    }

    int64_t loop_counter = 0;
    for (std::string mapping; std::getline(maps_f, mapping);) {

        if (loop_counter >= MAX_PFN) {
            fprintf(stderr, "Loop Counter Exceeded at %s:%d",
                    __FILE__, __LINE__);
            exit(-1);
        }
        loop_counter++;

        // Note: A line the /proc/pid/maps looks like the following
        // 000ae000-000b3000 rw-p 0009e000 b3:0d 14         /bin/bash
        // Only interested in the start and end addresses for the mapping
        int64_t virt_start, virt_end;
        int ok = sscanf(mapping.c_str(),
                        "%llx-%llx ",
                        &virt_start,
                        &virt_end);
        if (ok != 2) {
            fprintf(stderr, "Unable to parser mapping (%s)\n",
                    mapping.c_str());
            perror("sscanf: ");
            exit(-1);
        }

        if (virt_start == 0xffff0000 &&
            virt_end == 0xffff1000) {
            // This is a [vector] mapping on the Snapdragon. Cannot read the pagemap
            // for this page. Ignore it
            continue;
        }

        if (g_verbose) {
            fprintf(stderr, "Mapping (%s)\n", mapping.c_str());
            fprintf(stderr, "Searching Range %llx-%llx\n", virt_start, virt_end);
        }

        assert(virt_end > virt_start);

        // Move the pagemap fd to the start of the current virtual address range
        off_t pagemap_off = (virt_start / PAGE_SIZE) * sizeof(uint64_t);
        off_t lseek_ok = lseek(pagemap_fd, (virt_start / PAGE_SIZE) * sizeof(uint64_t), SEEK_SET);
        if (lseek_ok != pagemap_off) {
            fprintf(stderr, "Unable to lseek to addr %llx (off %ld)\n",
                    virt_start, pagemap_off);
            perror("lseek: ");
            exit(-1);
        }

        /* Walk each page in the virtual address range and print it
         * if the backing memory is one of the bad PFNs
         */
        for (int64_t virt = virt_start; virt < virt_end; virt += PAGE_SIZE) {
            uint64_t pm_entry;
            ssize_t read_ok = read(pagemap_fd, &pm_entry, sizeof(pm_entry));
            if (read_ok != sizeof(pm_entry)) {
                fprintf(stderr, "Unable to read pagemap for addr %llx\n",
                        virt);
                perror("read: ");
                exit(-1);
            }

            int64_t pfn = pfn_for_pagemap_entry(pm_entry);

            if (pfn < 0) {
                continue;
            }
            assert(PFN_VALID(pfn));

            if (std::find(pfn_list.begin(),
                          pfn_list.end(),
                          pfn) != pfn_list.end()) {

                if (!pid_printed) {
                    pid_printed = true;
                    printf("PID %lld (%s)\n",
                           pid, comm_str.c_str());
                }
                printf(" PFN %06llx: %llx (%s)\n",
                       pfn, virt,
                       mapping.c_str());

                // Store the PFN in the found_pfns list if
                // it is unique
                if (std::find(found_pfns.begin(),
                              found_pfns.end(),
                              pfn) == found_pfns.end()) {
                    found_pfns.push_back(pfn);
                }
            }
        }
    }

    return found_pfns;
}

int main(int argc, char** argv) {

    enum {
        ARG_PFN_LIST = 1,
        ARG_VERBOSE,
        ARG_PROCESS,
        ARG_MAX
    };

    if (argc < ARG_PROCESS || argc > ARG_MAX) {
        print_help();
        return -1;
    }

    const char* pfn_list_fname = argv[ARG_PFN_LIST];
    const char* verbose_arg = argv[ARG_VERBOSE];
    const char* process_arg = argc >= ARG_PROCESS ? 
                              argv[ARG_PROCESS] : nullptr;


    std::ifstream pfn_list_f(pfn_list_fname, std::ios::in);
    if (!pfn_list_f.is_open()) {
        fprintf(stderr, "Unable to open file %s\n", pfn_list_fname);
        print_help();
        return -1;
    }

    const int64_t verbose = std::strtoll(verbose_arg, nullptr, 10);
    if (verbose == LLONG_MAX || 
        verbose == LLONG_MIN) {
        fprintf(stderr, "Unable to parse verbose arg\n");
        perror("strtoll: ");
        print_help();
        return -1;
    }

    g_verbose = verbose > 0;

    std::string filter_comm = process_arg != nullptr ?
                              std::string(process_arg) : "";

    std::vector<int64_t> pfn_list = read_pfn_list(pfn_list_f);
    pfn_list_f.close();

    if (pfn_list.size() == 0) {
        fprintf(stderr, "error processing pfn list\n");
        return -1;
    }

    DIR* proc_dir = opendir("/proc");
    if (proc_dir == nullptr) {
        fprintf(stderr, "Unabled to open /proc");
        perror("opendir: ");
        return -1;
    }

    if (g_verbose) {
        print_pfn_flags(pfn_list);
    }

    std::vector<int64_t> found_pfns;

    struct dirent* dirent;
    int64_t dir_loop_counter = 0;
    while ((dirent = readdir(proc_dir)) != nullptr) {

        if (dir_loop_counter > (100*1000)) {
            fprintf(stderr, "Loop Counter Exceeded at %s:%d",
                    __FILE__, __LINE__);
            exit(-1);
        }
        dir_loop_counter++;

        if (dirent->d_type != DT_DIR) {
            continue;
        }

        int64_t pid = strtoll(dirent->d_name, nullptr, 10);
        if (pid == LLONG_MAX ||
            pid == LLONG_MIN ||
            pid <= 0) {
            continue;
        }

        std::vector<int64_t> pid_pfns;
        pid_pfns = print_pfns_for_pid(pfn_list, pid, filter_comm);

        int64_t pfn_loop_counter = 0;
        for (const int64_t pfn : pid_pfns) {
            if (pfn_loop_counter > (100*1000)) {
                fprintf(stderr, "Loop Counter Exceeded at %s:%d",
                        __FILE__, __LINE__);
                exit(-1);
            }
            pfn_loop_counter++;

            if (std::find(found_pfns.begin(),
                          found_pfns.end(),
                          pfn) == found_pfns.end()) {
                found_pfns.push_back(pfn);
            }
        }
    }

    std::vector<int64_t> missing_pfns = pfn_list;
    int64_t pfn_loop_counter = 0;
    for (int64_t found_pfn : found_pfns) {
        if (pfn_loop_counter > (100*1000)) {
            fprintf(stderr, "Loop Counter Exceeded at %s:%d",
                    __FILE__, __LINE__);
            exit(-1);
        }
        pfn_loop_counter++;


        // Find the pfn in the pfn list
        auto pfn_loc = std::find(missing_pfns.begin(),
                                 missing_pfns.end(),
                                 found_pfn);
        // It should be present. found_pfns is a subset
        // of pfn_list with no repeating elements.
        // Therefore, each PFN should only be removed
        // at most once
        assert(pfn_loc != missing_pfns.end());

        missing_pfns.erase(pfn_loc);
    }

    std::vector<int64_t> inuse_missing_pfns = find_inuse_pfns(missing_pfns);

    printf("Possible Kernel PFNs:\n");
    print_pfn_flags(inuse_missing_pfns);

    return 0;
}

