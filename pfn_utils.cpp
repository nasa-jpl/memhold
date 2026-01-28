#include <cassert>
#include <csignal>
#include <ctime>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <fstream>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <vector>

#include "pfn_utils.hpp"

/* Read an input file of PFNs and store the values in a vector
 * Expects one PFN per line, formated in hex without a leading 0x
 * Ie.
 *  063443
 *  81234
 *  1234
 * Returns an empty list on failure
 */
std::vector<int64_t> read_pfn_list(std::ifstream& pfn_list_f) {

    int64_t loop_counter = 0;
    std::vector<int64_t> pfn_list;
    for (std::string pfn_s; std::getline(pfn_list_f, pfn_s);) {

        // Max loop counter. Consider this a failure case
        if (loop_counter >= MAX_PFN) {
            fprintf(stderr, "Loop Counter Exceeded at %s:%d",
                    __FILE__, __LINE__);
            exit(-1);
        }
        loop_counter++;

        // Parse the number of the line
        const int64_t pfn = strtoll(pfn_s.c_str(), nullptr, 16);
        if (pfn == LLONG_MAX ||
            pfn == LLONG_MIN) {
            fprintf(stderr, "Unable to parse pfn (%s)\n", pfn_s.c_str());
            perror("strtoll: ");
            return std::vector<int64_t>();
        }

        // Validate the PFN. Must be in range [0, 0x100000] for a 32-bit physical
        // address space
        if (!PFN_VALID(pfn)) {
            fprintf(stderr, "PFN numbers must be in range [0, 0x100000). %lld (%s)\n",
                    pfn, pfn_s.c_str());
            return std::vector<int64_t>();
        }

        pfn_list.push_back(pfn);
    }

    return pfn_list;
}

/* Search kpagecount for PFN numbers within pfn_list with counts >0 
 * This count will include any PFN numbers that are currently
 * stored in the jail space
 */
std::vector<int64_t> find_inuse_pfns(const std::vector<int64_t>& pfn_list) {

    std::vector<int64_t> inuse_pfns;

    /* From man proc_kpagecount
     *  This file contains a 64-bit count of the number of times
     *  each physical page frame is mapped, indexed by page frame
     *  number (see the discussion of /proc/pid/pagemap).
     */
    const int kpagecount_fd = open("/proc/kpagecount", O_RDONLY);
    if (kpagecount_fd < 0) {
        fprintf(stderr, "Unable to open /proc/kpagecount\n");
        perror("open: ");
        exit(-1);
    }

    int64_t loop_counter = 0;
    for (const int64_t pfn : pfn_list) {

        if (loop_counter > MAX_PFN) {
            fprintf(stderr, "Loop Counter Exceeded at %s:%d",
                    __FILE__, __LINE__);
            exit(-1);
        }
        loop_counter++;

        assert(PFN_VALID(pfn));

        off_t pfn_offset = pfn * sizeof(int64_t);
        off_t ret = lseek(kpagecount_fd, pfn_offset, SEEK_SET);
        if (ret != pfn_offset) {
            fprintf(stderr, "Unable to seek to pfn %lld. Offset %ld\n",
                    pfn, pfn_offset);
            perror("lseek: ");
            exit(-1);
        }

        uint64_t count;
        ssize_t read_ok = read(kpagecount_fd, &count, sizeof(count));
        if (read_ok != sizeof(count)) {
            fprintf(stderr, "Unable to read kpagecount at pfn %lld\n",
                    pfn);
            perror("read: ");
            exit(-1);
        }

        if (count > 0) {
            inuse_pfns.push_back(pfn);
        }
    }

    close(kpagecount_fd);
    return inuse_pfns;
}

/* Returns the PFN for a pagemap entry
 * The pagemap entry is a 64-bit integer which may or may
 * not contain a PFN.
 * The pagemap entry will contain a PFN number in the bottom 54
 * bits if the PAGE_PRESENT (63) bit is set.
 *
 * Returns the PFN number if present or -1 if not
 */
int64_t pfn_for_pagemap_entry(const uint64_t pm_entry) {

    const uint64_t PAGE_PRESENT = (1ULL << 63);
    const uint64_t PFN_MASK = (1ULL << 55) - 1;

    return (pm_entry & PAGE_PRESENT) ?
           (pm_entry & PFN_MASK) : -1;
}

