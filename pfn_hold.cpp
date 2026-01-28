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
#include <iomanip>

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

// TODO: Consider setting /proc/sys/kernel/randomize_va_space to 0
// Default values on the snapdragon is 1, which randomizes the base
// address of mmap. Could cause issues when allocating a 1 GB contiguous
// space???

// Enable verbose printing in functions
static bool g_verbose = false;

// Enable sync() syscall strategy
static bool g_strat_sync = false;

// Enable sync() syscall strategy
static bool g_disable_oom = false;

// Enable /proc/sys/vm/dropcache strategy
static bool g_strat_dropcache = false;
// Character to write to dropcache file
static char g_strat_dropcache_val = '\0';

// Enable usleep() delay strategy
static bool g_strat_delay = false;
// Number of us to delay
static int32_t g_strat_delay_val_us = 0;

static bool g_strat_testmem = false;
static int32_t g_strat_testmem_delay_s = 0;

static bool g_strat_jailmargin = false;
static int32_t g_strat_jailmargin_slots = 0;

void print_help() {

    fprintf(stderr, "pfn_hold: pfn_list.txt mem_area_mb iterations verbose [strategies]\n");
    fprintf(stderr, "pfn_list.txt: List of Page Frame Numbers to hold. File should have one pfn per line. PFN are expected to be hexadecimal\n");
    fprintf(stderr, "mem_area_mb: Max size in KB of memory to allocate when looking for bad PFNs\n");
    fprintf(stderr, "iterations: Number of search iterations to perform when looking for bad PFNs\n");
    fprintf(stderr, "verbose: verbose printing\n");
    fprintf(stderr, "Strategies:\n");
    fprintf(stderr, " sync: Call sync() syscall, causing filesystem data to be flushed to disk. Ex. sync\n");
    fprintf(stderr, " dropcache: Write to /proc/sys/vm/drop_caches to flush pagecache and other caches data to disk.  Ex. sync\n");
    fprintf(stderr, "            The value to write to drop_caches is passed as an argument. Ex. dropcache:3\n");
    fprintf(stderr, " delay: Sleep for N microseconds between iterations. Ex. delay:100000\n");
    fprintf(stderr, " background: Spawn the hold process as a child process in the background\n");
    fprintf(stderr, "             The initial command will exit when the memory is held, or an error occurs\n");
    fprintf(stderr, " testmem: Test all memory regions for errors, even if the PFN is not known to be bad\n");
    fprintf(stderr, "          Sleep for N seconds between setting and testing memory for a given search\n");
    fprintf(stderr, " jailmargin: Increase the jail size by N entries to account for testmem pages that are found\n");
    fprintf(stderr, "             Ex: jailmargin:1000 to allocate space for all all pages in pfn_list.txt + 1000\n");

}

/* Write to the /proc/sys/vm/drop_caches values after each iteration
 * From kernel documentation
 *  Writing to this will cause the kernel to drop clean caches, dentries and
 *  inodes from memory, causing that memory to become free.
 *
 *  To free pagecache:
 *   echo 1 > /proc/sys/vm/drop_caches
 *  To free dentries and inodes:
 *   echo 2 > /proc/sys/vm/drop_caches
 *  To free pagecache, dentries and inodes:
 *   echo 3 > /proc/sys/vm/drop_caches
 *
 *  As this is a non-destructive operation and dirty objects are not freeable, the
 *  user should run `sync' first.
 *
 * This should free up some memory that is currently used in caches and may
 * free up one of the PFNs we are looking for. It may also add sufficent
 * randomizations to the page allocator that we see different PFNs this iteration
 *
 * Failures are ignored in this function as it is non-critical to the success
 * of the pfn_hold script
 */
void strategy_dropcaches(const char val) {

    int dropcaches_fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (dropcaches_fd < 0) {
        fprintf(stderr, "Unable to open /proc/sys/vm/drop_caches\n");
        perror("open");
        // Note: Don't fail here
        return;
    }

    ssize_t write_ok = write(dropcaches_fd, &val, 1);
    if (write_ok != 1) {
        fprintf(stderr, "Unable to write (%c) to /proc/sys/vm/drop_caches\n",
                val);
        perror("write");
        // Note: Don't fail here
    }

    close(dropcaches_fd);
}

void test_all_pages(const std::map<void*, int64_t>& testpages,
                    uint64_t pattern,
                    void* search_space,
                    int64_t search_size,
                    std::map<int64_t, void*>& bad_page_map) {

    for (auto items : testpages) {
        void* const page = std::get<0>(items);

        for (size_t i = 0; i < PAGE_SIZE / 8; i++) {
            reinterpret_cast<uint64_t*>(page)[i] = pattern;
        }
    }

    // Clear cache to make sure we're reading from memory
    __clear_cache(search_space, (reinterpret_cast<char*>(search_space) + search_size));

    // Wait n seconds
    sleep(g_strat_testmem_delay_s);

    for (auto items : testpages) {
        void* const page = std::get<0>(items);
        const int64_t pfn = std::get<1>(items);

        for (size_t i = 0; i < PAGE_SIZE / 8; i++) {
            uint64_t val = reinterpret_cast<uint64_t*>(page)[i];
            if (val != pattern) {
                if (bad_page_map.find(pfn) == bad_page_map.end()) {
                    printf("Found unlisted bad page at %p, (%llx). Exp %llx Act %llx\n",
                           &reinterpret_cast<uint64_t*>(page)[i],
                           pfn, pattern, val);
                    bad_page_map[pfn] = page;
                }
            }
        }
    }

}


std::map<int64_t, void*> strategy_testmem(const std::map<void*, int64_t>& testpages,
                                          void* search_space,
                                          int64_t search_size) {

    std::map<int64_t, void*> bad_page_map;

    test_all_pages(testpages, 0xaaaaaaaaaaaaaaaa, search_space, search_size, bad_page_map);
    test_all_pages(testpages, 0x5555555555555555, search_space, search_size, bad_page_map);

    test_all_pages(testpages, 0x0000000000000000, search_space, search_size, bad_page_map);
    test_all_pages(testpages, 0xffffffffffffffff, search_space, search_size, bad_page_map);

    test_all_pages(testpages, 0x0f0f0f0f0f0f0f0f, search_space, search_size, bad_page_map);
    test_all_pages(testpages, 0xf0f0f0f0f0f0f0f0, search_space, search_size, bad_page_map);

    return bad_page_map;
}

/* Run all the PFN randomization strategies prior to the next iteration
 */
void run_strategies() {

    // Sync all dirty pagecache pages to disk so that dropcache
    // can free more memory.
    if (g_strat_sync) {
        sync();
    }

    // Drop varies caches to free up otherwise used pfns
    if (g_strat_dropcache) {
        strategy_dropcaches(g_strat_dropcache_val);
    }

    // Delay for some time for caches to rebuild
    if (g_strat_delay) {
        usleep(g_strat_delay_val_us);
    }
}

// Disable Out-of-memory killer for this task so that
// we don't lose a handle on the bad PFNs
void disable_oom() {
    
    std::stringstream oom_score_adj_fname;
    oom_score_adj_fname << "/proc/" << getpid() << "/oom_score_adj";
    int oom_fd = open(oom_score_adj_fname.str().c_str(),
                      O_WRONLY);
    if (oom_fd < 0) {
        fprintf(stderr, "Unable to open %s\n",
                oom_score_adj_fname.str().c_str());
        perror("open");
        exit(-1);
    }

    // Minimum score of -1000 disabled oom-killer for process
    const char* oom_str = "-1000";

    ssize_t write_ok = write(oom_fd, oom_str, 5);
    if (write_ok != 5) {
        fprintf(stderr, "Failed write to oom_score_adj\n");
        perror("write");
        exit(-1);
    }
}

/* Allocate PFNs to fill the search space.
 *
 * It is expected that the virual address space has previously been
 * allocated, but no backing memory is mapped to the address space
 * search_virt: Beginning of allocated virtual address space
 * size: Size of search space to map
 */
void alloc_pfns_search(void* const search_virt, const int64_t size) {

    assert(search_virt != nullptr);
    assert(size > 0);

    const int mmap_flags = MAP_PRIVATE |   // Only pfn_hold can access the pfn
                           MAP_ANONYMOUS | // Map physical memory
                           MAP_POPULATE |  // Populate the memory region
                           MAP_FIXED;      // Force the allocation to be placed
                                           // at search_virt. Otherwise search_virt
                                           // is only a hint
    void* mmap_ok = mmap(search_virt,
                         size,
                         // Note: Need PROT_READ and PROT_WRITE otherwise the
                         // same zero page is returned for each pfn
                         PROT_READ | PROT_WRITE,
                         mmap_flags,
                         -1,
                         0);

    if (mmap_ok == (void*)-1) {
        fprintf(stderr, "Unable to allocate search area of %lld MB at %p\n",
                size,
                search_virt);
        perror("mmap");
        exit(-1);
    }
 
    if (mmap_ok != search_virt) {
        fprintf(stderr, "mmap did not place the region at the correct address. Exp %p. Act %p",
                search_virt,
                mmap_ok);
        exit(-1);
    }

    // Lock the PFNs into the search region
    if (mlock(search_virt, size) != 0) {
        fprintf(stderr, "Unable to mlock search region\n");
        perror("mlock");
        exit(-1);
    }

    if (g_verbose) {
        printf("Allocated %lld KB at address %p\n",
               size / 1024, search_virt);
    }
}

/* Walk the provided virtual address range
 * - Return virtual addresses associated with known
 *   bad PFNs
 * - Unlock and free remaining memory in region
 * After this function, the only remaining memory in the virtual
 * address region will be associated with bad PFNs
 */
std::map<int64_t, void*> process_pfns_in_virt_range(
        const std::vector<int64_t>& bad_pfn_list,
        void* const virt, 
        const int64_t virt_size,
	    std::ofstream& debug_f) {

    assert(bad_pfn_list.size() > 0);
    assert(virt != nullptr);
    assert(virt_size > 0);

    /* From man proc_pid_pagemap
     *  This file shows the mapping of each of the process's
     *  virtual pages into physical page frames or swap area.  It
     *  contains one 64-bit value for each virtual page, with the
     *  bits set as follows:
     *   63     If set, the page is present in RAM.
     *   ...
     *   54–0   If the page is present in RAM (bit 63), then these
     *          bits provide the page frame number, which can be
     *          used to index /proc/kpageflags and /proc/kpagecount.
     */
    std::stringstream pagemap_fname;
    pagemap_fname << "/proc/" << getpid() << "/pagemap";
    int pagemap_fd = open(pagemap_fname.str().c_str(),
                          O_RDONLY);
    if (pagemap_fd < 0) {
        fprintf(stderr, "Unable to open %s\n",
                pagemap_fname.str().c_str());
        perror("open");
        exit(-1);
    }

    // Bad PFNs found in the search space are stored in a map
    // The key is the PFN number and the value is the virtual
    // address space where the PFN is located.
    // This virtual address will later be used to remap the 
    // PFN into the jail space
    std::map<int64_t, void*> bad_pfn_map;

    std::map<void*, int64_t> check_pfn_map;

    /* Lseek to the begining of the search region
     * /proc/pid/pagemap is indexed to virtual addresses and since the
     * virtual address space of the search range is contiguous consecutive
     * reads will walk the search space.
     */
    const int64_t pagemap_entry_size = sizeof(int64_t);
    uint64_t off = (reinterpret_cast<uintptr_t>(virt) / PAGE_SIZE) * pagemap_entry_size;
    off_t lseek_ok = lseek(pagemap_fd, off, SEEK_SET);
    if (lseek_ok == (off_t)-1) {
        fprintf(stderr, "Unable to seek to offset %lld for virtual address %p\n",
                off, virt);
        perror("lseek");
        exit(-1);
    }

    for (int64_t off = 0; off < virt_size; off += PAGE_SIZE) {
        void* const iter_virt = reinterpret_cast<void*>(reinterpret_cast<char*>(virt) + off);

        uint64_t pm_entry;
        ssize_t read_ok = read(pagemap_fd, &pm_entry, pagemap_entry_size);
        if (read_ok != pagemap_entry_size) {
            off_t curr_off = lseek(pagemap_fd, 0, SEEK_CUR);
            fprintf(stderr, "Failed to read pagemap for address %p (exp: %lld act: %zd offset: %ld)\n",
                    iter_virt, pagemap_entry_size, read_ok, curr_off);
            perror("read");
            exit(-1);
        }

        int64_t pfn = pfn_for_pagemap_entry(pm_entry);
        if (pfn < 0) {
            fprintf(stderr, "No PFN for address %p\n", iter_virt);
            exit(-1);
        }

        // Catch a possible error if the PFN is larger than the MAX_PFN
        assert(PFN_VALID(pfn));

        // Is the PFN in the bad_pfn_list?
        const bool is_bad_pfn = std::find(bad_pfn_list.begin(),
                                          bad_pfn_list.end(),
                                          pfn) != bad_pfn_list.end();

        // Dump the PFNs found to file if in verbose mode
        if (g_verbose && debug_f.is_open()) {
            debug_f << std::hex;
            debug_f << std::setw(6) << pfn;
            debug_f << ": " << std::setw(8) << iter_virt;
            debug_f << " " << is_bad_pfn << std::endl;
        }

        if (is_bad_pfn) {
            // Known bad PFN number. Add it to the list
            // Assert that this PFN was not already found this
            // iteraion
            assert(bad_pfn_map.find(pfn) == bad_pfn_map.end());

            if (g_verbose) {
                printf("Found PFN %06llx at virt %p\n",
                       pfn, iter_virt);
            }

            bad_pfn_map[pfn] = iter_virt;
        } else {
            if (g_strat_testmem) {
                check_pfn_map[iter_virt] = pfn;
            }
        }
    }

    if (g_strat_testmem) {
        auto found_bad_pfns = strategy_testmem(check_pfn_map, virt, virt_size);

        for (std::pair<int64_t, void*> items : found_bad_pfns){ 
            const int64_t pfn = std::get<0>(items);
            void* const pfn_virt = std::get<1>(items);
            assert(bad_pfn_map.find(pfn) == bad_pfn_map.end());
            // Note: print statement about PFN in stategy_testmem
            bad_pfn_map[pfn] = pfn_virt;
        }
    }

    close(pagemap_fd);

    return bad_pfn_map;
}

/* Move the bad PFNs found in the search space to consecutive virtual
 * addresses in the jail space.
 * Returns a new base address into the jail virtual address space
 */
void* move_pfns_to_jail(const std::map<int64_t,void*>& pfn_map,
                        void* jail_virt,
                        int64_t* jail_slots_left) {

    assert(jail_virt != nullptr);
    assert(jail_slots_left != nullptr);
    assert(*jail_slots_left > 0);

    int64_t loop_counter = 0;
    for (const std::pair<int64_t,void*> kv : pfn_map) {

        if (*jail_slots_left == 0) {
            break;
        }
        if (loop_counter >= MAX_PFN) {
            fprintf(stderr, "Loop Counter Exceeded at %s:%d",
                    __FILE__, __LINE__);
            exit(-1);
        }
        loop_counter++;

        const int64_t pfn = std::get<0>(kv);
        void* const pfn_virt = std::get<1>(kv);

        /* Remap the bad PFN in the search address space to the jail address space.
         * The memory lock that is on the page in the search address space will
         * remain on the page in the jail space
         * Per mremap man page:
         *  If the memory segment  specified  by  old_address  and  old_size  is
         *  locked  (using  mlock(2)  or  similar), then this lock is maintained
         *  when the segment is resized and/or relocated.  As a consequence, the
         *  amount of memory locked by the process may change.
         */
        const void* ok = mremap(pfn_virt, PAGE_SIZE,
                                PAGE_SIZE,
                                MREMAP_FIXED | MREMAP_MAYMOVE,
                                jail_virt);
        if (ok != jail_virt) {
            fprintf(stderr, "Unable to move pfn to jail. From %p to %p\n",
                    pfn_virt, jail_virt);
            perror("mremap");
            exit(-1);
        }

        if (g_verbose) {
            printf("Jailed PFN %06llx (%p) at %p\n",
                   pfn, pfn_virt, jail_virt);
        }

        jail_virt = reinterpret_cast<char*>(jail_virt) + PAGE_SIZE;
        *jail_slots_left -= 1;

        if (*jail_slots_left == 0) {
            printf("Ran out of jail slots. Unable to jail more pfns\n");
        }
    }

    return jail_virt;
}

/* Provided a pfn_list, search and collect the provided PFNs into a jail
 * area so that they cannot be used by another process on the system.
 * pfn_list: List of PFNs to try and collect
 * mem_area_mb: Maximum physical memory to allocate during this function.
 *              This includes any jailed PFNs collected during previous
 *              iterations
 * iterations: Number of additional search iterations to perform.
 *             A value of 0 indicates that only a single initial
 *             search will be performed.
 *             A value of 1 indicates an addition iteration and so on
 *
 * Returns the list a jailed PFNs collected during this call
 */
std::vector<int64_t> collect_pfns(const std::vector<int64_t>& pfn_list,
                                  const int64_t mem_area_mb,
                                  const int64_t iterations) {

    assert(mem_area_mb > 0);
    assert(iterations >= 0);

    /* Collect and Jail Algorithm
     * 1. Allocate physical memory to a large search space
     *    This will create a 1-to-1 mapping of virtual page to 
     *    Page Frame Number (PFN) assuming the virtual memory
     *    space has been locked with mlock()
     *
     * 2. Walk the search space in /proc/pid/pagemap and look
     *    for any of the known bad PFNs. Record the PFN and the
     *    virtual address of the associated page
     *
     * 3. For each bad PFN found, remap the physical frame to
     *    a new virtual address in a jail region, outside of
     *    the search space. This process does not remove the
     *    lock on the memory, which ensures that the actual PFN
     *    stays mapped
     *
     * 4. Free all other PFNs in the search region
     *
     * 5. If performing a subsequent iteration, optionally perform
     *    a series of PFN randomization strategies, intended to
     *    increase the diversity in the PFNs allocated into our
     *    address space.
     *
     * 6. If not all bad PFNs have been located and the maximum
     *    number of iterations has not been reached, go to step 1
     *
     * Note: Managing virtual address space is important. The
     *       Snapdragon 801 is a 32-bit processor, which means only
     *       3GB of virtual address space is available for our process
     *       (1GB is used by the kernel). Any fragmentation in
     *       the virtual address space makes it increasingly unlikely
     *       for a large, contiguous search space allocation to
     *       succeed.
     *       Therefore, the bad PFNs must to moved out of the search
     *       space to a jail space to avoid fragmentation of the
     *       search space and allow the search space to be used
     *       for consecutive iterations
     */

    if (pfn_list.size() == 0) {
        return std::vector<int64_t>();
    }

    /* Allocate enough contiguous virtual address space to
     * store the PFN search region.
     * PROT_NONE ensures no mappings to physical memory
     * are created at this time
     */
    const size_t search_size = mem_area_mb * (1024*1024);
    void* const search_virt = mmap(0,
                                   search_size,
                                   PROT_NONE,
                                   MAP_ANONYMOUS | MAP_PRIVATE,
                                   -1, 0);

    if (search_virt == (void*)-1) {
        fprintf(stderr, "Unable to allocate search virtual space of %u MB\n",
                search_size);
        perror("mmap");
        exit(-1);
    }

    /* Allocate enough contiguous virtual address space to
     * store the PFN jail region.
     * PROT_NONE ensures no mappings to physical memory
     * are created at this time
     */
    assert(g_strat_jailmargin ? (g_strat_jailmargin_slots >= 0) :
                                (g_strat_jailmargin_slots == 0));
    const size_t jail_size = (pfn_list.size() + g_strat_jailmargin_slots) * PAGE_SIZE;
    void* const jail_base_virt = mmap(0,
                                      jail_size,
                                      PROT_NONE,
                                      MAP_ANONYMOUS | MAP_PRIVATE,
                                      -1, 0);
    int64_t jail_slots_left = pfn_list.size() + g_strat_jailmargin_slots;

    if (jail_base_virt == (void*)-1) {
        fprintf(stderr, "Unable to allocate jail virtual space of %u MB\n",
                jail_size);
        perror("mmap");
        exit(-1);
    }

    // Collect the list of currently jailed PFNs
    std::vector<int64_t> jailed_pfns;
    std::vector<int64_t> remaining_pfns = pfn_list;

    void* jail_virt = jail_base_virt;
    int64_t iter_size = search_size;
    int64_t iter = 0;
    std::ofstream debug_f;
    while (jailed_pfns.size() != pfn_list.size() &&
           iter <= iterations &&
            jail_slots_left > 0) {

        assert(iter >= 0);
        assert(iter_size > 0 && iter_size <= search_size);

        // Only run strategies on later iterations
        // to give the algorithm one chance to collect
        // PFNs undisturbed
        if (iter > 0) {
            if (g_verbose) {
                auto inuse = find_inuse_pfns(remaining_pfns);
                fprintf(stderr, "Pre Strat Inuse: %zu/%zu\n",
                        inuse.size(), remaining_pfns.size());
            }
            run_strategies();
            if (g_verbose) {
                auto inuse = find_inuse_pfns(remaining_pfns);
                fprintf(stderr, "Post Strat Inuse: %zu/%zu\n",
                        inuse.size(), remaining_pfns.size());
            }
        }

        if (g_verbose) {
            fprintf(stderr, "Iteration %lld/%lld\n",
                    iter, iterations);

            // In verbose mode, create a debug file to store
            // all the PFNs found during an iteration. Useful
            // for debugging the behavior of strategies
            std::stringstream debug_fname;
            debug_fname << "pfnhold_iter" << iter << ".txt";
            debug_f.open(debug_fname.str(), std::ios::out | std::ios::trunc);
        }

        // Allocate a search area equal to the available memory
        // size for this iteration
        alloc_pfns_search(search_virt, iter_size);

        // Find the known bad PFNs in this virtual area
        const std::map<int64_t,void*> iter_pfn_virt_map =
            process_pfns_in_virt_range(pfn_list,
                                       search_virt,
                                       iter_size,
                                       debug_f);

        // Add found bad mappings to list
        for (std::pair<int64_t, void*> mapping : iter_pfn_virt_map) {
            const int64_t pfn = std::get<0>(mapping);
            // Assert that the PFN has not already been found
            assert(std::find(jailed_pfns.begin(),
                             jailed_pfns.end(),
                             pfn) == jailed_pfns.end());
            jailed_pfns.push_back(std::get<0>(mapping));

            auto pfn_idx = std::find(remaining_pfns.begin(),
                                           remaining_pfns.end(),
                                           pfn);
            if (pfn_idx != remaining_pfns.end()) {
                remaining_pfns.erase(std::find(remaining_pfns.begin(),
                                               remaining_pfns.end(),
                                               pfn));
            }
        }

        // Move PFNs found this cycle to the jail address range
        jail_virt = move_pfns_to_jail(iter_pfn_virt_map, jail_virt, &jail_slots_left);
        if (g_verbose) {
            printf("Jail slots remaining: %lld\n", jail_slots_left);
        }

        // Remap the entire search space to PROT_NONE mappings.
        // This will free all good PFNs in the search space
        // Note: Call munlock() on this range first throws an
        // error. It seems to be enough to just unmap the space
        // and mlock() when the search space is allocated again
        
        void* mmap_ok = mmap(search_virt,
                             search_size,
                             PROT_NONE,
                             MAP_ANONYMOUS |
                             MAP_PRIVATE |
                             MAP_FIXED,
                             -1, 0);
        if (mmap_ok == (void*)-1) {
            fprintf(stderr, "Failed to unmap memory at %p\n",
                    search_virt);
            perror("mmap");
            exit(-1);
        }

        if (mmap_ok != search_virt) {
            fprintf(stderr, "Failed to unmap memory. Mmap retured different address than request. Exp %p. Act %p\n",
                    search_virt,
                    mmap_ok);
            exit(-1);
        }

        // Shink the allocation size for the next cycle so that a
        // mem_area_mb remains an upper bound on the amount of memory
        // allocated for the search and hold process
        iter_size -= iter_pfn_virt_map.size() * PAGE_SIZE;
        assert(iter_size >= 0);

        iter++;

        if (g_verbose) {
            debug_f.close();
        }

    }

    return jailed_pfns;
}

void monitor_proc(int pipe_read_fd, int child_pid) {
    assert(pipe_read_fd > 0);

    // Note: This function should not return. This loop should eventually
    // end with a call to exit()
    while (true) {

        // Timeout set to 100 ms
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100*1000;

        // Wait on a read on the read pipe fd
        fd_set pipe_fd_set;
        FD_ZERO(&pipe_fd_set);
        FD_SET(pipe_read_fd, &pipe_fd_set);

        // Wait for the read pipe to be ready or a 100 ms timeout
        int select_ok = select(pipe_read_fd+1, &pipe_fd_set, NULL, NULL, &timeout);
        if (select_ok == 1) {
            // Pipe has a value to read
            int32_t child_ret_val;
            ssize_t read_ok = read(pipe_read_fd, &child_ret_val, sizeof(child_ret_val));
            if (read_ok == -1) {
                fprintf(stderr, "Read on pipe failed\n");
                perror("read");
                exit(-1);
            } else if (read_ok == 0) {
                fprintf(stderr, "Read on pipe returned 0. Other side likely closed\n");
                perror("read");
                exit(-1);
            } else if (read_ok != sizeof(child_ret_val)) {
                fprintf(stderr, "Read on pipe did not return expected length. (%zu)\n",
                        read_ok);
                exit(-1);
            } else {
                // Exit the parent process with the return code from the child
                // This will orphan the child process and it will continue to hold
                // onto memory until explicitly killed
                exit(child_ret_val);
            }
        } else {
            // No bytes ready to read. Child if child process died
            int wstatus;
            pid_t wait_ok = waitpid(-1, &wstatus, WNOHANG);
            if (wait_ok == -1) {
                fprintf(stderr, "Error calling waitpid in parent process\n");
                perror("waitpid");
                exit(-1);
            } else if (wait_ok != 0) {
                assert(wait_ok == child_pid);

                fprintf(stderr, "Child process exited unexpectedly. Status %d\n",
                        wstatus);
                exit(-1);
            }
            // If wait_ok == 0 then the child process is still executing
            // This is the expected case
        }
    }
}

int main(int argc, char** argv) {

    enum {
        ARG_PFN_LIST = 1,
        ARG_MEM_AREA_KB,
        ARG_ITERATIONS,
        ARG_VERBOSE,
        ARG_STRATEGIES_BEGIN
    };

    if (argc < ARG_VERBOSE) {
        fprintf(stderr, "Invalid number of arguments\n");
        print_help();
        return -1;
    }

    const char* pfn_list_fname = argv[ARG_PFN_LIST];
    const char* mem_area_mb_arg = argv[ARG_MEM_AREA_KB];
    const char* iterations_arg = argv[ARG_ITERATIONS];
    const char* verbose_arg = argv[ARG_VERBOSE];

    // Parse arguments
    std::ifstream pfn_list_f(pfn_list_fname, std::ios::in);
    if (!pfn_list_f.is_open()) {
        fprintf(stderr, "Unable to open file %s\n", pfn_list_fname);
        print_help();
        return -1;
    }

    const int64_t mem_area_mb = std::strtoll(mem_area_mb_arg, nullptr, 10);
    if (mem_area_mb == LLONG_MAX || 
        mem_area_mb == LLONG_MIN) {
        fprintf(stderr, "Unable to parse mem_area_mb arg\n");
        perror("strtoll");
        print_help();
        return -1;
    }

    const int64_t iterations = std::strtoll(iterations_arg, nullptr, 10);
    if (iterations == LLONG_MAX || 
        iterations == LLONG_MIN) {
        fprintf(stderr, "Unable to parse iterations arg\n");
        perror("strtoll");
        print_help();
        return -1;
    }

    const int64_t verbose = std::strtoll(verbose_arg, nullptr, 10);
    if (verbose == LLONG_MAX || 
        verbose == LLONG_MIN) {
        fprintf(stderr, "Unable to parse verbose arg\n");
        perror("strtoll");
        print_help();
        return -1;
    }

    // Validate arguments
    if (mem_area_mb <= 0) {
        fprintf(stderr, "mem_area_mb must be > 0\n");
        print_help();
        return -1;
    }

    if (iterations < 0) {
        fprintf(stderr, "iterations must be >= 0\n");
        print_help();
        return -1;
    }

    g_verbose = verbose > 0;

    bool do_background = false;

    // Parse any extra arguments as PFN randomization strategies
    // Store the results in the relevant static global variables
    for (int idx = ARG_STRATEGIES_BEGIN; idx < argc; idx++) {
        std::string arg = std::string(argv[idx]);
        std::string name = arg.substr(0, arg.find(':'));
        std::string val;
        if (arg.find(':') != arg.size()) {
            val = arg.substr(arg.find(':')+1, arg.size());
        }

        if (name == "dropcache") {
            if (val.size() != 1) {
                fprintf(stderr, "Bad arg to dropcache\n");
                print_help();
                return -1;
            }
            g_strat_dropcache = true;
            g_strat_dropcache_val = val[0];
            printf("Enabled dropcache strategy with arg (%c)\n",
                   g_strat_dropcache_val);
        } else if (name == "sync") {
            g_strat_sync = true;
            printf("Enabled sync strategy\n");
        } else if (name == "disableoom") {
            g_disable_oom = true;
            printf("Enabled disable oom strategy\n");
        } else if (name == "delay") {
            int delay_val = strtol(val.c_str(), nullptr, 10);
            if (delay_val == LONG_MIN ||
                delay_val == LONG_MAX ||
                delay_val <= 0) {
                fprintf(stderr, "Bad arg to delay\n");
                perror("strtol");
                print_help();
                return -1;
            }
            g_strat_delay = true;
            g_strat_delay_val_us = delay_val;
            printf("Enabled delay strategy with arg (%d)\n",
                   g_strat_delay_val_us);
        } else if (name == "background") {
            do_background = true;
            printf("Enabled backgroud\n");
        } else if (name == "testmem") {
            int delay_val = strtol(val.c_str(), nullptr, 10);
            if (delay_val == LONG_MIN ||
                delay_val == LONG_MAX ||
                delay_val <= 0) {
                fprintf(stderr, "Bad arg to testmem\n");
                perror("strtol");
                print_help();
                return -1;
            }
            g_strat_testmem = true;
            g_strat_testmem_delay_s = delay_val;
            printf("Enabled testmem strategy with delay %d s\n", delay_val);
        } else if (name == "jailmargin") {
            int jail_val = strtol(val.c_str(), nullptr, 10);
            if (jail_val == LONG_MIN ||
                jail_val == LONG_MAX ||
                jail_val <= 0) {
                fprintf(stderr, "Bad arg to jailmargin\n");
                perror("strtol");
                print_help();
                return -1;
            }
            g_strat_jailmargin = true;
            g_strat_jailmargin_slots = jail_val;
            printf("Enabled jailmargin strategy with slots %d\n", jail_val);
        }
    }

    // Read all the PFNs in the file
    std::vector<int64_t> pfn_list = read_pfn_list(pfn_list_f);
    pfn_list_f.close();

    if (pfn_list.size() == 0) {
        fprintf(stderr, "error processing pfn list\n");
        return -1;
    }

    int write_pipe_fd = -1;
    if (do_background) {
        int pipe_fds[2] = {0};
        int pipe_ok = pipe(pipe_fds);
        if (pipe_ok != 0) {
            fprintf(stderr, "Failed to create IPC pipe to child\n");
            perror("pipe");
            return -1;
        }

        // Flush stdout, otherwise child gets copy of any buffered stdout
        fflush(stdout);
        int fork_rtn = fork();
        if (fork_rtn < 0) {
            fprintf(stderr, "Failed to create child process\n");
            perror("fork");
            return -1;
        } else if (fork_rtn != 0) {
            // Parent process

            // Close the write pipe
            close(pipe_fds[1]);
            fprintf(stderr, "Child pid: %d\n", fork_rtn);

            monitor_proc(pipe_fds[0], fork_rtn);

            // monitor_proc() should never return
            assert(false);
        } else {
            // Child process

            // Close the read pipe
            close(pipe_fds[0]);
            write_pipe_fd = pipe_fds[1];

            // Continue with code
        }
    }

    // Disable buffering stdout
    // In testing, we noticed that the HBS log files
    // would not contain any child process printfs
    setbuf(stdout, NULL);
    
    // Disable the OOM Killer for this process
    // This is to prevent an edge case where the OOM
    // kills the task after jailing the PFNs. Thereby
    // releasing all jailed PFNs back into the allocation pool
    if (g_disable_oom) {
        disable_oom();
    }

    // Jail as many bad PFNs as possible
    std::vector<int64_t> jailed_pfns = collect_pfns(pfn_list, mem_area_mb, iterations);
    std::vector<int64_t> testmem_pfns;

    // Calculate the list of PFNs that were not jailed
    std::vector<int64_t> nonjailed_pfns = pfn_list;
    for (const int64_t jailed_pfn : jailed_pfns) {
        auto pfn_index = std::find(nonjailed_pfns.begin(),
                                       nonjailed_pfns.end(),
                                       jailed_pfn);
        // Sort PFNs by expected and unexpected PFNs
        if (pfn_index != nonjailed_pfns.end()) {
            nonjailed_pfns.erase(pfn_index);
        } else {
            testmem_pfns.push_back(jailed_pfn);
        }
    }

    // Check if any of the non-jailed PFNs are in use elsewhere
    // in the system
    std::vector<int64_t> inuse_pfns = find_inuse_pfns(nonjailed_pfns);

    // Report statistics on the bad PFNs
    printf("Total Bad PFNs: %zu\n", pfn_list.size());
    printf("Inuse PFNs: %zu\n", inuse_pfns.size());
    printf("Jailed PFNs: %zu\n", jailed_pfns.size());
    for (const int64_t pfn : jailed_pfns) {
        printf(" %06llx\n", pfn);
    }
    printf("Testmem PFNs: %zu\n", testmem_pfns.size());
    for (const int64_t pfn : testmem_pfns) {
        printf(" %06llx\n", pfn);
    }

    if (write_pipe_fd > 0) {
        // Write the return code to the pipe
        int32_t ret_code = 0;
        ssize_t write_ok = write(write_pipe_fd, &ret_code, sizeof(ret_code));
        if (write_ok == -1) {
            fprintf(stderr, "Failed to write return code to pipe\n");
            perror("write");
        } else if (write_ok != sizeof(ret_code)) {
            fprintf(stderr, "Incorrect number of bytes written to pipe %zu\n",
                    write_ok);
            perror("write");
        }

        // Close the pipe. No longer writing
        close(write_pipe_fd);
    }

    // Hold onto bad PFNs indefinitely
    while (true) {
        sleep(1);
    }

    return 0;
}

