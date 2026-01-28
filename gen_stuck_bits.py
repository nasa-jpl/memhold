#!/usr/bin/env python3
import os
import sys
import struct
import random

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
KPAGECOUNT_PATH = "/proc/kpagecount"
IOMEM_PATH = "/proc/iomem"

def load_system_ram_pfn_ranges():
    """
    Parse /proc/iomem and return a list of (pfn_lo, pfn_hi) tuples
    covering all regions tagged "System RAM".
    """
    ranges = []
    try:
        f = open(IOMEM_PATH, "r")
    except IOError as e:
        sys.exit("ERROR: cannot read {0}: {1}".format(IOMEM_PATH, e))

    for line in f:
        line = line.strip()
        parts = line.split(" : ", 1)
        if len(parts) != 2 or parts[1] != "System RAM":
            continue
        lo_str, hi_str = parts[0].split("-", 1)
        lo = int(lo_str, 16)
        hi = int(hi_str, 16)
        pfn_lo = lo  // PAGE_SIZE
        pfn_hi = hi  // PAGE_SIZE
        if pfn_lo <= pfn_hi:
            ranges.append((pfn_lo, pfn_hi))
    f.close()

    if not ranges:
        sys.exit("ERROR: no System RAM regions found in {0}".format(IOMEM_PATH))
    return ranges

def sample_free_pfn(ranges, max_tries=10000):
    """
    Pick a random PFN from `ranges` whose kpagecount is zero.
    Raises RuntimeError if none found within max_tries.
    """
    try:
        fd = os.open(KPAGECOUNT_PATH, os.O_RDONLY)
    except OSError as e:
        sys.exit("ERROR: cannot open {0}: {1}".format(KPAGECOUNT_PATH, e))

    for _ in range(max_tries):
        lo, hi = random.choice(ranges)
        pfn = random.randint(lo, hi)
        offset = pfn * 8
        try:
            data = os.pread(fd, 8, offset)
            if len(data) == 8:
                count, = struct.unpack("<Q", data)
                if count == 0:
                    os.close(fd)
                    return pfn
        except OSError:
            continue

    os.close(fd)
    raise RuntimeError("failed to find a free PFN after {0} tries".format(max_tries))

def main():
    if len(sys.argv) != 3:
        print("Usage: {0} <N> <output.conf>".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    try:
        N = int(sys.argv[1])
        if N <= 0:
            raise ValueError
    except ValueError:
        sys.exit("ERROR: N must be a positive integer")

    out_path = sys.argv[2]

    ranges = load_system_ram_pfn_ranges()
    selected = {}
    total_tries = 0
    max_total_tries = N * 1000

    while len(selected) < N:
        if total_tries >= max_total_tries:
            sys.exit("ERROR: gave up after {0} attempts, only found {1} free pages"
                     .format(total_tries, len(selected)))
        total_tries += 1
        try:
            pfn = sample_free_pfn(ranges, max_tries=100)
        except RuntimeError:
            continue
        if pfn in selected:
            continue
        bit = random.choice([0, 1])
        selected[pfn] = bit

    try:
        f = open(out_path, "w")
    except IOError as e:
        sys.exit("ERROR: cannot write to {0}: {1}".format(out_path, e))

    f.write("# <physical-address> <stuck-bit>\n")
    for pfn, bit in selected.items():
        phys = pfn * PAGE_SIZE
        f.write("0x{0:016X} {1}\n".format(phys, bit))
    f.close()

    print("Wrote {0} entries to {1}".format(len(selected), out_path))

if __name__ == "__main__":
    main()
