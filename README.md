# Software SEE Testing for Commodity SoCs
This tool detects and locates potential stuck or sticky bits in DRAM. The default
configuration is meant for the Snapdragon 801 SoC on the Mars 2020 HBS, but can be
easily adapted to support other chipsets.

## Design
The `memtest` program reserves `memory_size` megabytes of memory using `malloc` and writes an
array of different repeating pattern to the reserved locations. After a user-specified
wait time, the memory location is then read back again, and the read pattern compared
to the written one. Errors are then logged to `<output_file_template>.csv` in a CSV
format. Kernel page information is also saved to allow logged virtual memory addresses
to be converted to physical memory addresses. `mlock` is used to ensure that no memory
is swapped out, while `__clear__cache` calls in between reads and writes ensure that
data is read from DRAM and not the intermediate caches.

The `memhold` program can then be used to reserve all pages with detected weak bits. As
we operate without access to the kernel, we must randomly allocate pages until we reach
the problematic page, and then release all other pages. This repeats until all pages with
weak bits are isolated, allowing other programs to run non-weak bits.

## Usage
```bash
memtest mbs_to_alloc iterations sleep_time max_errors_out out_file_template

pfn_find pfn_list.txt
```

## Requirements
* CMake 3.16 or newer
* GCC/LLVM toolchain with C++14 support

## Building
This program can be built using CMake.
```bash
mkdir build && cd build
cmake ..
make
```

## Relevant Papers
A Software-Based Approach to Radiation Mitigation for Planetary Missions, 2026 IEEE Aerospace Conference

[Radshield: Software Radiation Protection for Commodity Hardware in Space](https://dl.acm.org/doi/abs/10.1145/3760250.3762218), ASPLOS 2026

[Censible: A Robust and Practical Global Localization Framework for Planetary Surface Missions](https://www-robotics.jpl.nasa.gov/media/documents/2024_Global_Localization_ICRA.pdf), ICRA 2024

[Enabling Long & Precise Drives for The Perseverance Mars Rover via Onboard Global Localization](https://doi.org/10.48577/jpl.V3LJNP), 2024 IEEE Aerospace Conference
