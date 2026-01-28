# Software SEE Testing for Commodity SoCs
This tool detects and locates potential stuck or sticky bits in DRAM. The default
configuration is meant for the Snapdragon 801 SoC on the Mars 2020 HBS, but can be
easily adapted to support other chipsets.

## Usage
```bash
memhold mbs_to_alloc iterations sleep_time max_errors_out out_file_template
```

## Requirements
* CMake 3.16 or newer
* GCC/LLVM toolchain with C++14 support

## Building
This project is meant to be built as part of HCE-FSW. Follow the build instructions
in the M20-HCE/HCE-FSW repo. The `wanghaod-rad-hardening` branch keeps track of this
repo. The `radiation_test` target will build and compile a minimal binary for HBS
(~162KB gzip-ed).

## Design
The program reserves `memory_size` megabytes of memory using `malloc` and writes an
array of different repeating pattern to the reserved locations. After a user-specified
wait time, the memory location is then read back again, and the read pattern compared
to the written one. Errors are then logged to `<output_file_template>.csv` in a CSV
format. Kernel page information is also saved to allow logged virtual memory addresses
to be converted to physical memory addresses. `mlock` is used to ensure that no memory
is swapped out, while `__clear__cache` calls in between reads and writes ensure that
data is read from DRAM and not the intermediate caches.

## Example CSV output
```csv
iter,time,virtual_addr,actual,expected
0,11741703296,0,0,0
1,11741733527,0x7ffff7b0b010,0x5555455555555555,0x5555555555555555
