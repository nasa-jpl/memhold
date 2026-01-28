#include <cassert>
#include <csignal>
#include <ctime>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <system_error>
//#include <cerrno>
//#include <stdio.h>
//#include <sys/mman.h>
//#include <unistd.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUF_SIZE 65536

// In LLVM libcompiler-rt, this call calls the Linux cacheflush syscall.
// ARM documentation notes that this syscall cleans the data cache range
// in addition to invalidating the instruction cache range.
// https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/caches-and-self-modifying-code
extern "C" void __clear_cache(void *beg, void *end);

// Memory space to test and buffer to assist with writes
volatile uint8_t *memory_space = nullptr;
char *buf = nullptr;
size_t errors_detected = 0, max_errors_out, memory_size, sleep_time;

//int cp(const char *src_path, const char *dst_path) {
int cp(const std::string &src_path, const std::string &dst_path) {
    int src_fd = open(src_path.c_str(), O_RDONLY);
    if (src_fd < 0) {
        perror(src_path.c_str());
        return -1;
    }

    // Removed "remove" call, which was failing silently
    // because file often didn't exist

    // Create file if missing, or truncate to 0 if exists
    int dst_fd = open(dst_path.c_str(),
                      O_WRONLY   // write-only
                      | O_CREAT  // create if it doesn't exist
                      | O_TRUNC, // truncate file to zero if it does exist
                      0777);
    if (dst_fd < 0) {
        perror(dst_path.c_str());
        close(src_fd);
        return -1;
    }

    // Copy loop with handling of short writes
    ssize_t nread;
    while ((nread = read(src_fd, buf, BUF_SIZE)) > 0) {
        char *out_ptr = buf;
        ssize_t nwritten;
        do {
            // write() may write fewer bytes than requested, so
            // we need to handle this corner case
            nwritten = write(dst_fd, out_ptr, nread);
            if (nwritten < 0) {
                perror("write");
                close(src_fd);
                close(dst_fd);
                return -1;
            }
            nread   -= nwritten;
            out_ptr += nwritten;
        } while (nread > 0);
    }
    if (nread < 0) {
        perror("read");
    }

    close(src_fd);
    close(dst_fd);
    return (nread < 0) ? -1 : 0;
}

void save_system_files(const std::string &folder_name) {
  std::string pid = std::to_string(getpid());

  // Make sure the folder isn't a file already
  // No need to handle failures (e.g. file does not exist)
  remove(folder_name.c_str());

  int ret_code = mkdir(folder_name.c_str(), 0755);
  // Do not fail if the pathname exists already
  if (ret_code != 0 && errno != EEXIST) {
    std::cerr << "Failed to create folder with err code: " << errno << std::endl;
    return;
  }

  // Not bothering to check return status, because there is nothing
  // we would do to "handle" the problem
  cp("/proc/" + pid + "/pagemap", folder_name + "/pagemap");
  cp("/proc/" + pid + "/maps", folder_name + "/maps");
  cp("/proc/kpagecount", folder_name + "/kpagecount");
  cp("/proc/kpageflags", folder_name + "/kpageflags");
}

void write_and_test(unsigned int iteration, uint64_t cmp, std::ofstream &out_file) {
  uint64_t *curr = nullptr;

  // Write alternating 1s and 0s into memory
  for (size_t i = 0; i < memory_size / 8; i++) {
    curr = (uint64_t *)(memory_space + (i * 8));
    *curr = cmp;
  }

  // Clear cache to make sure we're reading from memory
  __clear_cache((void *) memory_space, (void *)(memory_space + memory_size));

  // Wait n seconds
  sleep(sleep_time);

  // Make sure all bits in memory match
  for (size_t i = 0; i < memory_size / 8; i++) {
    curr = (uint64_t *)(memory_space + (i * 8));
    if (*curr != cmp) {
      if (errors_detected < max_errors_out) {
        out_file << iteration << "," << std::time(nullptr) << "," << std::hex << static_cast<void*>(curr) << ","
                 << std::hex << *curr << "," << std::hex << cmp << std::endl << std::dec; // reset to decimal after std::hex
      }
      errors_detected += 1;
    }
  }
}

int main(int argc, char *argv[]) {
  unsigned int iter = 0;

  if (argc != 6) {
    std::cout << "Usage: " << argv[0] << " mbs_to_alloc iterations sleep_time max_errors_out out_file_template" << std::endl;
    return 1;
  }

  // Read cmd line arguments
  memory_size = 1024 * 1024 * std::atoll(argv[1]);
  iter = std::atoi(argv[2]);
  sleep_time = std::atoi(argv[3]);
  max_errors_out = std::atoi(argv[4]);
  const std::string out_pref = std::string(argv[5]);

  // Changed asserts to if statement checks,
  // since the asserts are removed in the release build
  if (memory_size <= 0 || iter <= 0 || sleep_time < 0 \
      || max_errors_out < 0 || out_pref.length() == 0) {
      std::cerr << "Invalid numeric arguments\n";
      return 2;
  }  

  // Allocate buf and memory space
  buf = (char *) malloc(BUF_SIZE);
  if (buf == NULL) {
      perror("malloc buf");
      return 3;
  }
  memory_space = (uint8_t *) malloc(memory_size);
  if (memory_space == NULL) {
      perror("malloc memory_space");
      return 4;
  }

  // Pin memory
  if (mlock((char *) memory_space, memory_size) != 0) {
      std::cerr << "mlock failed: " << std::strerror(errno) << "\n";
      return 5;
  }
  
  // Open output files
  std::ofstream csv_out_file(out_pref + ".csv");
  std::ofstream err_count_out_file(out_pref + ".txt");

  // Write out CSV header and record starting time
  csv_out_file << "iter,time,virtual_addr,actual,expected" << std::endl;
  csv_out_file << "0," << std::time(nullptr) << ",0,0,0" << std::endl;

  // Loop through N iterations and test a couple patterns
  for (unsigned int i = 1; i <= iter; i++) {
    write_and_test(i, 0xaaaaaaaaaaaaaaaa, csv_out_file); // 0b10101010
    write_and_test(i, 0x5555555555555555, csv_out_file); // 0b01010101

    write_and_test(i, 0x0000000000000000, csv_out_file); // 0b00000000
    write_and_test(i, 0xffffffffffffffff, csv_out_file); // 0b11111111

    write_and_test(i, 0x0f0f0f0f0f0f0f0f, csv_out_file); // 0b00001111
    write_and_test(i, 0xf0f0f0f0f0f0f0f0, csv_out_file); // 0b11110000
  }

  // Flush CSV file with all errors
  csv_out_file.flush();
  csv_out_file.close();

  // Write error count to file
  err_count_out_file << errors_detected << std::endl;
  err_count_out_file.flush();
  err_count_out_file.close();

  // Save memory maps to disk after starting the test
  save_system_files("memmaps." + out_pref);
  
  // Free up all data allocated
  munlock((char *) memory_space, memory_size);
  free((char *) memory_space);
  free((char *) buf);

  return 0;
}

