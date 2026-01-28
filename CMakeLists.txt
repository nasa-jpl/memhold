cmake_minimum_required(VERSION 3.16)
project(radiation_test)

set(CMAKE_CXX_STANDARD 17)

add_executable(memtest main.cpp)
target_link_libraries(memtest PUBLIC
  pthread
)

target_compile_options(memtest PUBLIC
  -fno-math-errno
  -fdelete-null-pointer-checks
  -fno-rtti
  -fdata-sections
  -ffunction-sections
)
target_link_options(memtest PUBLIC
  -Wl,--gc-sections
  -Wl,--icf=safe
)


add_executable(stuck_bit_injector stuck_bit_injector.cpp)
target_link_libraries(stuck_bit_injector PUBLIC
  pthread
)

target_compile_options(stuck_bit_injector PUBLIC
  -fno-math-errno
  -fdelete-null-pointer-checks
  -fno-exceptions
  -fno-rtti
  -fdata-sections
  -ffunction-sections
)
target_link_options(stuck_bit_injector PUBLIC
  -Wl,--gc-sections
  -Wl,--icf=safe
)

# The debug flag will only apply to cmake targets after this line
# Necessary because memhold uses asserts. -Oz reduces binary size
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE Debug)

add_executable(memhold
  pfn_hold.cpp
  pfn_utils.cpp
)

add_executable(memfind
  pfn_find.cpp
  pfn_utils.cpp
)

target_compile_options(memhold PUBLIC
  -Wall
  -Wextra
  -Werror
  -Wno-unused-command-line-argument
  -Oz
)

target_compile_options(memfind PUBLIC
  -Wall
  -Wextra
  -Werror
  -Wno-unused-command-line-argument
  -Oz
)
