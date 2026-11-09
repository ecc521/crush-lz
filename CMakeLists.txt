# Builds the C libraries for consumers who are not using Cargo.
#
# The Rust crates compile these same sources themselves via build.rs and do not
# need this file. 
#
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build
#   cmake --install build --prefix /usr/local
#
# Installs two libraries, their headers and pkg-config files, so a consumer
# links with `pkg-config --cflags --libs crushlzfse` and nothing else.

cmake_minimum_required(VERSION 3.16)
project(crushlz VERSION 0.1.0 LANGUAGES C
        HOMEPAGE_URL "https://github.com/ecc521/crush-lz")

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_compile_options($<$<CONFIG:Release>:-O3>)

# The crates compile these same sources through build.rs, and the harness
# through flags.mk; both add flags this file was missing, so a library
# installed from here was not the library either of those measure. What
# follows mirrors them. Every flag is probed rather than assumed, so a
# compiler that does not take them still builds, just without the fast
# paths, which is what this file did for all of them before.
include(CheckCCompilerFlag)

function(crushlz_add_flag target flag var)
  check_c_compiler_flag("${flag}" ${var})
  if(${var})
    target_compile_options(${target} PRIVATE "${flag}")
  endif()
endfunction()

include(CheckCSourceCompiles)

check_c_source_compiles("
#if !defined(__x86_64__) && !defined(_M_X64)
#error not x86_64
#endif
int main(void) { return 0; }
" CRUSHLZ_TARGET_X86_64)

if(CRUSHLZ_TARGET_X86_64 OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$" OR CMAKE_OSX_ARCHITECTURES MATCHES "x86_64")
  set(CRUSHLZ_X86_64 TRUE)
endif()

add_library(crushlzfse
  crates/crushlzfse/csrc/lzfse_encode.c
  crates/crushlzfse/csrc/lzfse_encode_base.c
  crates/crushlzfse/csrc/lzfse_decode.c
  crates/crushlzfse/csrc/lzfse_decode_base.c
  crates/crushlzfse/csrc/lzvn_encode_base.c
  crates/crushlzfse/csrc/lzvn_decode_base.c
  crates/crushlzfse/csrc/lzfse_fse.c
  crates/crushlzfse/csrc/crushlzfse.c
  crates/crushlzfse/csrc/crushlzvn.c
)
target_include_directories(crushlzfse PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crates/crushlzfse/csrc>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
set_target_properties(crushlzfse PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  C_VISIBILITY_PRESET hidden
)

add_library(lzbitmap
  crates/lzbitmap/csrc/libzbitmap.c
)
target_include_directories(lzbitmap PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crates/lzbitmap/csrc>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
set_target_properties(lzbitmap PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  C_VISIBILITY_PRESET hidden
)

# csrc/vendor/lz4 is upstream LZ4, unmodified and BSD-2-Clause; crushlz4.c is
# ours and MPL-2.0. They are separate sources in one library, not a fork.
add_library(crushlz4
  crates/crushlz4/csrc/crushlz4.c
  crates/crushlz4/csrc/vendor/lz4/lz4.c
  crates/crushlz4/csrc/vendor/lz4/lz4hc.c
)
target_include_directories(crushlz4 PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crates/crushlz4/csrc>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
set_target_properties(crushlz4 PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  C_VISIBILITY_PRESET hidden
)

# ---------------------------------------------------------------- C flags
#
# All three: -fno-strict-aliasing, which every build.rs and flags.mk set.
foreach(tgt crushlzfse lzbitmap crushlz4)
  crushlz_add_flag(${tgt} -fno-strict-aliasing HAVE_FNO_STRICT_ALIASING)
endforeach()

option(CRUSHLZ_SIMD_PORTABLE
  "Build for pre-Haswell x86-64: no -march=x86-64-v3, lzbitmap on its scalar crush_simd.h branch" OFF)

if(CRUSHLZ_SIMD_PORTABLE)
  target_compile_definitions(lzbitmap PRIVATE CRUSH_SIMD_PORTABLE)
elseif(CRUSHLZ_X86_64)
  # x86-64 targets Haswell (AVX2, BMI1/2, FMA), which every Intel Mac macOS
  # still supports has; see harness/flags.mk.
  foreach(tgt crushlzfse lzbitmap crushlz4)
    crushlz_add_flag(${tgt} -march=x86-64-v3 HAVE_MARCH_X86_64_V3)
  endforeach()
endif()

# ------------------------------------------------------------------- install
install(TARGETS crushlzfse lzbitmap crushlz4
  EXPORT crushlzTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
  crates/crushlzfse/csrc/crushlzfse.h
  crates/crushlzfse/csrc/crushlzvn.h
  crates/crushlzfse/csrc/lzfse.h
  crates/lzbitmap/csrc/crushlzbitmap.h
  crates/crushlz4/csrc/crushlz4.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

foreach(pc crushlzfse lzbitmap crushlz4)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/packaging/${pc}.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/${pc}.pc
    @ONLY
  )
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${pc}.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endforeach()
