# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Canonical native build for package:webcrypto.
#
# This file is used by the Dart Native Assets build hook on Android, iOS,
# Linux, macOS, and Windows. It is also retained as the build entry point for
# `dart run webcrypto:setup` while older direct-script workflows are supported.

cmake_minimum_required(VERSION 3.14)
project(webcrypto LANGUAGES C)

set(BORINGSSL_ROOT "${CMAKE_CURRENT_LIST_DIR}/../third_party/boringssl/")
include("${BORINGSSL_ROOT}/sources.cmake")

# Trade performance for a smaller binary. This is the option used by all
# historical package:webcrypto platform builds.
add_compile_definitions(OPENSSL_SMALL)

# Native Assets passes these explicitly. Infer them for the legacy setup path.
if(NOT DEFINED WEBCRYPTO_BORINGSSL_ARCH)
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _webcrypto_processor)
  if(_webcrypto_processor MATCHES "^(x86_64|amd64)$")
    set(WEBCRYPTO_BORINGSSL_ARCH "x86_64")
  elseif(_webcrypto_processor MATCHES "^(x86|i[3-6]86)$")
    set(WEBCRYPTO_BORINGSSL_ARCH "x86")
  elseif(_webcrypto_processor MATCHES "^(aarch64|arm64|arm64e)$")
    set(WEBCRYPTO_BORINGSSL_ARCH "aarch64")
  elseif(_webcrypto_processor MATCHES "^arm")
    set(WEBCRYPTO_BORINGSSL_ARCH "arm")
  elseif(_webcrypto_processor STREQUAL "ppc64le")
    set(WEBCRYPTO_BORINGSSL_ARCH "ppc64le")
  else()
    set(WEBCRYPTO_BORINGSSL_ARCH "generic")
  endif()
endif()

if(NOT DEFINED WEBCRYPTO_BORINGSSL_PLATFORM)
  if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(WEBCRYPTO_BORINGSSL_PLATFORM "win")
  elseif(APPLE)
    set(WEBCRYPTO_BORINGSSL_PLATFORM "apple")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Android" OR
         CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # BoringSSL's generated Android assembly uses the linux_* source lists.
    set(WEBCRYPTO_BORINGSSL_PLATFORM "linux")
  else()
    message(FATAL_ERROR
      "Unsupported webcrypto target system: ${CMAKE_SYSTEM_NAME}. "
      "Expected Android, iOS, Linux, macOS, or Windows.")
  endif()
endif()

set(_webcrypto_asm_var
  "crypto_sources_${WEBCRYPTO_BORINGSSL_PLATFORM}_${WEBCRYPTO_BORINGSSL_ARCH}")
if(DEFINED ${_webcrypto_asm_var})
  set(webcrypto_asm_sources ${${_webcrypto_asm_var}})
else()
  message(WARNING
    "No BoringSSL assembly list ${_webcrypto_asm_var}; building without ASM")
  add_compile_definitions(OPENSSL_NO_ASM)
  set(webcrypto_asm_sources)
endif()

if(NOT WIN32)
  enable_language(ASM)
elseif(WEBCRYPTO_BORINGSSL_ARCH STREQUAL "aarch64" AND NOT MSVC)
  enable_language(ASM)
endif()

if(WIN32)
  # The generated Windows ARM64 sources are preprocessed GNU-style .S files.
  # MSVC's ARM assembler does not accept that format. Disable assembly
  # explicitly for this one toolchain/architecture combination rather than
  # silently producing the wrong architecture or accidentally selecting NASM.
  if(MSVC AND WEBCRYPTO_BORINGSSL_ARCH STREQUAL "aarch64")
    message(STATUS
      "Building Windows ARM64 with MSVC and OPENSSL_NO_ASM; generated "
      "BoringSSL ARM64 .S files require a Clang integrated assembler")
    add_compile_definitions(OPENSSL_NO_ASM)
    set(webcrypto_asm_sources)
  endif()

  # BoringSSL's x86/x64 Windows assembly uses NASM syntax. Explicitly assign
  # NASM because CMake also recognizes .asm as generic ASM and could otherwise
  # select ml/ml64.
  if(webcrypto_asm_sources AND
     (WEBCRYPTO_BORINGSSL_ARCH STREQUAL "x86" OR
      WEBCRYPTO_BORINGSSL_ARCH STREQUAL "x86_64"))
    enable_language(ASM_NASM)
    set_source_files_properties(${webcrypto_asm_sources}
      PROPERTIES LANGUAGE ASM_NASM)
    if(MSVC)
      set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -gcv8")
    endif()
  endif()

  add_compile_definitions(
    _HAS_EXCEPTIONS=0
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
  )

  if(MSVC)
    # Scope MSVC switches to C compilation. Passing these to NASM makes the
    # assembly build fail because options such as /utf-8 and /W4 are not NASM
    # arguments.
    add_compile_options(
      $<$<COMPILE_LANGUAGE:C>:/utf-8>
      $<$<COMPILE_LANGUAGE:C>:/W4>
      $<$<COMPILE_LANGUAGE:C>:/WX>
      $<$<COMPILE_LANGUAGE:C>:/wd4100>
      $<$<COMPILE_LANGUAGE:C>:/wd4127>
      $<$<COMPILE_LANGUAGE:C>:/wd4141>
      $<$<COMPILE_LANGUAGE:C>:/wd4244>
      $<$<COMPILE_LANGUAGE:C>:/wd4267>
      $<$<COMPILE_LANGUAGE:C>:/wd4706>
    )
    # Multi-config Visual Studio generators otherwise place the DLL in a
    # Release/ subdirectory. A stable root output simplifies hook publication.
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "$<1:${CMAKE_BINARY_DIR}>")
  endif()
endif()

add_library(webcrypto SHARED
  "${CMAKE_CURRENT_LIST_DIR}/webcrypto.c"
  "${CMAKE_CURRENT_LIST_DIR}/symbols.generated.c"
  ${crypto_sources}
  ${webcrypto_asm_sources}
)

target_include_directories(webcrypto PRIVATE
  "${BORINGSSL_ROOT}/src/include"
)

set_target_properties(webcrypto PROPERTIES
  C_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES
  LINKER_LANGUAGE C
  OUTPUT_NAME webcrypto
)
