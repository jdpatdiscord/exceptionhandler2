cmake_minimum_required(VERSION 3.15)

project(exceptionhandler LANGUAGES C)

option(ZYDIS_FEATURE_ENCODER "" OFF)
option(ZYDIS_FEATURE_DECODER "" ON)
option(ZYDIS_FEATURE_FORMATTER "" OFF)
option(ZYDIS_FEATURE_AVX512 "" ON)
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
option(ZYDIS_BUILD_MAN "" OFF)
option(ZYDIS_BUILD_DOXYGEN "" OFF)
option(ZYDIS_BUILD_TESTS "" OFF)
option(ZYDIS_BUILD_SHARED_LIB "" OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -g3 -gcodeview")

add_subdirectory(zydis/)

set(CMAKE_C_STANDARD_LIBRARIES "-lZydis -lZycore -ldbghelp -lmsvcrt -lkernel32 -lntdll")

add_library(exceptionhandler_lib
    MODULE
    ExceptionHandler.c
    ExceptionHandler.h
    DllMain.c)

set_property(TARGET exceptionhandler_lib PROPERTY C_STANDARD 90)
include_directories(${CMAKE_SOURCE_DIR}/zydis/include ${CMAKE_SOURCE_DIR}/zydis/dependencies/zycore/include)
target_link_directories(exceptionhandler_lib PUBLIC ${CMAKE_SOURCE_DIR}/build/zydis/ ${CMAKE_SOURCE_DIR}/build/zydis/zycore)
add_dependencies(exceptionhandler_lib Zydis)