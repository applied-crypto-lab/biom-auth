cmake_minimum_required(VERSION 3.12)
project(OTExtension LANGUAGES C CXX)

set (CMAKE_CXX_STANDARD 11)

if (CMAKE_COMPILER_IS_GNUCXX AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
    message(FATAL_ERROR "ENCRYPTO_utils require at least g++-8")
endif()

option(OTEXTENSION_BUILD_EXE "Build executables" ON)

find_package(ENCRYPTO_utils QUIET)
if(ENCRYPTO_utils_FOUND)
    message(STATUS "Found ENCRYPTO_utils")
elseif(NOT ENCRYPTO_utils_FOUND AND NOT TARGET ENCRYPTO_utils::encrypto_utils)
    message("ENCRYPTO_utils was not found: add ENCRYPTO_utils subdirectory")
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/ENCRYPTO_utils/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/ENCRYPTO_utils")
        execute_process(COMMAND git submodule update --init extern/ENCRYPTO_utils
                        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif()
    add_subdirectory(extern/ENCRYPTO_utils)
endif()
find_package(Threads REQUIRED)


add_library(otextension
    ot/alsz-ot-ext-rec.cpp
    ot/alsz-ot-ext-snd.cpp
#    ot/asharov-lindell.cpp
    ot/iknp-ot-ext-rec.cpp
    ot/iknp-ot-ext-snd.cpp
    ot/kk-ot-ext-rec.cpp
    ot/kk-ot-ext-snd.cpp
    ot/naor-pinkas.cpp
#    ot/naor-pinkas_noro.cpp
    ot/nnob-ot-ext-rec.cpp
    ot/nnob-ot-ext-snd.cpp
    ot/ot-ext.cpp
    ot/ot-ext-rec.cpp
    ot/ot-ext-snd.cpp
    ot/pvwddh.cpp
    ot/simpleot.cpp
)
add_library(OTExtension::otextension ALIAS otextension)


target_compile_features(otextension PUBLIC cxx_std_17)
target_compile_options(otextension PRIVATE "-Wall" "-Wextra")
#target_compile_options(otextension PUBLIC "-fno-omit-frame-pointer" "-fsanitize=address")
#target_link_options(otextension PUBLIC "-fno-omit-frame-pointer" "-fsanitize=address")

target_include_directories(otextension
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)


target_link_libraries(otextension
    PUBLIC ENCRYPTO_utils::encrypto_utils
    PUBLIC Threads::Threads
)


install(TARGETS otextension
        EXPORT "${PROJECT_NAME}Targets"
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        INCLUDES DESTINATION lib
)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/ot"
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
)
export(TARGETS otextension NAMESPACE "${PROJECT_NAME}::" FILE "${PROJECT_NAME}Targets.cmake")
install(EXPORT "${PROJECT_NAME}Targets"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "lib/cmake/${PROJECT_NAME}"
)


include(CMakePackageConfigHelpers)

configure_package_config_file("${CMAKE_CURRENT_LIST_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    INSTALL_DESTINATION "lib/cmake/${PROJECT_NAME}"
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    DESTINATION "lib/cmake/${PROJECT_NAME}"
)

###############################################################################
#	Additions
###############################################################################

set(MAINS_PATH "${PROJECT_SOURCE_DIR}/mains")
set(JGN_PATH "${PROJECT_SOURCE_DIR}/../JustGarble")

#NOTE msgpack library names differ between operating systems
#NOTE the provided package name is also not guaranteed to match the library file name
#NOTE the lines below attempt to extract this from the filesystem; assumes linux OS

#find msgpack library file
message("Scanning for msgpack installation...")
file(GLOB_RECURSE MSGPACK_LIB_MATCHES_LIST LIST_DIRECTORIES false "/usr/l*msgpack*.so")
#highly likely there is only one result; optimistically assume first match is correct
list(GET MSGPACK_LIB_MATCHES_LIST 0 MSGPACK_LIB_FILEPATH)
get_filename_component(MSGPACK_LIB_FILE ${MSGPACK_LIB_FILEPATH} NAME)
string(REGEX REPLACE "^\\l\\i\\b" "" MSGPACK_LIBNAME ${MSGPACK_LIB_FILE})
string(REGEX REPLACE "\\.\\s\\o$" "" MSGPACK_LIBNAME ${MSGPACK_LIBNAME})
string(PREPEND MSGPACK_LIBNAME "-l")
message(STATUS "Detected msgpack library file location: ${MSGPACK_LIB_FILEPATH}")

#find msgpack header file
file(GLOB_RECURSE MSGPACK_HEADER_MATCHES LIST_DIRECTORIES false "/usr/msgpack.h")
string(REGEX REPLACE "\\m\\s\\g\\p\\a\\c\\k\\.\\h$" "" MSGPACK_HEADER_DIR ${MSGPACK_HEADER_MATCHES})
message(STATUS "Detected msgpack header file location: ${MSGPACK_HEADER_DIR}")

add_library(msgpack SHARED IMPORTED GLOBAL)
set_target_properties(msgpack PROPERTIES
  IMPORTED_LOCATION "${MSGPACK_LIB_FILEPATH}"
  INTERFACE_INCLUDE_DIRECTORIES "${MSGPACK_HEADER_DIR}"
)


add_library(justGarble STATIC
    ${JGN_PATH}/src/aes.c
    ${JGN_PATH}/src/aescircuits.c
    ${JGN_PATH}/src/bio_auth.c
    ${JGN_PATH}/src/check.c
    ${JGN_PATH}/src/circuits.c
    ${JGN_PATH}/src/dkcipher.c
    ${JGN_PATH}/src/eval.c
    ${JGN_PATH}/src/garble.c
    ${JGN_PATH}/src/gates.c
    ${JGN_PATH}/src/bio_circuits.c
    ${JGN_PATH}/src/bio_common.c
    ${JGN_PATH}/src/bio_commit_funcs.c
    ${JGN_PATH}/src/scd.c
    ${JGN_PATH}/src/util.c
    ${JGN_PATH}/test/circuit_test_and_gen.c
)

target_compile_features(justGarble PRIVATE c_std_99)

target_include_directories(justGarble
    PRIVATE
        $<INSTALL_INTERFACE:${JGN_PATH}/include>
)

target_link_libraries(justGarble INTERFACE msgpack)

set(GCC_COVERAGE_COMPILE_FLAGS "-O2 -lrt -lpthread -lm -fPIE -maes -msse4 ${MSGPACK_LIBNAME} -march=native")

set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")


add_library(PeerNet STATIC
	${MAINS_PATH}/PeerNet.cpp
	${MAINS_PATH}/Timer.cpp
)

target_compile_features(PeerNet PRIVATE)

target_include_directories(PeerNet
    PRIVATE
        $<INSTALL_INTERFACE:${MAINS_PATH}>
)

add_subdirectory(mains)
add_subdirectory(${JGN_PATH} ${JGN_PATH}/bin)



