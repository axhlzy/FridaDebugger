cmake_minimum_required(VERSION 3.10)

project(packlibs)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--whole-archive")

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/code SRC_LIST)

add_library(${PROJECT_NAME} SHARED main.cpp ${SRC_LIST})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/code)

# link QBDI
target_link_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/QBDI/${ANDROID_ABI}/include)
target_link_libraries(${PROJECT_NAME} -Wl,--whole-archive ${CMAKE_CURRENT_SOURCE_DIR}/QBDI/${ANDROID_ABI}/lib/libQBDI.a -Wl,--no-whole-archive)

# link LIEF
set(LIEF_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/LIEF/${ANDROID_ABI})
set(LIEF_DIR ${LIEF_ROOT_DIR}/share/LIEF/cmake)
message(STATUS "LIEF_DIR: ${LIEF_DIR}")
find_package(LIEF REQUIRED)
target_link_libraries(${PROJECT_NAME} -Wl,--whole-archive LIEF::LIEF -Wl,--no-whole-archive)

find_library(log-lib log)
target_link_libraries(${PROJECT_NAME} ${log-lib})

if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -g")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -g")
endif()