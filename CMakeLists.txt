cmake_minimum_required(VERSION 3.11)

project(main)

set(CMAKE_CXX_STANDARD 17)

add_executable(main main.cpp)

target_compile_options(main PRIVATE -Wall -O2)
# target_include_directories(main PRIVATE )
# target_link_directories(main PRIVATE )
# target_link_libraries(main PRIVATE -pthread)


find_package(cryptopp CONFIG REQUIRED)
target_link_libraries(main PRIVATE cryptopp-static)