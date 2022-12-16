cmake_minimum_required(VERSION 3.23)
project(shellcode_dropper_no_obfuscation)

set(CMAKE_CXX_STANDARD 14)

add_executable(unstaged unstaged.cpp)
add_executable(staged staged.cpp)
