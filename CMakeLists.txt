cmake_minimum_required(VERSION 3.24)
project(differential_attack)

set(CMAKE_CXX_STANDARD 17)

add_executable(differential_attack main.cpp cipher.cpp)

add_executable(test test.cpp cipher.cpp)