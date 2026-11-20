cmake_minimum_required(VERSION 3.16)
project(stary LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(stary main.cpp)
target_link_libraries(stary PRIVATE OpenSSL::Crypto Threads::Threads)

enable_testing()
add_executable(stary_tests tests.cpp)
target_link_libraries(stary_tests PRIVATE OpenSSL::Crypto Threads::Threads)
add_test(NAME stary_tests COMMAND stary_tests)
