cmake_minimum_required(VERSION 3.12)
project(Network_analyser)
set(CMAKE_C_STANDARD 99)
include(FindPCAP.cmake)
add_executable(Network_analyser analyser.c)
include_directories(C:/WpdPack/Include)
target_link_libraries(Network_analyser C:/WpdPack/Lib/x64/wpcap.lib)
#after your flags
