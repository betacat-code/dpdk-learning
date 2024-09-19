cmake_minimum_required(VERSION 3.10)
project(dpdk_receive)

# 设置 C 标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设定编译选项
add_compile_options(-O3 -march=native)
add_definitions(-DALLOW_EXPERIMENTAL_API)

# 查找 DPDK 包
find_package(PkgConfig REQUIRED)
pkg_check_modules(RTE REQUIRED libdpdk)

# 包含 DPDK 头文件
include_directories(${RTE_INCLUDE_DIRS})

# 添加可执行文件
add_executable(recv recv.c)

# 链接 DPDK 库
target_link_libraries(recv ${RTE_LIBRARIES})

# 设置库搜索路径
link_directories(/usr/local/lib/x86_64-linux-gnu)

# 链接选项
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")

