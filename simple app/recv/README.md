> 本机环境为 Ubuntu20.04 ，dpdk-stable-20.11.10

# DPDK 应用基础


DPDK应用程序的一般处理流程如下：

**初始化DPDK环境**：调用`rte_eal_init()`初始化DPDK环境抽象层（EAL），设置运行时环境和配置。

**配置和绑定网卡**：使用`rte_eth_dev_configure()`配置网卡，包括队列、收发缓冲区等。绑定网卡到DPDK的驱动程序，以确保网卡被DPDK识别和控制。

**分配内存**：使用`rte_mempool_create()`创建内存池，用于存储数据包缓冲区。

**设置接收和发送队列**：使用`rte_eth_rx_queue_setup()`和`rte_eth_tx_queue_setup()`设置接收和发送队列，分配相应的内存和配置参数。

**启动网卡**：调用`rte_eth_dev_start()`启动网卡，使其开始接收和发送数据包。

**主处理循环**：进入主循环，调用`rte_eth_rx_burst()`从接收队列中获取数据包。
处理数据包，执行所需的操作，如数据包转发、处理或其他逻辑。使用`rte_eth_tx_burst()`将处理后的数据包发送到发送队列。

**清理资源**：在应用程序退出前，调用`rte_eth_dev_stop()`停止网卡，释放资源，调用`rte_mempool_free()`释放内存池。
# 头文件

```c
// DPDK
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
//Linux
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
```

# 定义关键变量

```c
#define RX_RING_SIZE 128  //发送环形缓冲区
#define NUM_MBUFS 8191  //数据包缓冲池
#define MBUF_CACHE_SIZE 0  //内存池中每个缓存的大小(以数据包为单位)
#define BURST_SIZE 32  //批量处理的大小

#define DPDK_QUEUE_ID_RX 0 // 接收队列ID

int g_dpdkPortId = -1;  //网络端口ID
static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};
```

其中，`g_dpdkPortId`是我们要使用的网络端口，需要在下面初始化的时候找一个空闲的。`rte_eth_conf`是包含了各种配置选项，用于设置网卡的工作模式、队列、过滤器等（需要根据实际网卡来设置）。本文的simple app 只需要设置一下rx（接收队列）的设置即可。

# 端口初始化

```c
static void port_init(struct rte_mempool *mbuf_pool) {
    // 查找空闲端口
    g_dpdkPortId = 0;
    while (g_dpdkPortId < RTE_MAX_ETHPORTS &&
	       rte_eth_devices[g_dpdkPortId].data->owner.id != RTE_ETH_DEV_NO_OWNER) {
		g_dpdkPortId++;
    }
    printf("ports:%d \n",g_dpdkPortId);
    if (g_dpdkPortId == RTE_MAX_ETHPORTS) {
        rte_exit(EXIT_FAILURE, "There were no DPDK ports free.\n");
    }
 
    const int num_rx_queues = 1;
    const int num_tx_queues = 0;
    struct rte_eth_conf port_conf = port_conf_default;
    if (rte_eth_dev_configure(g_dpdkPortId, num_rx_queues, num_tx_queues, &port_conf)) {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_configure() failed.\n");
    }

    // 设置接收队列
    if (rte_eth_rx_queue_setup(g_dpdkPortId, DPDK_QUEUE_ID_RX, RX_RING_SIZE,
            rte_eth_dev_socket_id(g_dpdkPortId), NULL, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup RX queue.\n");
    }
    // 启动网卡
    if (rte_eth_dev_start(g_dpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Device start failed.\n");
    }

    // 设置为混杂模式
    rte_eth_promiscuous_enable(g_dpdkPortId);
}
```

当NIC处于混杂模式时，它将接收所有经过它的网络数据包，这样捕获所有的流量。
# 简单解析数据包

```c
void process_packet(struct rte_mbuf *mbuf) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint8_t *packet_data;
    uint16_t ether_type;
    uint16_t l4_len;

    // 获取数据包指针
    packet_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    eth_hdr = (struct rte_ether_hdr *)packet_data;

    // 输出以太网头部信息
    printf("MAC Src: ");
    for (int j = 0; j < RTE_ETHER_ADDR_LEN; j++) {
        printf("%02x", eth_hdr->s_addr.addr_bytes[j]);
        if (j < RTE_ETHER_ADDR_LEN - 1) printf(":");
    }
    printf(" -> MAC Dst: ");
    for (int j = 0; j < RTE_ETHER_ADDR_LEN; j++) {
        printf("%02x", eth_hdr->d_addr.addr_bytes[j]);
        if (j < RTE_ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");

    // 确保数据包是 IPv4 类型
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        // 操作IP数据包头部
        ipv4_hdr = (struct rte_ipv4_hdr *)(packet_data + sizeof(struct rte_ether_hdr));
        printf("IP Src: %d.%d.%d.%d -> IP Dst: %d.%d.%d.%d\n",
            ipv4_hdr->src_addr & 0xFF, (ipv4_hdr->src_addr >> 8) & 0xFF, (ipv4_hdr->src_addr >> 16) & 0xFF, (ipv4_hdr->src_addr >> 24) & 0xFF,
            ipv4_hdr->dst_addr & 0xFF, (ipv4_hdr->dst_addr >> 8) & 0xFF, (ipv4_hdr->dst_addr >> 16) & 0xFF, (ipv4_hdr->dst_addr >> 24) & 0xFF
        );

        // 计算传输层协议
        uint8_t proto = ipv4_hdr->next_proto_id;
        // 传输层协议长度
        l4_len = rte_be_to_cpu_16(ipv4_hdr->total_length) - (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * 4;
        if (proto == IPPROTO_TCP) {
            // 计算TCP头部所在的位置
            tcp_hdr = (struct rte_tcp_hdr *)(packet_data + sizeof(struct rte_ether_hdr) + (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * 4);
            printf("TCP Src Port: %d -> TCP Dst Port: %d\n",
                rte_be_to_cpu_16(tcp_hdr->src_port), rte_be_to_cpu_16(tcp_hdr->dst_port)
            );
        } else if (proto == IPPROTO_UDP) {
            udp_hdr = (struct rte_udp_hdr *)(packet_data + sizeof(struct rte_ether_hdr) + (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * 4);
            printf("UDP Src Port: %d -> UDP Dst Port: %d\n",
                rte_be_to_cpu_16(udp_hdr->src_port), rte_be_to_cpu_16(udp_hdr->dst_port)
            );
        } else {
            printf("Unsupported IP protocol: %d\n", proto);
        }
    } else {
        printf("Unsupported Ethernet type: %x\n", ether_type);
    }
}
```


**获取数据包内容**：`rte_pktmbuf_mtod`函数将数据包转换为uint8_t *类型，uint8_t表示单个字节，通过这个指针，可以逐字节地读取或写入数据包的任意部分，从而直接处理数据包的内容。

**解析以太网头部**：提取并打印源和目的MAC地址。`RTE_ETHER_ADDR_LEN`用于确定MAC地址的长度。

**检查以太网类型**：通过`rte_be_to_cpu_16`将网络字节顺序的以太网类型转换为主机字节顺序。支持IPv4类型的数据包。

**解析IPv4头部**：提取并打印源和目的IP地址。计算IP头部长度和总长度，以确定传输层数据的起始位置。

**处理传输层协议**：根据IPv4头部中的`next_proto_id`字段，判断是TCP还是UDP协议，并解析相应的头部信息。对于TCP和UDP数据包，打印源和目的端口号。

**输出不支持的协议**：如果以太网类型或IP协议不是支持的类型，打印相应的错误信息。

# 主函数

```c
int main(int argc, char *argv[]) {
    // 初始化了 DPDK 的环境抽象层
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Couldn't create mbuf pool\n");
    }

    port_init(mbuf_pool);
    static uint8_t g_mac_addr[ETH_ALEN];
    // 获取此时的mac地址输出
    rte_eth_macaddr_get(g_dpdkPortId, (struct ether_addr *)g_mac_addr);
    printf("Our MAC: %02x %02x %02x %02x %02x %02x\n",
        g_mac_addr[0], g_mac_addr[1],
        g_mac_addr[2], g_mac_addr[3],
        g_mac_addr[4], g_mac_addr[5]);
    
    while (1) {
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(g_dpdkPortId, DPDK_QUEUE_ID_RX, mbufs, BURST_SIZE);
        for (unsigned i = 0; i < num_recvd; i++) {
            process_packet(mbufs[i]);
            rte_pktmbuf_free(mbufs[i]);
        }
    }
    return 0;
}
```

**DPDK环境初始化**：使用`rte_eal_init`初始化DPDK环境抽象层（EAL）。

**创建内存池**：用于存储数据包缓冲区（mbuf）

**端口初始化**：调用`port_init`函数来初始化网络端口，配置其使用创建的内存池。

**主循环**：调用`rte_eth_rx_burst`从网络端口接收数据包，并将接收到的数据包传递给`process_packet`进行处理。处理完成后，释放mbuf。
# 编译

```c
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
add_executable(recv recv.c)

# 链接 DPDK 库
target_link_libraries(recv ${RTE_LIBRARIES})

# 设置库搜索路径
link_directories(/usr/local/lib/x86_64-linux-gnu)

# 链接选项
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/d68f554693c846b2856a52f604214556.png)

