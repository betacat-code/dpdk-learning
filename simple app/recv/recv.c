// DPDK
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>

#define RX_RING_SIZE 128  //发送环形缓冲区
#define NUM_MBUFS 8191  //数据包缓冲池
#define MBUF_CACHE_SIZE 0  //内存池中每个缓存的大小(以数据包为单位)
#define BURST_SIZE 32  //批量处理的大小

#define DPDK_QUEUE_ID_RX 0 // 接收队列ID

int g_dpdkPortId = -1;  //网络端口ID
static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

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

    if (rte_eth_dev_start(g_dpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Device start failed.\n");
    }

    // 设置为混杂模式
    rte_eth_promiscuous_enable(g_dpdkPortId);
}

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
        ipv4_hdr = (struct rte_ipv4_hdr *)(packet_data + sizeof(struct rte_ether_hdr));
        printf("IP Src: %d.%d.%d.%d -> IP Dst: %d.%d.%d.%d\n",
            ipv4_hdr->src_addr & 0xFF, (ipv4_hdr->src_addr >> 8) & 0xFF, (ipv4_hdr->src_addr >> 16) & 0xFF, (ipv4_hdr->src_addr >> 24) & 0xFF,
            ipv4_hdr->dst_addr & 0xFF, (ipv4_hdr->dst_addr >> 8) & 0xFF, (ipv4_hdr->dst_addr >> 16) & 0xFF, (ipv4_hdr->dst_addr >> 24) & 0xFF
        );

        // 计算层4头部的起始位置
        uint8_t proto = ipv4_hdr->next_proto_id;
        l4_len = rte_be_to_cpu_16(ipv4_hdr->total_length) - (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * 4;
        if (proto == IPPROTO_TCP) {
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
