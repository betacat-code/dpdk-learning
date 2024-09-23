#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define NUM_MBUFS (8192)  // 增加了用于更大缓冲池的MBUF数量
#define BURST_SIZE 32  // 每次从接收队列中读取的包数量
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static const uint32_t LOCAL_IP = MAKE_IPV4_ADDR(192, 168, 131, 153);  // 本地IP地址
static uint8_t src_mac[RTE_ETHER_ADDR_LEN];  // 本地MAC地址

int gDpdkPortId = 0;  // 端口ID

// 默认端口配置
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
};

// 初始化DPDK端口
static void init_port(struct rte_mempool *mbuf_pool) {
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;

    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to set up RX queue\n");
    }

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;

    if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to set up TX queue\n");
    }

    if (rte_eth_dev_start(gDpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to start Ethernet device\n");
    }

    rte_eth_promiscuous_enable(gDpdkPortId);  // 启用混杂模式，接收所有包
}

// 计算校验和
static uint16_t checksum(uint16_t *addr, int count) {
    register long sum = 0;

    while (count > 1) {
        sum += *(unsigned short*)addr++;
        count -= 2;
    }

    if (count > 0) {
        sum += *(unsigned char *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

// 编码并构建ICMP包
static void encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip, 
                               uint16_t id, uint16_t seqnb) {
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);  // 设置源MAC
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);  // 设置目标MAC
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);  // 设置以太类型为IPv4

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(sizeof(struct rte_icmp_hdr) + sizeof(struct rte_ipv4_hdr));  // IP报文长度
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_ICMP;  // 下一层协议为ICMP
    ip->src_addr = sip;  // 设置源IP地址
    ip->dst_addr = dip;  // 设置目标IP地址
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);  // 计算并设置IP头校验和

    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip + 1);
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;  // 设置ICMP类型为回显应答
    icmp->icmp_code = 0;
    icmp->icmp_ident = id;
    icmp->icmp_seq_nb = seqnb;
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = checksum((uint16_t *)icmp, sizeof(struct rte_icmp_hdr));  // 计算ICMP校验和

    // 输出ICMP报文相关信息
    printf("ICMP Packet:\n");
    printf("  Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
           eth->s_addr.addr_bytes[0], eth->s_addr.addr_bytes[1], eth->s_addr.addr_bytes[2],
           eth->s_addr.addr_bytes[3], eth->s_addr.addr_bytes[4], eth->s_addr.addr_bytes[5]);
    printf("  Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
           eth->d_addr.addr_bytes[0], eth->d_addr.addr_bytes[1], eth->d_addr.addr_bytes[2],
           eth->d_addr.addr_bytes[3], eth->d_addr.addr_bytes[4], eth->d_addr.addr_bytes[5]);
    printf("  Source IP: %s\n", inet_ntoa(*(struct in_addr *)&sip));
    printf("  Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&dip));
}

// 发送ICMP包
static void send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip, 
                         uint16_t id, uint16_t seqnb) {
    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);  // 分配内存池中的mbuf
    if (mbuf == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to allocate mbuf for ICMP\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);  // 获取数据指针
    encode_icmp_pkt(pktdata, dst_mac, sip, dip, id, seqnb);  // 构建ICMP包

    rte_eth_tx_burst(gDpdkPortId, 0, &mbuf, 1);  // 发送ICMP包
    rte_pktmbuf_free(mbuf);  // 释放mbuf
}

// 编码并构建ARP包
static void encode_arp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);  // 设置源MAC
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);  // 设置目标MAC
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);  // 设置以太类型为ARP

    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = htons(1);  // 硬件类型，1表示以太网
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);  // 协议类型，IPv4
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;  // 硬件地址长度
    arp->arp_plen = sizeof(uint32_t);  // 协议地址长度
    arp->arp_opcode = htons(RTE_ARP_OP_REPLY);  // 设置为ARP应答
    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);  // 源MAC地址
    rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);  // 目标MAC地址
    arp->arp_data.arp_sip = sip;  // 源IP地址
    arp->arp_data.arp_tip = dip;  // 目标IP地址

    // 输出ARP报文相关信息
    printf("ARP Packet:\n");
    printf("  Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
           eth->s_addr.addr_bytes[0], eth->s_addr.addr_bytes[1], eth->s_addr.addr_bytes[2],
           eth->s_addr.addr_bytes[3], eth->s_addr.addr_bytes[4], eth->s_addr.addr_bytes[5]);
    printf("  Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
           eth->d_addr.addr_bytes[0], eth->d_addr.addr_bytes[1], eth->d_addr.addr_bytes[2],
           eth->d_addr.addr_bytes[3], eth->d_addr.addr_bytes[4], eth->d_addr.addr_bytes[5]);
    printf("  Source IP: %s\n", inet_ntoa(*(struct in_addr *)&sip));
    printf("  Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&dip));
}

// 发送ARP包
static void send_arp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);  // 分配内存池中的mbuf
    if (mbuf == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to allocate mbuf for ARP\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);  // 获取数据指针
    encode_arp_pkt(pktdata, dst_mac, sip, dip);  // 构建ARP包

    rte_eth_tx_burst(gDpdkPortId, 0, &mbuf, 1);  // 发送ARP包
    rte_pktmbuf_free(mbuf);  // 释放mbuf
}

// 处理接收到的ARP请求并发送ARP应答
static void handle_arp(struct rte_mbuf *mbuf, struct rte_mempool *mbuf_pool) {
    struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    struct rte_arp_hdr *ahdr = (struct rte_arp_hdr *)(ehdr + 1);

    if (ahdr->arp_data.arp_tip == LOCAL_IP) {
        send_arp(mbuf_pool, ahdr->arp_data.arp_sha.addr_bytes, 
                    ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);  // 发送ARP应答
    }

    rte_pktmbuf_free(mbuf);  // 释放mbuf
}

// 处理接收到的ICMP回显请求并发送回显应答
static void handle_ipv4_icmp(struct rte_mbuf *mbuf, struct rte_mempool *mbuf_pool) {
    struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
    struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

    if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
        send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes, iphdr->dst_addr, iphdr->src_addr, 
                     icmphdr->icmp_ident, icmphdr->icmp_seq_nb);  // 发送ICMP应答
    }

    rte_pktmbuf_free(mbuf);  // 释放mbuf
}

int main(int argc, char *argv[]) {
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUM_MBUFS,
            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    init_port(mbuf_pool);  // 初始化DPDK端口

    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)src_mac);  // 获取本地MAC地址
    printf("DPDK initialized. Waiting for packets...\n");

    // 主循环，处理接收到的报文
    while (1) {
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);  // 从接收队列中接收报文
        if (num_recvd == 0) {
            continue;
        }

        // 处理接收到的每个报文
        for (unsigned i = 0; i < num_recvd; i++) {
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                handle_arp(mbufs[i], mbuf_pool);  // 处理ARP报文
            } else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
                if (iphdr->next_proto_id == IPPROTO_ICMP) {
                    handle_ipv4_icmp(mbufs[i], mbuf_pool);  // 处理ICMP报文
                }
            } else {
                rte_pktmbuf_free(mbufs[i]);  // 如果报文类型不是ARP或ICMP，释放mbuf
            }
        }
    }

    return 0;
}
