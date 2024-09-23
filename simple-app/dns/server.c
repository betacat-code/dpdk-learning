#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include <stdbool.h>
#include <inttypes.h>
#include <signal.h>

#include "dns.h"

static volatile bool force_quit;

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096

#define SCHED_RX_RING_SZ 8192
#define SCHED_TX_RING_SZ 8192

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64
#define PROCESS_SIZE 4

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

struct rte_mempool *mbuf_pool;

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool){

	// 默认端口配置
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;  // 接收队列描述符数量
	uint16_t nb_txd = TX_RING_SIZE;  // 发送队列描述符数量
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;
	rte_eth_dev_info_get(port, &dev_info);

	// 检查并设置快速释放缓冲区标志位
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* 配置以太网设备 */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	// 调整接收和发送队列的描述符数量
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	// 分配并设置每个以太网端口的接收队列
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	// 设置默认发送配置
	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	// 分配并设置每个以太网端口的发送队列
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	// 启动以太网端口
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	// 显示端口的MAC地址
	struct rte_ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	// 开启以太网设备的混杂模式接收
	rte_eth_promiscuous_enable(port);
	return 0;
}

static void build_packet(char *buf1, char *buf2, uint16_t pkt_size){

	struct rte_ether_hdr *eth_hdr1, *eth_hdr2;
	struct rte_ipv4_hdr *ip_hdr1, *ip_hdr2;
	struct rte_udp_hdr *udp_hdr1, *udp_hdr2;

	eth_hdr1 = (struct rte_ether_hdr*)buf1;
	ip_hdr1 = (struct rte_ipv4_hdr*)(buf1 + 14);
	udp_hdr1 = (struct rte_udp_hdr*)(buf1 + 14 + 20);
	eth_hdr2 = (struct rte_ether_hdr*)buf2;
	ip_hdr2 = (struct rte_ipv4_hdr*)(buf2 + 14);
	udp_hdr2 = (struct rte_udp_hdr*)(buf2 + 14 + 20);

	eth_hdr2->d_addr = eth_hdr1->s_addr;
	eth_hdr2->s_addr = eth_hdr1->d_addr;
	eth_hdr2->ether_type = eth_hdr1->ether_type;

	ip_hdr2->version_ihl = ip_hdr1->version_ihl;
	ip_hdr2->type_of_service = ip_hdr1->type_of_service;
	ip_hdr2->total_length = rte_cpu_to_be_16(28 + pkt_size);
	ip_hdr2->packet_id = ip_hdr1->packet_id ^ 0x0100;
	ip_hdr2->fragment_offset = ip_hdr1->fragment_offset | 0x0040;
	ip_hdr2->time_to_live = ip_hdr1->time_to_live;
	ip_hdr2->next_proto_id = ip_hdr1->next_proto_id;
	ip_hdr2->src_addr = ip_hdr1->dst_addr;
	ip_hdr2->dst_addr = ip_hdr1->src_addr;
	ip_hdr2->hdr_checksum = rte_ipv4_cksum(ip_hdr2);

	udp_hdr2->src_port = udp_hdr1->dst_port;
	udp_hdr2->dst_port = udp_hdr1->src_port;
	udp_hdr2->dgram_len = rte_cpu_to_be_16(8 + pkt_size);
	udp_hdr2->dgram_cksum = 0;
}

static void signal_handler(int signum){
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

struct lcore_params {
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring;
};


static int lcore_rx(struct rte_ring *rx_ring){
    uint16_t port;
	uint16_t nb_rx, nb_tx; 
    uint16_t total=0;
    struct rte_mbuf *bufs[BURST_SIZE];

    // 检查端口和轮询线程是否位于相同的NUMA节点
    if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) !=
					(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
				"polling thread.\n\tPerformance will "
				"not be optimal.\n", port);

	printf("\nCore %u doing packet RX.\n", rte_lcore_id());

    port=0;
    uint32_t rx_queue_drop_packets = 0;
    
    while(!force_quit){
        nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
        total+=nb_rx;
        nb_tx = rte_ring_enqueue_burst(rx_ring, (void *)bufs, nb_rx, NULL);
        if (unlikely(nb_tx < nb_rx)){
            rx_queue_drop_packets+=nb_rx-nb_tx; // 丢包
            while (nb_tx < nb_rx) {
				rte_pktmbuf_free(bufs[nb_tx++]);
			}
        }
    }
    printf("rx queue enqeue packet number: %d\n",total);
    printf("rx queue drop packet number: %d\n", rx_queue_drop_packets);
}

static int lcore_worker(struct lcore_params *p)
{
	uint16_t nb_rx, nb_tx;
	struct rte_mbuf *query_buf[PROCESS_SIZE], *reply_buf[PROCESS_SIZE]; 
	struct rte_ring *in_ring = p->rx_ring;  // 输入环形队列
	struct rte_ring *out_ring = p->tx_ring; // 输出环形队列
	uint8_t *buffer;  // 指向数据部分的指针
	struct Message msg;  // 用于存储 DNS 消息的结构体
	memset(&msg, 0, sizeof(struct Message));  // 初始化消息结构体为0

	printf("\nCore %u doing packet processing.\n", rte_lcore_id());

	uint16_t tx_queue_drop_packets = 0;  // 用于统计传输队列中丢包的数量
    uint16_t total_dns_packet=0;

	while (!force_quit) {  

		for(uint16_t i = 0; i < PROCESS_SIZE; i++){
			do{
				reply_buf[i] = rte_pktmbuf_alloc(mbuf_pool);  // 分配 mbuf 内存，如果失败则重试
			}while(reply_buf[i] == NULL);
		}
		// 从输入环形队列中取出批量查询包
		nb_rx = rte_ring_dequeue_burst(in_ring,(void *)query_buf, PROCESS_SIZE, NULL);

		// 如果没有接收到包，释放刚刚分配的回复包内存，继续下一次循环
		if (unlikely(nb_rx == 0)){
			for(uint16_t i = 0; i < PROCESS_SIZE; i++)
				rte_pktmbuf_free(reply_buf[i]);
			continue;
		}
		uint16_t nb_tx_prepare = 0;  // 用于统计准备好发送的回复包数量
		for(uint16_t i = 0; i < nb_rx; i++){
            free_questions(msg.questions);
            free_resource_records(msg.answers);
            free_resource_records(msg.authorities);
            free_resource_records(msg.additionals);
            memset(&msg, 0, sizeof(struct Message));
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(query_buf[i], struct rte_ether_hdr *);

			if(*rte_pktmbuf_mtod_offset(query_buf[i], uint16_t*, 36) != rte_cpu_to_be_16(9000)){
				continue;
			}
			buffer = rte_pktmbuf_mtod_offset(query_buf[i], uint8_t*, 42); 
			
			if (decode_msg(&msg, buffer, query_buf[i]->data_len - 42) != 0) {
				continue;
			}
			resolver_process(&msg);
			rte_pktmbuf_append(reply_buf[nb_tx_prepare], sizeof(struct rte_ether_hdr));
			rte_pktmbuf_append(reply_buf[nb_tx_prepare], sizeof(struct rte_ipv4_hdr));
			rte_pktmbuf_append(reply_buf[nb_tx_prepare], sizeof(struct rte_udp_hdr));
			
			uint8_t *p = buffer;
			if (encode_msg(&msg, &p) != 0) {
				continue;
			}
			uint32_t buflen = p - buffer;
			char * payload = (char*)rte_pktmbuf_append(reply_buf[nb_tx_prepare], buflen);
			rte_memcpy(payload, buffer, buflen); 

			build_packet(rte_pktmbuf_mtod_offset(query_buf[i], char*, 0), rte_pktmbuf_mtod_offset(reply_buf[nb_tx_prepare], char*, 0), buflen);
			nb_tx_prepare++;
		}

		nb_tx = rte_ring_enqueue_burst(out_ring, (void *)reply_buf, nb_tx_prepare, NULL);
        total_dns_packet+=nb_tx;

		for(uint16_t i = 0; i < nb_rx; i++)
			rte_pktmbuf_free(query_buf[i]);
		for(uint16_t i = nb_tx; i < nb_tx_prepare; i++){
			tx_queue_drop_packets += 1;  // 统计未成功发送的回复包数量
			rte_pktmbuf_free(reply_buf[i]);  // 释放未成功发送的回复包
		}
	}

	printf("core %d: tx queue drop packet number: %d\n", rte_lcore_id(), tx_queue_drop_packets);
    printf("total sent dns packet is %d\n",total_dns_packet);
	return 0;
}


static int
lcore_tx(struct rte_ring *tx_ring)
{
	uint16_t port = 0;
	uint16_t nb_rx, nb_tx;
	struct rte_mbuf *bufs[BURST_SIZE];

	printf("\nCore %u doing packet TX.\n", rte_lcore_id());

	uint16_t dpdk_send_ring_drop_packets = 0;
	uint16_t total_sent = 0;
	while (!force_quit) {
		nb_rx = rte_ring_dequeue_burst(tx_ring, (void *)bufs, BURST_SIZE, NULL);
		nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);
		total_sent += nb_tx;

		if(unlikely(nb_tx < nb_rx)){
			dpdk_send_ring_drop_packets += nb_rx - nb_tx;
			while(nb_tx < nb_rx){
				rte_pktmbuf_free(bufs[nb_tx++]);
			}
		}
	}

	printf("dpdk send ring drop packet numbers: %d, total sent number: %d\n", dpdk_send_ring_drop_packets, total_sent);

	return 0;
}

int
main(int argc, char *argv[])
{
	uint8_t ip[4] = {192, 168, 1, 1};
	add_A_record("foo.bar.com",ip);
	unsigned lcore_id;
	uint16_t portid = 0, nb_ports = 1;

	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

	struct rte_ring *rx_ring = rte_ring_create("Input_ring", SCHED_RX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (rx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

    struct rte_ring *tx_ring = rte_ring_create("Output_ring", SCHED_TX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (tx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

    // 0号lcore运行rx线程
	struct lcore_params p;
	p.rx_ring = rx_ring;
	p.tx_ring = tx_ring;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if(lcore_id == 1)
			rte_eal_remote_launch((lcore_function_t*)lcore_tx, (void*)tx_ring, lcore_id);
		else
			rte_eal_remote_launch((lcore_function_t*)lcore_worker, (void*)&p, lcore_id);
	}
	lcore_rx(rx_ring);
	rte_eal_mp_wait_lcore();
	return 0;
}