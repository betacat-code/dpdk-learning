// 标准C库头文件
#include <stdio.h>         // 标准输入输出库
#include <stdlib.h>        // 标准库，包含内存分配、进程控制等
#include <stdint.h>        // 定义固定大小的整数类型
#include <inttypes.h>      // 提供用于格式化固定大小整数类型的宏
#include <string.h>        // 字符串处理函数库
#include <stdarg.h>        // 用于处理变长参数的宏
#include <errno.h>         // 错误号处理
#include <stdbool.h>       // 布尔类型定义
#include <time.h>          // 时间处理函数
#include <sys/types.h>     // 定义数据类型，如`size_t`，`ssize_t`
#include <linux/if_ether.h> // 以太网常量

// Linux系统库头文件
#include <sys/queue.h>     // 定义队列和链表的宏和类型
#include <getopt.h>        // 命令行选项解析
#include <signal.h>        // 信号处理库
#include <sys/time.h>      // 获取时间的库函数（用于高精度时间）

// DPDK 核心库头文件
#include <rte_common.h>        // DPDK中的通用定义
#include <rte_log.h>           // DPDK日志系统
#include <rte_memory.h>        // DPDK内存管理相关函数
#include <rte_memcpy.h>        // 高效的内存拷贝函数
#include <rte_memzone.h>       // DPDK内存区域管理
#include <rte_malloc.h>        // DPDK内存分配函数
#include <rte_ring.h>          // DPDK环形缓冲区
#include <rte_mempool.h>       // DPDK内存池管理
#include <rte_mbuf.h>          // DPDK数据包缓冲区结构和操作

// DPDK 环境初始化库头文件
#include <rte_eal.h>           // DPDK环境抽象层（EAL）初始化
#include <rte_per_lcore.h>     // DPDK每核特定变量
#include <rte_launch.h>        // 启动函数
#include <rte_atomic.h>        // 原子操作
#include <rte_spinlock.h>      // 自旋锁
#include <rte_cycles.h>        // CPU周期数函数
#include <rte_prefetch.h>      // 缓存预取函数
#include <rte_lcore.h>         // 核心绑定函数
#include <rte_branch_prediction.h> // 分支预测优化
#include <rte_interrupts.h>    // 中断处理
#include <rte_pci.h>           // PCI设备管理
#include <rte_random.h>        // 随机数生成
#include <rte_debug.h>         // 调试相关功能

// DPDK 网络相关头文件
#include <rte_ether.h>         // 以太网帧的定义和处理
#include <rte_ethdev.h>        // DPDK中的以太网设备驱动

// DPDK IP、TCP、UDP协议栈相关头文件
#include <rte_ip.h>            // IP协议处理
#include <rte_tcp.h>           // TCP协议处理
#include <rte_udp.h>           // UDP协议处理

// DPDK 字符串操作头文件
#include <rte_string_fns.h>    // 字符串处理函数库



// IP地址  UDP端口
#define IP_SRC_ADDR ((192U << 24) | (168 << 16) | (131 << 8) | 152)
#define IP_DST_ADDR ((192U << 24) | (168 << 16) | (131 << 8) | 130)
#define UDP_SRC_PORT 1024
#define UDP_DST_PORT 1024

#define MAX_PKT_BURST 32
#define RX_RING_SIZE 128  //发送环形缓冲区
#define NUM_MBUFS 8191  //数据包缓冲池
#define MBUF_CACHE_SIZE 256  //内存池中每个缓存的大小(以数据包为单位)
#define BURST_SIZE 32  //批量处理的大小
#define SEND_TOTAL 1 //发送


#define IP_DEFTTL 64 
#define IP_VERSION 0x40 
#define IP_HDRLEN 0x05 //默认头部为20字节

static volatile bool force_quit;//程序强制退出标识符
struct rte_mempool *pktmbuf_pool;
struct rte_mbuf *mbuf_list[MAX_PKT_BURST];//对应的rte_mbuf结构指针数组。32


static struct rte_ipv4_hdr  pkt_ip_hdr;
static struct rte_udp_hdr pkt_udp_hdr;
struct rte_ether_addr des_eth_addrs;//目的mac
struct rte_ether_addr src_eth_addrs;//源mac
struct rte_ether_addr eth_addrs;

unsigned socket_id;
unsigned port_id;
unsigned lcore_id;
unsigned rx_queue_id;
unsigned tx_queue_id;

uint32_t send_total = 0;

rte_spinlock_t spinlock_conf = RTE_SPINLOCK_INITIALIZER; //自旋锁，来保证对一个网口竞争访问；

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { 
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        /*.offloads = DEV_RX_OFFLOAD_VLAN_STRIP|
                    DEV_RX_OFFLOAD_VLAN_FILTER|
                    DEV_RX_OFFLOAD_MACSEC_STRIP,
        // 启用硬件 VLAN 过滤功能 启用硬件 VLAN 标签剥离功能 启用硬件 CRC 去除功能
        */
    },
    /*.rx_adv_conf={
        .rss_conf={
            .rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
        },
    },
    */
    .txmode={
        .mq_mode = ETH_MQ_TX_NONE, // 不使用多队列模式
    }
};

char buf[64]="Partial string initialization";

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static void print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
    char buf[48];
	rte_ether_format_addr(buf, 48, eth_addr);
	printf("%s%s \n", name, buf);
}

// 设置并初始化 IPv4 和 UDP 的头部信息
static void setup_pkt_udp_ip_headers(struct rte_ipv4_hdr *ip_hdr,
    struct rte_udp_hdr *udp_hdr,uint16_t pkt_data_len)
{
    uint16_t pkt_len;

    // 初始化UDP头部
    pkt_len = (uint16_t)(pkt_data_len + sizeof(struct rte_udp_hdr));
    udp_hdr->src_port = rte_cpu_to_be_16(UDP_SRC_PORT);
    udp_hdr->dst_port = rte_cpu_to_be_16(UDP_DST_PORT);
    udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_len);
    udp_hdr->dgram_cksum = 0;  // 不使用UDP校验

    // 初始化IP头部
    pkt_len = (uint16_t) (pkt_len + sizeof(struct rte_ipv4_hdr));
	ip_hdr->version_ihl   =IP_VERSION|IP_HDRLEN;
	ip_hdr->type_of_service   = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live   = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length   = rte_cpu_to_be_16(pkt_len);
	ip_hdr->src_addr = rte_cpu_to_be_32(IP_SRC_ADDR); // 换为网络字节序
	ip_hdr->dst_addr = rte_cpu_to_be_32(IP_DST_ADDR);

    // IP 首部校验和
    ip_hdr->hdr_checksum = 0; 
    uint32_t ip_cksum = 0;

    // 将 IP 头部作为 16 位无符号整数数组处理
    uint16_t *ptr16 = (uint16_t *)ip_hdr;
        for (int i = 0; i < sizeof(struct rte_ipv4_hdr) / 2; i++) {
        if (i != 5) { // 校验和字段需要跳过
            ip_cksum += ptr16[i];
        }
    }
    // 循环进位，将结果压缩为 16 位并处理溢出。
    while (ip_cksum >> 16) {
        ip_cksum = (ip_cksum & 0xFFFF) + (ip_cksum >> 16);
    }
    ip_hdr->hdr_checksum = (uint16_t)(~ip_cksum & 0xFFFF);
}

//  将一个内存缓冲区的内容（buf）拷贝到一个 DPDK 的数据包缓冲区中的多个片段中
static void copy_buf_to_pkt_segs(void *buf, unsigned len, 
    struct rte_mbuf *pkt, unsigned offset)
{
    struct rte_mbuf *seg = pkt;
    unsigned copy_len;
    void *seg_buf;

    // 定位到正确的片段
    while (offset >= seg->data_len) {
        offset -= seg->data_len;
        seg = seg->next;
    }

    // 从当前片段开始拷贝数据
    while (len > 0) {
        // 计算当前片段中需要拷贝的数据长度
        copy_len = seg->data_len - offset;
        if (len < copy_len) {
            copy_len = len;
        }

        seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
        rte_memcpy(seg_buf, buf, copy_len);

        len -= copy_len;
        buf = (char *)buf + copy_len;
        offset = 0;

        if (len > 0) {
            seg = seg->next;
            if (seg == NULL) {
                break; // 防止访问空片段
            }
        }
    }
}


static inline void copy_buf_to_pkt(void* buf, unsigned len, 
    struct rte_mbuf *pkt, unsigned offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset),buf, (size_t) len);
		return;
	}
    // 处理跨多个片段的拷贝操作
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

// 创建一组数据包缓冲区
static void create_pkt_mbuf_array(){

    struct rte_mbuf *pkt;
    struct rte_ether_hdr eth_hdr;
    unsigned pkt_data_len = sizeof(struct rte_ether_hdr) + 
        sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(buf);
    for (uint16_t i = 0; i <MAX_PKT_BURST ; i++)
    {
        // 分配一个buf
        pkt = rte_mbuf_raw_alloc(pktmbuf_pool);
        if (pkt == NULL) {
            printf("error: no enough pool!\n");
            continue; // 处理分配失败情况，继续下一个循环
        }
        // 重置pkt头部空间
        rte_pktmbuf_reset_headroom(pkt);
        pkt->data_len = pkt_data_len;
        pkt->next = NULL;
        // 设置以太网头部
        rte_ether_addr_copy(&des_eth_addrs, &eth_hdr.d_addr);
        rte_ether_addr_copy(&src_eth_addrs, &eth_hdr.s_addr);
        eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        // copy 这里优化可以使用dpdk的函数
        copy_buf_to_pkt(&eth_hdr, sizeof(eth_hdr), pkt, 0); // Eth
        copy_buf_to_pkt(&pkt_ip_hdr, sizeof(pkt_ip_hdr), pkt, sizeof(struct rte_ether_hdr)); // IP header
        copy_buf_to_pkt(&pkt_udp_hdr, sizeof(pkt_udp_hdr), pkt, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)); // UDP header
        copy_buf_to_pkt(&buf, sizeof(buf), pkt, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr)); // Data
        
        /* dpdk优化版
        struct rte_ether_hdr* eth_hdr;
        struct rte_ipv4_hdr *ip_hdr;
        struct rte_udp_hdr *udp_hdr;
        ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        *ip_hdr = pkt_ip_hdr;
        ip_hdr->total_length = rte_cpu_to_be_16(pkt_data_len - sizeof(struct rte_ether_hdr));

        udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
        *udp_hdr = pkt_udp_hdr;
        udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_data_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));

        void *pkt_data = (void *)(udp_hdr + 1);
        rte_memcpy(pkt_data, buf, sizeof(buf));
        */
       // 设置 rte_mbuf 参数：
       pkt->nb_segs = 1; 
       pkt->pkt_len = pkt->data_len;
       pkt->ol_flags = 0;
       pkt->vlan_tci = 0;
       pkt->vlan_tci_outer = 0;
       pkt->l2_len = sizeof(struct rte_ether_hdr);
       pkt->l3_len = sizeof(struct rte_ipv4_hdr);
       pkt->l4_len = sizeof(struct rte_udp_hdr);
       mbuf_list[i] = pkt;      
    }
}

// 在一个网口发送数据包 
static inline int
send_burst(uint8_t portid, uint8_t queueid)
{
    uint16_t send;
    
    // 上锁，防止多线程同时访问发送队列
    rte_spinlock_lock(&spinlock_conf);

    // 发送数据包，send 是实际发送的数据包数量
    
        send = rte_eth_tx_burst(portid, queueid, mbuf_list, MAX_PKT_BURST);
    printf("-------- Data sent: %d packets\n", send);

    // 解锁
    rte_spinlock_unlock(&spinlock_conf);

    // 如果未能全部发送，释放未发送的数据包
    if (unlikely(send < MAX_PKT_BURST)) {
        for (uint16_t i = send; i < MAX_PKT_BURST; i++) {
            rte_pktmbuf_free(mbuf_list[i]);
        }
    }
    // 统计已发送数据包总数
    send_total += send;
    return send;
}

static int app_lcore_main_loop(__attribute__((unused)) void *arg)
{
    unsigned lcoreid;
    uint32_t count = 0; // 记录发送的包数
    uint32_t num = 0;   // 记录发送的包总数
    uint16_t ret;       // 记录每次发送成功的包数
    uint16_t pkt_data_len = sizeof(buf);  // 数据包的总长度
    struct rte_eth_stats port_stats;      // 记录端口统计数据
    struct timeval tv;                    // 用于计算时间

    lcoreid = rte_lcore_id(); // 获取当前核心 ID

    if (lcoreid == lcore_id) 
    {
        printf("------- Sending from core %u\n", lcore_id);

        // 重置端口统计数据
        rte_eth_stats_reset(port_id);

        // 打印初始的统计数据
        if (rte_eth_stats_get(port_id, &port_stats) == 0) 
        {
            printf("Initial stats:\n");
            printf("Received packets: %ld    Sent packets: %ld\n", port_stats.ipackets, port_stats.opackets);
            printf("Received bytes: %ld      Sent bytes: %ld\n", port_stats.ibytes, port_stats.obytes);
            printf("Receive errors: %ld      Send errors: %ld\n", port_stats.ierrors, port_stats.oerrors);
            printf("Missed packets: %ld     RX no buffer: %ld\n", port_stats.imissed, port_stats.rx_nombuf);
        }

        // 开始计时
        gettimeofday(&tv, NULL);
        int starttime = tv.tv_sec * 1000000 + tv.tv_usec; // 转换为微秒

        // 设置数据包的 IP 和 UDP 头部
        setup_pkt_udp_ip_headers(&pkt_ip_hdr, &pkt_udp_hdr, pkt_data_len);

        printf("setup_pkt_udp_ip_headers\n");
        while (num < SEND_TOTAL) 
        {
            if (force_quit) // 检查是否需要退出
                break;

            // 准备数据包并发送
            create_pkt_mbuf_array(); // 组装数据包
            ret = send_burst(port_id, tx_queue_id); // 发送数据包
            rte_eth_tx_done_cleanup(port_id, tx_queue_id, 0); // 清理已发送的包
            count += ret; // 累加成功发送的包数
            num++;        // 累加总发送包数
        }

        // 结束计时
        gettimeofday(&tv, NULL);
        int endtime = tv.tv_sec * 1000000 + tv.tv_usec; // 转换为微秒
        int time = endtime - starttime; // 计算总耗时

        // 打印发送后的统计数据
        if (rte_eth_stats_get(port_id, &port_stats) == 0) 
        {
            printf("Final stats:\n");
            printf("Received packets: %ld    Sent packets: %ld\n", port_stats.ipackets, port_stats.opackets);
            printf("Received bytes: %ld      Sent bytes: %ld\n", port_stats.ibytes, port_stats.obytes);
            printf("Receive errors: %ld      Send errors: %ld\n", port_stats.ierrors, port_stats.oerrors);
            printf("Missed packets: %ld     RX no buffer: %ld\n", port_stats.imissed, port_stats.rx_nombuf);
        }

        // 打印发送的总包数和耗时
        printf("------- Total sent: %d  Count: %d  Time: %d microseconds\n", send_total, count, time);    
    }

    return 0;
}


int
main(int argc, char **argv)
{

	int ret;
	uint32_t nb_lcores;
	uint32_t nb_ports;
	unsigned lcoreid;

	uint8_t  nb_rx_queue, nb_tx_queue;
	uint16_t nb_rx_desc, nb_tx_desc;
	
	struct rte_eth_dev_info default_eth_dev_info_before;
	struct rte_eth_dev_info default_eth_dev_info_after;
	struct rte_eth_rxconf default_rxconf;
	struct rte_eth_txconf default_txconf;
	struct rte_eth_desc_lim 	rx_desc_lim;
	struct rte_eth_desc_lim 	tx_desc_lim;
	
	nb_rx_queue = 1;    //端口接收队列数量
	nb_tx_queue = 1;    //端口传输队列数量
	nb_rx_desc = 128;   //端口接收队列描述符数量
	nb_tx_desc = 512;   //端口传输队列描述符数量
	rx_queue_id = 0;    //仅使用接收队列 0 
	tx_queue_id = 0;    //仅使用传输队列 0 
	port_id = 0;		//仅使用端口 0 
	lcore_id = 1;       //仅使用的逻辑核 1
	force_quit = false;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	
	//端口数量
	nb_ports = rte_eth_dev_count_total();
	if (nb_ports > RTE_MAX_ETHPORTS)
		nb_ports = RTE_MAX_ETHPORTS;
	//逻辑核数量
	nb_lcores = rte_lcore_count();
	printf("number of lcores: %d    number of ports: %d\n", nb_lcores, nb_ports);
	//主逻辑核 CPU 插槽编号
	socket_id = rte_lcore_to_socket_id(rte_get_master_lcore());
	
	//创建内存池
	char s[64];//内存池名称
	snprintf(s, sizeof(s), "mbuf_pool_%d", socket_id);
	pktmbuf_pool = rte_pktmbuf_pool_create(s,NUM_MBUFS, MBUF_CACHE_SIZE, 0,RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n", socket_id);
	else
		printf("Allocated mbuf pool on socket %d\n", socket_id);
	
	//获取端口mac 地址
	rte_eth_macaddr_get(port_id, &src_eth_addrs);
	print_ethaddr("SRC1  Mac Address:", &src_eth_addrs);
	
	rte_eth_macaddr_get(port_id + 1, &eth_addrs);
	print_ethaddr("SRC2  Mac Address:", &eth_addrs);
	
	//目的mac 地址
	void *tmp;
	tmp = &des_eth_addrs.addr_bytes[0];
	//*((uint64_t *)tmp) = (((uint64_t)0x59 << 40) | ((uint64_t)0x41 << 32) | ((uint64_t)0x02 << 24) | ((uint64_t)0x4A << 16) | ((uint64_t)0x53 << 8) | (uint64_t)0x2C);
	//*((uint64_t *)tmp) = (((uint64_t)0x30 << 40) | ((uint64_t)0x05 << 32) | ((uint64_t)0x05 << 24) | ((uint64_t)0x0A << 16) | ((uint64_t)0x11 << 8) | (uint64_t)0x00);
     *((uint64_t *)tmp) = (((uint64_t)0xFF << 40) | ((uint64_t)0xFF << 32) | ((uint64_t)0xFF << 24) | ((uint64_t)0xFF << 16) | ((uint64_t)0xFF << 8) | (uint64_t)0xFF);
	print_ethaddr("DES  Mac Address:", &des_eth_addrs);
	
	//端口配置
	ret = rte_eth_dev_configure(port_id, nb_rx_queue, nb_tx_queue, &port_conf_default);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",ret, port_id);
	//检查Rx和Tx描述符的数量是否满足来自以太网设备信息的描述符限制，否则将其调整为边界 nb_rx_desc =128,nb_tx_desc=128
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rx_desc,&nb_tx_desc);
	
	//获取端口默认配置信息
	rte_eth_dev_info_get(port_id, &default_eth_dev_info_before);
	
	
	//端口 TX 队列配置
	fflush(stdout);
	
	default_txconf = default_eth_dev_info_before.default_txconf;
	tx_desc_lim = default_eth_dev_info_before.tx_desc_lim;
	printf("config before ---- tx_free_thresh : %d ,desc_max ：%d ,desc_min : %d \n",default_txconf.tx_free_thresh, tx_desc_lim.nb_max, tx_desc_lim.nb_min);
	
	default_txconf.tx_free_thresh = (uint16_t) MAX_PKT_BURST;
	ret = rte_eth_tx_queue_setup(port_id, tx_queue_id, nb_tx_desc, socket_id, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, port_id);
		
	
	//端口 RX 队列配置
	fflush(stdout);
	
	default_rxconf = default_eth_dev_info_before.default_rxconf;
	rx_desc_lim = default_eth_dev_info_before.rx_desc_lim;
	printf("config before ---- rx_free_thresh : %d ,desc_max ：%d ,desc_min : %d \n",default_rxconf.rx_free_thresh, rx_desc_lim.nb_max, rx_desc_lim.nb_min);
	
	default_rxconf.rx_free_thresh = (uint16_t) MAX_PKT_BURST;
	ret = rte_eth_rx_queue_setup(port_id, rx_queue_id, nb_rx_desc, socket_id, NULL, pktmbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d,port=%d\n", ret, port_id);
	
	rte_delay_ms(5000);//延迟5秒
	memset(&default_txconf, 0, sizeof(default_txconf));
	memset(&default_rxconf, 0, sizeof(default_rxconf));
	
	memset(&tx_desc_lim, 0, sizeof(tx_desc_lim));
	memset(&rx_desc_lim, 0, sizeof(rx_desc_lim));
	
	//获取端口默认配置信息
	rte_eth_dev_info_get(port_id, &default_eth_dev_info_after);
	
	default_txconf = default_eth_dev_info_after.default_txconf;
	tx_desc_lim = default_eth_dev_info_after.tx_desc_lim;
	printf("config after  ---- tx_free_thresh : %d ,desc_max ：%d ,desc_min : %d \n",default_txconf.tx_free_thresh, tx_desc_lim.nb_max, tx_desc_lim.nb_min);
	default_rxconf = default_eth_dev_info_after.default_rxconf;
	rx_desc_lim = default_eth_dev_info_after.rx_desc_lim;
	printf("config after  ---- rx_free_thresh : %d ,desc_max ：%d ,desc_min : %d \n",default_rxconf.rx_free_thresh, rx_desc_lim.nb_max, rx_desc_lim.nb_min);
	
	
	
	/*开启端口网卡 */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n",ret, port_id);

	printf("started: Port %d\n", port_id);
	
	/* 设置端口网卡混杂模式 */
    rte_eth_promiscuous_enable(port_id);
	
	/*等待网卡启动成功*/
	#define CHECK_INTERVAL 100 /* 100ms */	
	#define MAX_CHECK_TIME 50 /* 5s (50 * 100ms) in total */
	uint8_t count;
	struct rte_eth_link link;
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return 0;
		memset(&link, 0, sizeof(link));
		rte_eth_link_get_nowait(port_id, &link);
		if (link.link_status)
			printf("Port %d Link Up - speed %u Mbps - %s\n", (uint8_t)port_id,(unsigned)link.link_speed,
					(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
						("full-duplex") : ("half-duplex\n"));
		else
			printf("Port %d Link Down\n",(uint8_t)port_id);
		rte_delay_ms(CHECK_INTERVAL);
	}
	printf("调用逻辑核执行任务\n");
	/*调用逻辑核执行任务*/
	rte_eal_mp_remote_launch(app_lcore_main_loop, NULL, CALL_MASTER);
	
	/*等待逻辑核退出*/
	RTE_LCORE_FOREACH_SLAVE(lcoreid) {
		if (rte_eal_wait_lcore(lcoreid) < 0) {
			return -1;
		}
	}
	printf("Bye...\n");
	printf("Closing port %d...\n", port_id);
	
	/*停止端口网卡*/
	rte_eth_dev_stop(port_id);
	/*关闭端口网卡*/
	rte_eth_dev_close(port_id);
	return 0;
}