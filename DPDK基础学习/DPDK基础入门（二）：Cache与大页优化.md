
# Cache简介

目前Cache主要由三级组成: L1 Cache, L2 Cache和Last Level Cache(LLC)。 L1最快，但容量小，可能只有几十KB。LLC慢，但容量大，可能多达几十MB。

L1和L2 Cache一般集成在CPU内部。另外,，L1和L2 Cache是每个处理器核心独有的 ，而LLC是被所有核心所共享的。

Intel处理器对各级Cache的访问时间一直都保持稳定, 见下表所示


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/008403ab6d2a43828da9c5bc427bb5dd.png)

除以上Cache外，现代CPU中还有一个TLB (Translation Look-aside Buffer) Cache，专门用于缓存内存中的页表项。TLB Cache使用虚拟地址进行搜索，直接返回对应的物理地址，相对于内存中的多级页表需要多次访问才能得到最终物理地址。


## Cache地址映射与变换

内存容量很大， 一般是GB级，而Cache最大才几十MB。 要把内存数据放到Cache中，需要一个分块机制和映射算法。

Cache和内存以块为单位进行数据交换，块的大小通常以在内存的一个存储周期内能够访问到的数据长度为限，当前主流块的大小为64字节，这也就是Cache line的含义。

而映射算法分为全关联型，直接关联型和组关联型3种。

- 在全关联型映射中，数据块可以存储在缓存的任何位置，而不受特定的限制。
- 直接关联型映射将每个主存块映射到缓存中唯一确定的位置。
- 组关联型映射结合了全关联型和直接关联型映射的优点。缓存被分为多个组（sets），每个组中有多个行（ways）。主存块可以映射到某一组中的任何行，但仅限于这一组内的行。

目前广泛使用组关联型Cache。

## Cache的写策略

内存的数据被加载到Cache后，在某个时刻要被写回内存，写回策略有以下几种：

- **直写(write-through)** ：处理器写入Cache的同时, 将数据写入内存中
-  **回写(write-back)**：为cache line设置dirty标志，当处理器改写了某个cache line后，不立即将其写回内存，而是将dirty标志置1。当处理器再次修改该cache line并且写回cache中， 查表发现dirty=1，则先将cache line内容写回内存，再将新数据写到cache。
- **WC(write-combining)**： 当cache line的数据被批量修改后，一次性将其写到内存。
- **UC(uncacheable)** ：针对内存不能被缓存到cache的场景，比如硬件需要立即收到指令。


# Cache预取

## 预取原理

cache之所以能够提高系统性能，主要原因是程序运行存在局部性现象，包括时间局部性和空间局部性。这两种情况下处理器会把之后要用到的指令/数据读取到cache中，提高程序性能。而所谓的cache预取，就是预测哪些指令/数据将会被用到，然后采用合理方法将其预先取入到cache中。


一些处理器提供的软件预取指令(只对数据有效)：
- PREFETCH0 将数据存放在所有cache
- PREFETCH1 将数据存放在L1 Cache之外的cache
- PREFETCH2 将数据存放在L1，L2 Cache之外的cache
- PREFETCHNTA 与PREFETCH0类似，但数据是以非临时数据存储，在使用完一次后，cache认为该数据是可以被淘汰出去的。

这些指令都是汇编指令, 一些程序库会提供对应的C语言版本, 如mmintrin.h中的_mm_prefetch()函数:

```c
// p: 要预取的内存地址
// i: 预取指令类型, 与汇编指令对应关系如下
//    _MM_HINT_T0:  PREFETCH0
//    _MM_HINT_T1:  PREFETCH1
//    _MM_HINT_T2:  PREFETCH2
//    _MM_HINT_NTA: PREFETCHNTA
void _mm_prefetch(char* p, int i);
```

- p 是要预取的内存地址。
- i 是预取指令类型，可以是 _MM_HINT_T0、_MM_HINT_T1、_MM_HINT_T2 或 _MM_HINT_NTA 中的一个。

## dpdk中的预取

dpdk转发一个报文所需要的基本过程分解:

- 写接收描述符到内存，填充数据缓冲区指针，网卡收到报文后就会根据这个地址把报文内容填充进去。
- 从内存中读取接收描述符(当收到报文时, 网卡会更新该结构)(内存读)，从而确认是否收到报文。
- 从接收描述符确认收到报文时，从内存中读取控制结构体的指针(内存读)， 再从内存中读取控制结构体(内存读)，把从接收描述符读取的信息填充到该控制结构体。
- 更新接收队列寄存器，表示软件接收到了新的报文。
- 内存中读取报文头部(内存读)，决定转发端口。
    从控制结构体把报文信息填入到发送队列发送描述符，更新发送队列寄存器.
- 从内存中读取发送描述符(内存读)，检查是否有包被硬件传送出去。
- 如果有的话，从内存中读取相应控制结构体(内存读)，释放数据缓冲区。


 处理一个报文的过程，需要6次读取内存(见上“内存读”)。而之前我们讨论过处理器从一级Cache读取数据需要3~5个时钟周期， 二级是十几个时钟周期，三级是几十个时钟周期，而内存则需要几百个时钟周期。从性能数据来说, 每80个时钟周期就要处理一个报文。

因此，dpdk必须保证所有需要读取的数据都在Cache中，否则一旦出现Cache不命中，性能将会严重下降。为了保证这点， dpdk采用了多种技术来进行优化, 预取只是其中的一种。

```c
/*
 * Prefetch a cache line into all cache levels.
 */
#define rte_ixgbe_prefetch(p)   rte_prefetch0(p)
```

实际例子：

```c
while (nb_rx < nb_pkts) {
    rxdp = &rx_ring[rx_id]; // 读取接收描述符
    staterr = rxdp->wb.upper.status_error;
    // 检查是否有报文收到
    if (!(staterr & rte_cpu_to_le_32(IXGBE_RXDADV_STAT_DD)))
        break;
    rxd = *rxdp;
    // 分配数据缓冲区
    nmb = rte_rxmbuf_alloc(rxq->mb_pool); nb_hold++;
    // 读取控制结构体
    rxe = &sw_ring[rx_id];
    ......
    rx_id++;
    if (rx_id == rxq->nb_rx_desc)
        rx_id = 0;
    // 预取下一个控制结构体mbuf
    rte_ixgbe_prefetch(sw_ring[rx_id].mbuf);
    // 预取接收描述符和控制结构体指针
    if ((rx_id & 0x3) == 0) {
        rte_ixgbe_prefetch(&rx_ring[rx_id]);
        rte_ixgbe_prefetch(&sw_ring[rx_id]);
    }
    ......
    // 预取报文
    rte_packet_prefetch((char *)rxm->buf_addr + rxm->data_off);
    // 把接收描述符读取的信息存储在控制结构体mbuf中
    rxm->nb_segs = 1;
    rxm->next = NULL;
    rxm->pkt_len = pkt_len;
    rxm->data_len = pkt_len;
    rxm->port = rxq->port_id;
    ......
    rx_pkts[nb_rx++] = rxm;
}
```

# Cache一致性

cache一致性问题的根源，是因为存在多个处理器核心各自独占的cache(L1,L2)，当多个核心访问内存中同一个cache行的内容时， 就会因为多个cache同时缓存了该内容引起同步的问题。

dpdk使用Cache Line对齐，同时避免多个核心访问同一个内存地址或者数据结构来解决cache一致性问题。


## dpdk实现Cache Line对齐


实现很简单，定义该数据结构或者数据缓冲区时就申明对齐，DPDK对很多结构体定义的时候就是如此操作的，以下是宏定义。

**rte_common.c**

```c
/** Minimum Cache line size. */
#define RTE_CACHE_LINE_MIN_SIZE 64

/** Force alignment to cache line. */
#define __rte_cache_aligned __rte_aligned(RTE_CACHE_LINE_SIZE)

/** Force minimum cache line alignment. */
#define __rte_cache_min_aligned __rte_aligned(RTE_CACHE_LINE_MIN_SIZE)
```

```cpp
struct __rte_cache_aligned lcore_params {
	uint16_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
};
```

以上定义了一个简单的结构体 lcore_params，用于存储和管理逻辑核心相关的参数信息，包括端口 ID、队列 ID 和逻辑核心 ID。通过 __rte_cache_aligned 这个宏，确保了结构体在内存中按缓存行对齐。

## MESI协议

解决Cache一致性问题的机制有著名的MESI协议。

MESI协议是Cache line四种状态的首字母的缩写，分别是修改（Modified）态、独占（Exclusive）态、共享（Shared）态和失效（Invalid）态。Cache中缓存的每个Cache Line都必须是这四种状态中的一种。


**Modified（修改）态**：当某个处理器或核心修改了一个缓存行中的数据时，该缓存行处于修改态。
- 数据在此缓存中被修改过，并且未写回主存。
- 此状态下的缓存行数据是最新的，并且与主存中的数据不一致（即缓存数据是脏的）。
- 其他处理器或核心若要读取该缓存行，需要先将其写回到主存或者转换为共享态或失效态。

**Exclusive（独占）态** ：当某个处理器或核心拥有一个缓存行的唯一访问权限，且此缓存行与主存中的数据一致时，该缓存行处于独占态。
- 缓存行中的数据与主存中的数据一致，且没有其他处理器或核心缓存了相同的数据。
- 其他处理器或核心可以读取该缓存行，但必须先将其设置为共享态或者失效态，再读取或修改。

**Shared（共享）态**： 当多个处理器或核心缓存了同一个缓存行，并且数据与主存中的一致时，该缓存行处于共享态。
- 多个处理器或核心可以同时缓存并访问该缓存行的数据。
- 数据与主存中的数据一致，因此无需写回操作。

**Invalid（失效）态**： 当某个处理器或核心的缓存行无效或者失效时，处于失效态。
- 处理器或核心的缓存行与主存中的数据不一致，或者缓存行中的数据已经过时。
- 若有其他处理器或核心修改了相同的缓存行，可能会导致当前缓存行失效。
- 在失效态的缓存行上的任何访问操作都将导致从主存重新获取最新数据。


## dpdk实现缓存一致性

dpdk解决方法很简单，首先就是避免多个核访问同一个内存地址或者数据结构。这样，每个核尽量都避免与其他核共享数据，从而减少因为错误的数据共享（cache line false sharing）导致的Cache一致性的开销。

```cpp
struct __rte_cache_aligned lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[ETHDEV_RX_QUEUE_PER_LCORE_MAX];
	struct rte_graph *graph;
	char name[RTE_GRAPH_NAMESIZE];
	rte_graph_t graph_id;
};
struct lcore_conf lcore_conf[RTE_MAX_LCORE];
```


# TLB和大页

TLB和Cache本质上是一样的，都是一个缓存。TLB用于存储最近访问的虚拟地址到物理地址的映射。它存在于CPU中，目的是加速虚拟内存到物理内存的转换过程。

当程序访问内存时，CPU需要将虚拟地址转换为物理地址。TLB 通过缓存这些转换结果来减少每次地址转换所需的时间。

## TLB工作原理

每当CPU执行内存访问操作时，它会首先查询TLB，以确定虚拟地址是否已经在缓存中。

如果地址在TLB中找到（称为“TLB命中”），CPU直接使用缓存中的物理地址，从而加速访问。

如果地址不在TLB中（称为“TLB未命中”），CPU需要查找页表（Page Table），然后将转换结果加载到TLB中，以备将来的访问使用。

TLB是非常小的，一般都是几十项到几百项不等，并且为了提高命中率，很多处理器还采用全相连方式。
## 使用大页的原因

TLB大小是很有限的，随着程序的变大或者程序使用内存的增加，那么势必会增加TLB的使用项，最后导致TLB出现不命中的情
况。

那么，在这种情况下，大页的优势就显现出来了。如果采用2MB作为分页的基本单位，那么只需要一个表项就可以保证不出现TLB不命中的情况；对于消耗内存以GB为单位的大型程序，可以采用1GB为单位作为分页的基本单位，减少TLB不命中的情况。

Linux操作系统采用了基于hugetlbfs的特殊文件系统来加入对2MB或者1GB的大页面支持。编译内核时可以激活。

# DDIO

DDIO （Data Direct I/O）主要目的是优化数据包的处理性能，特别是在高吞吐量的网络环境中。通过将数据包直接发送到 CPU 的缓存中，DDIO 减少了数据包在 CPU 内部的处理延迟和开销。

DDIO 利用 CPU 的数据缓存来加速数据访问。数据包被直接写入到 CPU 的数据缓存（如 L2 或 L3 缓存），而不是首先写入主内存。这种方法可以显著减少内存访问延迟。

## 网卡读写对比

**没有DDIO技术**

当I/O设备（如网络接口卡、存储设备等）发起读写请求时，数据首先被传输到设备的缓冲区。设备通常通过DMA将数据直接传输到系统内存中的缓冲区。这个过程绕过了CPU，以减少CPU的负担和提高效率。

由于数据直接写入系统内存，可能会导致CPU缓存中存储的数据和系统内存中的数据不一致，需要通过缓存一致性协议来处理这些不一致。

完成数据传输后，I/O设备会生成中断信号通知CPU处理数据。CPU需要处理这些中断并从内存中读取数据，进一步将数据处理到应用程序中。

**有DDIO技术**

DDIO技术允许I/O设备（如网络卡）将数据直接写入CPU的L3缓存（通常是更大的共享缓存）而不是系统内存。这意味着I/O设备可以绕过传统的内存路径，将数据直接写入CPU的缓存层次结构中。

DDIO技术通过将数据直接写入CPU缓存，减少了CPU和系统内存之间的缓存一致性问题。由于数据首先进入L3缓存，CPU可以在缓存中处理数据，减少了对系统内存的读取和写入操作。

CPU处理这些数据时不需要从系统内存中读取数据，能够减少中断处理的延迟。


