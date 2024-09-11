
# 网络处理模块划分

- Packet Input: 接收数据包，将其引入处理流程。
- Pre-processing: 对数据包进行初步处理，例如基本的检查和标记。
- Input Classification: 细化数据包的分类，例如基于协议或流进行分流。
- Ingress Queuing: 将数据包放入队列中进行排队，通常采用FIFO（先进先出）策略。
- Delivery/Scheduling: 根据队列的优先级和CPU的状态决定数据包的处理顺序。
- Accelerator: 使用硬件加速功能来进行加解密或数据压缩等操作。
- Egress Queuing: 在出口处对数据包进行基于QoS（服务质量）的调度。
- Post Processing: 进行数据包的后处理，释放相关缓存。
- Packet Output: 将处理完的数据包发送到网络中。

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/921ef0b1d0c446e29f84d8d8810e43d2.png)
在深色软件部分可以通过提高算法的效率和结合CPU相关的并行指令来提升网络性能。

# 转发框架

传统的Network Processor（专用网络处理器）转发的模型可以分为run to completion（运行至终结，简称RTC）模型和pipeline（流水线）模型。


## run to completion模型


它的核心思想是，当一个处理核心接收到一个数据包时，它会完整地处理这个数据包，从接收到输出，直到处理结束，不会将其交给其他核心或线程处理。这个模型有几个主要特点：

- 完整处理：每个核心负责从输入到输出的整个数据包处理过程，减少了上下文切换和跨核心通信的开销。
- 高性能：通过避免频繁的线程切换和数据包转发，降低了延迟，提高了处理效率。
- 简单性：简化了数据包处理的模型，使得开发者可以更专注于优化单一核心的处理逻辑。

这种模型特别适合于高吞吐量的应用场景，例如网络交换和路由器，因为它最大限度地减少了延迟并提高了整体吞吐量。但是由于每个核上的处理能力其实都是一样的，并没有针对某个逻辑功能进行优化，因此在这个层面上与pipeline模型比较是不高效的。

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/50afad7675944083a388603e80a49fcc.png)


## pipeline模型

Pipeline模型在网络数据处理中的应用借鉴了工业上的流水线设计理念，其基本思想是将数据处理流程分解为多个独立的阶段，每个阶段专注于处理数据的一个特定部分。每个阶段通过队列将数据传递给下一个阶段，这种结构使得不同阶段的处理可以并行进行，从而提高整体处理效率。

在这个模型中，每个阶段可以被优化以处理特定类型的任务。例如，可以将CPU密集型的计算操作分配到专门的微处理引擎上，这些引擎能够提供高计算性能和效率。同时，将I/O密集型的操作分配到另一个微处理引擎上，这样可以优化I/O操作的处理能力。通过这种分离，模型可以充分利用不同处理引擎的特长，避免了单一引擎的瓶颈问题。

此外，Pipeline模型允许使用过滤器来动态地为不同的操作分配线程，这样可以根据处理负载和任务的需求调整资源分配。队列则起到缓冲和协调的作用，通过控制数据流速率，使得各个阶段的处理速率得到匹配，从而避免了过度的等待和资源闲置，优化了并发处理效率。


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/94b94a5770e741759071d036b3fccbbb.png)
# DPDK run to completion模型

在DPDK的轮询模式中主要通过一些DPDK中eal中的参数-c、-l、-l core s来设置哪些核可以被DPDK使用，最后再把处理对应收发队列的线程绑定到对应的核上。每个报文的整个生命周期都只可能在其中一个线程中出现。

run to completion 模型 虽然有许多优势，但是针对单个报文的处理始终集中在一个逻辑单元上，无法利用其他运算单元，并且逻辑的耦合性太强，而流水线模型正好解决了以上的问题。

# DPDK pipeline模型

pipeline的主要思想就是不同的工作交给不同的模块，而每一个模块都是一个处理引擎，每个处理引擎都只单独处理特定的事务，每个处理引擎都有输入和输出，通过这些输入和输出将不同的处理引擎连接起来，完成复杂的网络功能，DPDK pipeline的多处理引擎实例和每个处理引擎中的组成框图：zoom out（多核应用框架）和zoom in（单个流水线模块）。 

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/dc03f691dbbf45169372eb94aa08f85f.png)

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/678204d1d2e045f39b4af484e3caeb18.png)


Zoom out的实例中包含了五个DPDK pipeline处理模块，每个pipeline作为一个特定功能的包处理模块。一个报文从进入到发送，会有两个不同的路径，上面的路径有三个模块（解析、分类、发送），下面的路径有四个模块（解析、查表、修改、发送）。

Zoom in的图示中代表在查表的pipeline中有两张查找表，报文根据不同的条件可以通过一级表或两级表的查询从不同的端口发送出去。

DPDK的pipeline是由三大部分组成的：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/252c597db1c54409b2d7295a42f3e832.png)
DPDK支持的不同类型的pipeline处理包括：

- Packet I/O：处理网络数据包的输入和输出。
- Flow Classification：根据数据包的特征将其分类到不同的流中。
- Firewall：实现网络防火墙功能，控制数据包的访问权限。
- Routing：决定数据包的转发路径。
- Metering： 监测和测量网络流量。

在 `doc\guides\sample_app_ug\ip_pipeline.rst`中有 IP Pipeline 应用程序的一个例子

# 转发算法

除了良好的转发框架外，转发中很重要的一部分内容就是对报文字段的匹配和识别。DPDK 中主要用到了精确匹配（Exact Match）算法和最长前缀匹配（Longest Prefix Matching， LPM）算法来进行报文的匹配从而获得相应的信息。


## 精确匹配算法

精确匹配主要需要解决两个问题：进行数据的签名（哈希），解决哈希的冲突问题，DPDK中主要支持CRC32和J hash。

CRC 校验原理实际上就是在一个 p 位二进制数据序列之后附加一个 r 位二进制检验码，从而构成一个总长为 n=p+r 位的二进制序列。附加的检验码与数据序列的内容之间存在某种特定关系，通过检查这一关系，就可以实现对数据正确性的校验。

CRC中的多项式模 2 运行，实际上就是按位异或，不考虑进位、借位。当进行 CRC 校验时，发送方和接收方需要事先约定一个除数，即生成多项式，一般记作 G(x)。生成多项式的最高位与最低位必须是 1。

在 CRC32 算法上，DPDK 将数据流按照 8 字节 或 4 字节为单位，直接使用 IA 的硬件指令来一次处理，或使用查表的方法进行一次处理，利用空间换时间。

## 解决冲突

分离链表：所有发生冲突的项通过链式相连，在查找元素时需要遍历某个哈希桶下对应的整条链。不需要额外占用哈希桶，但是速度较慢。

开放地址：所有发生冲突的项自动往当前所对应可使用的哈希桶的下一个哈希桶进行填充。不需要链表操作，但有时会加剧冲突的发生。

DPDK 哈希桶的结构定义如下所示，每个桶可以盛 8 项，算是上述两种方法的一个折中。

```c
#define RTE_HASH_BUCKET_ENTRIES		8
/** Bucket structure */
struct __rte_cache_aligned rte_hash_bucket {
	uint16_t sig_current[RTE_HASH_BUCKET_ENTRIES];
	RTE_ATOMIC(uint32_t) key_idx[RTE_HASH_BUCKET_ENTRIES];
	uint8_t flag[RTE_HASH_BUCKET_ENTRIES];
	void *next;
};
```


## 最长前缀匹配算法

DPDK 中 LPM 的具体实现综合考虑了空间和时间，由一张 2^24^ 条目的表和多张（配置指定） 2^8^ 条目的表组成。前者称为表 tlb24， 后者称为表 tlb8。

表条目和转发如下：

```c
struct rte_lpm_tbl_entry {
	/**
	 * Stores Next hop (tbl8 or tbl24 when valid_group is not set) or
	 * a group index pointing to a tbl8 structure (tbl24 only, when
	 * valid_group is set)
	 */
	uint32_t next_hop    :24;
	/* Using single uint8_t to store 3 values. */
	uint32_t valid       :1;   /**< Validation flag. */
	/**
	 * For tbl24:
	 *  - valid_group == 0: entry stores a next hop
	 *  - valid_group == 1: entry stores a group_index pointing to a tbl8
	 * For tbl8:
	 *  - valid_group indicates whether the current tbl8 is in use or not
	 */
	uint32_t valid_group :1;
	uint32_t depth       :6; /**< Rule depth. */
};
/**
 * Lookup an IP into the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP to be looked up in the LPM table
 * @param next_hop
 *   Next hop of the most specific rule found for IP (valid on lookup hit only)
 * @return
 *   -EINVAL for incorrect arguments, -ENOENT on lookup miss, 0 on lookup hit
 */
static inline int
rte_lpm_lookup(const struct rte_lpm *lpm, uint32_t ip, uint32_t *next_hop)
{
	unsigned tbl24_index = (ip >> 8);
	uint32_t tbl_entry;
	const uint32_t *ptbl;

	/* DEBUG: Check user input arguments. */
	RTE_LPM_RETURN_IF_TRUE(((lpm == NULL) || (next_hop == NULL)), -EINVAL);

	/* Copy tbl24 entry */
	ptbl = (const uint32_t *)(&lpm->tbl24[tbl24_index]);
	tbl_entry = *ptbl;

	/* Memory ordering is not required in lookup. Because dataflow
	 * dependency exists, compiler or HW won't be able to re-order
	 * the operations.
	 */
	/* Copy tbl8 entry (only if needed) */
	if (unlikely((tbl_entry & RTE_LPM_VALID_EXT_ENTRY_BITMASK) ==
			RTE_LPM_VALID_EXT_ENTRY_BITMASK)) {

		unsigned tbl8_index = (uint8_t)ip +
				(((uint32_t)tbl_entry & 0x00FFFFFF) *
						RTE_LPM_TBL8_GROUP_NUM_ENTRIES);

		ptbl = (const uint32_t *)&lpm->tbl8[tbl8_index];
		tbl_entry = *ptbl;
	}

	*next_hop = ((uint32_t)tbl_entry & 0x00FFFFFF);
	return (tbl_entry & RTE_LPM_LOOKUP_SUCCESS) ? 0 : -ENOENT;
}
```


- 检查输入参数：如果 lpm 或 next_hop 为 NULL，则返回 -EINVAL。
- 查找 tbl24 表中的条目：根据 IP 地址的高 24 位索引，读取 tbl24 表中的条目。
- 判断是否需要进一步查找 tbl8 表：如果 tbl24 条目指示存在扩展条目（由 RTE_LPM_VALID_EXT_ENTRY_BITMASK 标志表示），则根据 IP 地址和 tbl24 条目中的索引计算 tbl8 表中的条目位置，并读取对应条目。
- 提取并返回结果：从条目中提取下一个跳转地址，并检查查找是否成功（通过 RTE_LPM_LOOKUP_SUCCESS 标志）。
