
硬件加速是指利用专门设计的硬件（如网络接口卡、处理器等）来加速特定的计算任务，从而提升性能。功能卸载是指将某些计算密集型或复杂的处理任务从 CPU 卸载到专门的硬件中，从而减少 CPU 的负担并提升整体系统的性能。

**协议卸载**：网络接口卡可以处理某些网络协议的功能（如 TCP 卸载），减少 CPU 需要处理的协议栈部分。例如，TCP 卸载将 TCP 连接的建立、管理、终止等操作交给 NIC 处理，从而降低 CPU 的工作负荷。

**加密和解密卸载**：硬件加速卡可以处理数据加密和解密操作。例如，支持 IPsec 的 NIC 可以在硬件层面处理加密操作，减少软件层的负担。

**负载均衡和流量管理**：高端 NIC 可以在硬件层面进行负载均衡和流量管理，减少需要在主机上进行的负担。

**数据包处理和筛选**：一些 NIC 支持硬件层的数据包筛选、分类和处理功能，这些操作通常会消耗 CPU 资源，但通过硬件卸载可以显著提高处理效率。

# 网卡硬件卸载

各种网卡支持的硬件卸载的功能

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/bb6090d98551450f842a5c842b08a875.png)
DPDK提供了硬件卸载的接口，利用rte_mbuf数据结构里的64位的标识（ol_flags）来表征卸载与状态

```c
uint64_t ol_flags;        /**< Offload features. */
```

## 接收

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/54bdf1168b8b4fa8b5b3a85c56e79929.png)
## 发送

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/d95f3a9f3aa243cc976be840d9660c3a.png)
# VLAN硬件卸载

虚拟局域网是一种通过将物理网络划分为多个逻辑网络来实现网络隔离和管理的技术。VLAN使用标记（Tag）来标识数据包所属的虚拟网络。


如果由软件完成VLAN Tag的插入将会给CPU带来额外的负荷，涉及一次额外的内存拷贝（报文内容复制），最坏场景下，这可能是上百周期的开销。大多数网卡硬件提供了VLAN卸载的功能。

## 接收侧针对VLAN进行包过滤

网卡最典型的卸载功能之一就是在接收侧针对VLAN进行包过滤，在DPDK中app/testpmd提供了测试命令与实现代码

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0f2cf0bb57ae42c8a77050485811044d.png)

## 发包时VLAN Tag的插入

在DPDK中，在调用发送函数前，必须提前设置mbuf数据结构，设置PKT_TX_VLAN_PKT位，同时将具体的Tag信息写入vlan_tci字段。

```c
/** Outer VLAN TCI (CPU order), valid if RTE_MBUF_F_RX_QINQ is set. */
uint16_t vlan_tci_outer;
```

## 多层VLAN的支持

在早期的VLAN标准中，VLAN标记字段为12位宽，这使得可以标识最多4096个不同的VLAN（2^12 = 4096）。这个限制在大型网络中可能不够用，因为可能需要更多的虚拟网络来进行合理的网络分段和管理。

为了克服单层VLAN的限制，业界引入了QinQ技术，也称为双层VLAN堆叠。QinQ技术在数据包中嵌套两个VLAN标签：一个是外层VLAN（称为服务提供商VLAN，S-VLAN），另一个是内层VLAN（称为客户VLAN，C-VLAN）。这种双层VLAN标记允许在同一物理网络中支持更多的虚拟网络。


现代网卡硬件大多提供对两层VLAN Tag进行卸载，如VLAN Tag的剥离、插入。而不需要依赖主机的处理器来执行这些操作。这种硬件卸载可以显著提高网络性能，减轻CPU负担。


# checksum硬件卸载功能

**接收方向**：网络硬件可以自动验证收到的数据包的校验和。如果发现校验和错误，硬件会设置一个错误标志，并可以选择丢弃这些错误的数据包。在DPDK中，每个数据包由rte_mbuf表示，网卡会将错误标志设置在ol_flags字段中，软件驱动可以通过查询这个字段来检测是否有错误发生。

**发送方向**：在数据包发送时，硬件可以自动计算和插入校验和，减轻主机的处理负担。这样，软件应用只需要准备数据，硬件负责处理校验和的计算和插入。


# 分片功能卸载

TSO（TCP Segment Offload）是TCP分片功能的硬件卸载，对于从应用层获取的较大的数据，TCP需要根据下层网络的报文大小限制，将其切分成较小的分片发送。

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1f79d93a5434462c816078bf88893696.png)


在dpdk/testpmd中提供了两条TSO相关的命令行：

- tso set 14000：用于设置tso分片大小。
- tso show 0：用于查看tso分片的大小。


# 组包功能卸载

RSC（Receive Side Coalescing，接收方聚合）是TCP组包功能的硬件卸载。硬件组包功能实际上是硬件拆包功能的逆向功能。

硬件组包功能针对TCP实现，是接收方向的功能，可以将拆分的TCP分片聚合成一个大的分片，从而减轻软件的处理。

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/3fd548b2a5e54457a63e0cc8fb35a4fe.png)

```c
/**
 * A structure used to configure the Rx features of an Ethernet port.
 */
struct rte_eth_rxmode {
	/** The multi-queue packet distribution mode to be used, e.g. RSS. */
	enum rte_eth_rx_mq_mode mq_mode;
	uint32_t mtu;  /**< Requested MTU. */
	/** Maximum allowed size of LRO aggregated packet. */
	uint32_t max_lro_pkt_size;
	/**
	 * Per-port Rx offloads to be set using RTE_ETH_RX_OFFLOAD_* flags.
	 * Only offloads set on rx_offload_capa field on rte_eth_dev_info
	 * structure are allowed to be set.
	 */
	uint64_t offloads;

	uint64_t reserved_64s[2]; /**< Reserved for future fields */
	void *reserved_ptrs[2];   /**< Reserved for future fields */
};
```

RSC是接收方向的功能，因此和描述接收模式的数据结构（即enable_lro）相关。（LRO是指Large Receive Offload，是RSC的另一种表述）


当对接收处理进行初始化`ixgbe_dev_rx_init`时，会调用`ixgbe_set_rsc`，此函数中对`enable_lro`进行判断，如果其为真，则会对RSC进行相关设置，从而使用此功能。

```c
static int
ixgbe_set_rsc(struct rte_eth_dev *dev)
{
	struct rte_eth_rxmode *rx_conf = &dev->data->dev_conf.rxmode;
	struct ixgbe_hw *hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct rte_eth_dev_info dev_info = { 0 };
	bool rsc_capable = false;
	uint16_t i;
	uint32_t rdrxctl;
	uint32_t rfctl;

	/* Sanity check */
	dev->dev_ops->dev_infos_get(dev, &dev_info);
	if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO)
		rsc_capable = true;

	if (!rsc_capable && (rx_conf->offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO)) {
		PMD_INIT_LOG(CRIT, "LRO is requested on HW that doesn't "
				   "support it");
		return -EINVAL;
	}
...........
```


