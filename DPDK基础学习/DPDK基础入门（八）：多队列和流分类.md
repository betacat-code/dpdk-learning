
# 网卡多队列

网卡多队列，也就是传统网卡的DMA队列有多个，网卡有基于多个DMA队列的分配机制。多队列网卡已经是当前高速率网卡的主流。
## Linux内核中的多队列

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/e4b5182ce97c4a32b77a5d3af7e591f4.png)
Linux中的dev_pick_tx用于选择发送队列。它可以根据自定义策略、队列优先级或哈希均衡来决定哪个队列用于发送数据包。队列会被分配到特定的CPU列表中，这些CPU中的某个CPU负责处理队列中的数据。这种映射有两个主要好处：

- 减少设备队列上的锁竞争，因为只有少数CPU对同一队列竞争。
- 减少缓存不命中的概率，因为数据处理集中在特定的CPU上，避免了缓存频繁迁移。

而收发队列通常会绑定在同一个中断上，这样可以提高效率，因为从接收队列收到的数据包可以直接从相应的发送队列发出，提高缓存命中率和性能。


多核CPU系统中，各个核有自己的L1和L2缓存，多个核共享L3缓存。


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/6e671a82d24440d687cd6e071f97b298.png)
对于单队列的网卡设备，有时也会需要负载分摊到多个执行单元上执行，在没有多队列支持的情况下，就需要软件来均衡流量。

Linux内核中，`RPS（Receive Packet Steering）`在接收端提供了这样的机制。RPS主要是把软中断的负载均衡到CPU的各个core上，网卡驱动对每个流生成一个hash标识，这个hash值可以通过四元组（源IP地址SIP，源四层端口SPORT，目的IP地址DIP，目的四层端口DPORT）来计算，然后由中断处理的地方根据这个hash标识分配到相应的core上去，这样就可以比较充分地发挥多核的能力了。


也就是在软件层面模拟实现硬件的多队列网卡功能。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/8a0a16b19f1f4767ab0b8e2223325441.png)

>NAPI（New API）是Linux内核中的一个机制，用于提高网络数据包接收的效率。它通过减少中断处理的频率，将网络接收处理转变为轮询机制

>Qdisc（Queueing Discipline）是Linux网络栈中的一个组件，用于管理数据包的队列和调度。它控制数据包的入队、出队顺序以及如何处理队列中的数据包


## DPDK多队列

DPDK Packet I/O机制具有多队列支持功能，可以根据不同的平台或者需求，选择需要使用的队列数目，并可以很方便地使用队列，指定队列发送或接收报文。由于这样的特性，可以很容易实现CPU核、缓存与网卡队列之间的亲和性，从而达到很好的性能。

DPDK的队列管理机制还可以避免多核处理器中的多个收发进程采用自旋锁产生的不必要等待。

以run to completion模型为例，可以从核、内存与网卡队列之间的关系来理解DPDK是如何利用网卡多队列技术带来性能的提升。

- 将网卡的某个接收队列分配给某个核，从该队列中收到的所有报文都应当在该指定的核上处理结束。
- 从核对应的本地存储中分配内存池，接收报文和对应的报文描述符都位于该内存池。
- 为每个核分配一个单独的发送队列，发送报文和对应的报文描述符都位于该核和发送队列对应的本地内存池中。

`l3fwd`示例

```c
/* init one TX queue per couple (lcore,port) */
		queueid = 0;
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			if (queueid >= dev_txq_num)
				continue;

			if (numa_on)
				socketid = \
				(uint8_t)rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;

			printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
			fflush(stdout);

			txconf = &dev_info.default_txconf;
			txconf->offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     socketid, txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					"rte_eth_tx_queue_setup: err=%d, "
						"port=%d\n", ret, portid);

			qconf = &lcore_conf[lcore_id];
			qconf->tx_queue_id[portid] = queueid;
			queueid++;

			qconf->tx_port_id[qconf->n_tx_port] = portid;
			qconf->n_tx_port++;
		}
```

其中调用 `rte_eth_tx_queue_setup` 来初始化指定端口 (portid) 的传输队列。不同的核，操作的是不同的队列，从而避免了多个线程同时访问一个队列带来的锁的开销。但是，如果逻辑核的数目大于每个接口上所含的发送队列的数目，那么就需要有机制将队列分配给这些核。


常用的方法有微软提出的`RSS`与英特尔提出的`Flow Director`技术，前者是根据哈希值希望均匀地将包分发到多个队列中。后者是基于查找的精确匹配，将包分发到指定的队列中。


# 流分类
## RSS


RSS（Receive-Side Scaling，接收方扩展），就是根据关键字通过哈希函数计算出哈希值，再由哈希值确定队列。 

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/05ed82fdaf354da4accdc7c2fa1304f9.png)
关键字确定如下图：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1eb037a9f29e4feca2111242c360f760.png)

## Flow Director

Flow Director技术是Intel公司提出的根据包的字段精确匹配，将其分配到某个特定队列的技术。

网卡上存储了一个Flow Director的表，表的大小受硬件资源限制，它记录了需要匹配字段的关键字及匹配后的动作；驱动负责操作这张表，包括初始化、增加表项、删除表项；网卡从线上收到数据包后根据关键字查Flow Director的这张表，匹配后按照表项中的动作处理，可以是分配队列、丢弃等。


相比RSS的负载分担功能，它更加强调特定性。比如，用户可以为某几个特定的TCP对话（S-IP+D-IP+S-Port+D-Port）预留某个队列，那么处理这些TCP对话的应用就可以只关心这个特定的队列，从而省去了CPU过滤数据包的开销，并且可以提高cache的命中率。

## QoS

多队列应用于服务质量（QoS）流量类别，把发送队列分配给不同的流量类别，可以让网卡在发送侧做调度；把收包队列分配给不同的流量类别，可以做到基于流的限速。

根据流中优先级或业务类型字段，可以将流不同的业务类型有着不同的调度优先级及为其分配相应的带宽，一般网卡依照VLAN标签的UP（User Priority，用户优先级）字段。网卡依据UP字段，将流划分到某个业务类型（TC，Traffic Class），网卡设备根据TC对业务做相应的处理，比如确定相对应的队列，根据优先级调度等。

## 流过滤

来自外部的数据包哪些是本地的、可以被接收的，哪些是不可以被接收的？可以被接收的数据包会被网卡送到主机或者网卡内置的管理控制器，其过滤主要集中在以太网的二层功能，包括VLAN及MAC过滤。

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a9cf44c4db684362abeb8402af49be64.png)



