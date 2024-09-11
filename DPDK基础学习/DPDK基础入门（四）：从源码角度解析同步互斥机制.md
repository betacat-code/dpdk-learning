# 原子锁

原子操作在DPDK代码中的定义都在rte_atomic.h文件中，主要包含两部分：内存屏蔽和原16、32和64位的原子操作API。

## 内存屏障

```c
#ifndef _RTE_ATOMIC_ARM32_H_
#define _RTE_ATOMIC_ARM32_H_

#ifndef RTE_FORCE_INTRINSICS
#  error Platform must be built with RTE_FORCE_INTRINSICS
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "generic/rte_atomic.h"

#define	rte_mb()  __sync_synchronize()

#define	rte_wmb() do { asm volatile ("dmb st" : : : "memory"); } while (0)

#define	rte_rmb() __sync_synchronize()

#define rte_smp_mb() rte_mb()

#define rte_smp_wmb() rte_wmb()

#define rte_smp_rmb() rte_rmb()

#define rte_io_mb() rte_mb()

#define rte_io_wmb() rte_wmb()

#define rte_io_rmb() rte_rmb()

static __rte_always_inline void
rte_atomic_thread_fence(rte_memory_order memorder)
{
	__rte_atomic_thread_fence(memorder);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ATOMIC_ARM32_H_ */
```

 ` rte_mb() `使用 GCC 内建函数 `__sync_synchronize() `来实现。这是一个全屏障，确保所有的内存操作在这个屏障之前的操作完成之后再执行之后的操作。 `__sync_synchronize() `函数对应着 `MFENCE`这个序列化加载与存储操作汇编指令。

`MFENCE`用于在多核处理器环境中确保内存操作的顺序性。它会强制所有之前的内存读写操作在 MFENCE 指令执行前完成，确保内存操作的可见性和顺序性。


以下代码为例，用来判断环形缓冲区从空变为非空时是否需要发出信号
```c
static inline bool
vmbus_txbr_need_signal(const struct vmbus_bufring *vbr, uint32_t old_windex)
{
	rte_smp_mb();
	if (vbr->imask)
		return false;
	rte_smp_rmb();

	/*
	 * This is the only case we need to signal when the
	 * ring transitions from being empty to non-empty.
	 */
	return old_windex == vbr->rindex;
}
```

## 原子操作

以`rte_atomic64_add()` 为例子

```c
static inline void
rte_atomic64_add(rte_atomic64_t *v, int64_t inc)
{
	rte_atomic_fetch_add_explicit(&v->cnt, inc, rte_memory_order_acquire);
}
// 涉及的宏定义
#define rte_memory_order_acquire __ATOMIC_ACQUIRE

#define rte_atomic_fetch_add_explicit(ptr, val, memorder) \
	__atomic_fetch_add(ptr, val, memorder)
```

`__atomic_fetch_add` 是 GCC 和 Clang 编译器提供的一个内置函数,用于对一个变量执行原子加法操作，保证该操作的原子性。

# 读写锁

读写锁对共享资源的访问操作划分成读操作和写操作，读操作只对共享资源进行读访问，写操作则需要对共享资源进行写操作。这种锁相对于自旋锁而言，能提高并发性，因为在多处理器系统中，它允许同时有多个读操作来访问共享资源，最大可能的读操作数为实际的逻辑CPU数。

读写锁定义在`rte_rwlock.h`中，以读锁操作为例：

```c
static inline void
rte_rwlock_read_lock(rte_rwlock_t *rwl)
	__rte_shared_lock_function(rwl)
	__rte_no_thread_safety_analysis
{
	int32_t x;

	while (1) {
		/* Wait while writer is present or pending */
		while (rte_atomic_load_explicit(&rwl->cnt, rte_memory_order_relaxed)
		       & RTE_RWLOCK_MASK)
			rte_pause();

		/* Try to get read lock */
		x = rte_atomic_fetch_add_explicit(&rwl->cnt, RTE_RWLOCK_READ,
				       rte_memory_order_acquire) + RTE_RWLOCK_READ;

		/* If no writer, then acquire was successful */
		if (likely(!(x & RTE_RWLOCK_MASK)))
			return;

		/* Lost race with writer, backout the change. */
		rte_atomic_fetch_sub_explicit(&rwl->cnt, RTE_RWLOCK_READ,
				   rte_memory_order_relaxed);
	}
}
```

使用自旋等待和原子操作来保证线程安全。它会不断检查写锁是否被持有，尝试在没有写者的情况下获取读锁。如果获取失败，会回滚并重试。

# 自旋锁

自旋锁是一种忙等待的锁机制，线程在尝试获取锁时，如果锁被其他线程持有，就会不断地循环检查锁的状态，直到获取锁为止。DPDK的自旋锁定义在`rte_spinlock.h`中

```c
typedef struct __rte_lockable {
	volatile RTE_ATOMIC(int) locked; /**< lock status 0 = unlocked, 1 = locked */
} rte_spinlock_t;
```

以获取自旋锁的操作为例

```c
static inline void
rte_spinlock_lock(rte_spinlock_t *sl)
	__rte_no_thread_safety_analysis
{
	int exp = 0;

	while (!rte_atomic_compare_exchange_strong_explicit(&sl->locked, &exp, 1,
				rte_memory_order_acquire, rte_memory_order_relaxed)) {
		rte_wait_until_equal_32((volatile uint32_t *)(uintptr_t)&sl->locked,
			       0, rte_memory_order_relaxed);
		exp = 0;
	}
}
```
使用原子操作尝试将sl->locked的值从0（锁未被持有）设置为1（锁被持有）。如果成功，表示锁被当前线程获取。如果锁已被持有，线程会忙等待，直到sl->locked的值变为0。期间会周期性地检查锁状态，减少对CPU的负担。
# 无锁机制 

在DPDK这种高并发的环境下，锁竞争机制会比数据拷贝、上下文切换等更伤害系统的性能。需要考虑在特定的场合使用不同的无锁队列，Linux中有kfifo，其采用FIFO（先进先出）原则，适用于单生产者/单消费者模式，不需要任何加锁行为就可以保证kfifo线程安全。

在DPDK中提供了一套无锁环形缓冲区队列管理代码，支持单生产者产品入列，单消费者产品出列；多名生产者产品入列，多名消费者出列操作。

## 数据定义

```c
/**
 * An RTE ring structure.
 *
 * The producer and the consumer have a head and a tail index. The particularity
 * of these index is that they are not between 0 and size(ring)-1. These indexes
 * are between 0 and 2^32 -1, and we mask their value when we access the ring[]
 * field. Thanks to this assumption, we can do subtractions between 2 index
 * values in a modulo-32bit base: that's why the overflow of the indexes is not
 * a problem.
 */
struct rte_ring {
	alignas(RTE_CACHE_LINE_SIZE) char name[RTE_RING_NAMESIZE];
	/**< Name of the ring. */
	int flags;               /**< Flags supplied at creation. */
	const struct rte_memzone *memzone;
			/**< Memzone, if any, containing the rte_ring */
	uint32_t size;           /**< Size of ring. */
	uint32_t mask;           /**< Mask (size-1) of ring. */
	uint32_t capacity;       /**< Usable size of ring */

	RTE_CACHE_GUARD;

	/** Ring producer status. */
	union __rte_cache_aligned {
		struct rte_ring_headtail prod;
		struct rte_ring_hts_headtail hts_prod;
		struct rte_ring_rts_headtail rts_prod;
	};

	RTE_CACHE_GUARD;

	/** Ring consumer status. */
	union __rte_cache_aligned {
		struct rte_ring_headtail cons;
		struct rte_ring_hts_headtail hts_cons;
		struct rte_ring_rts_headtail rts_cons;
	};

	RTE_CACHE_GUARD;
};
```

`RTE_CACHE_LINE_SIZE` 确保名称字段在缓存行边界上对齐，从而减少缓存行伪共享的可能性，`RTE_CACHE_GUARD`与上类似。

下面定义了生产者状态的联合体，它包含不同的状态结构体 (`rte_ring_headtail`, `rte_ring_hts_headtail`, `rte_ring_rts_headtail`)，这些结构体定义了生产者的状态信息，如生产者的头尾指针或索引。

```c
struct rte_ring_headtail {
	volatile RTE_ATOMIC(uint32_t) head;      /**< prod/consumer head. */
	volatile RTE_ATOMIC(uint32_t) tail;      /**< prod/consumer tail. */
	union {
		/** sync type of prod/cons */
		enum rte_ring_sync_type sync_type;
		/** deprecated -  True if single prod/cons */
		uint32_t single;
	};
};
```
可以注意到head、tail、的类型都是uint32_t。除此之外，队列的大小count被限制为2的幂次方。这两个条件放到一起构成了一个很巧妙的情景。因为队列的大小一般不会有2的32次方那么大，所以，把队列取为32位的一个窗口，当窗口的大小是2的幂次方，则32位包含整数个窗口。

这样，用来存放ring对象的void *指针数组空间就可只申请一个窗口大小即可。根据二进制的回环性，可以直接用`(uint32_t)( prod_tail \- cons_tail)`计算队列中有多少生产的产品，即使溢出了也不会出错。

##  进程间通信

`rte_ring`需要与`rte_mempool`配合使用，通过`rte_mempool`来共享内存。dpdk多进程示例解读`（examples/multi_process/simple_mp）`，实现进程之间的master和slave线程互发字串 ：

```c
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

static const char *_MSG_POOL = "MSG_POOL";
static const char *_SEC_2_PRI = "SEC_2_PRI";
static const char *_PRI_2_SEC = "PRI_2_SEC";

struct rte_ring *send_ring, *recv_ring;
struct rte_mempool *message_pool;
volatile int quit = 0;

static int
lcore_recv(__rte_unused void *arg)
{
	unsigned lcore_id = rte_lcore_id();

	printf("Starting core %u\n", lcore_id);
	while (!quit){
		void *msg;
		if (rte_ring_dequeue(recv_ring, &msg) < 0){
			usleep(5);
			continue;
		}
		printf("core %u: Received '%s'\n", lcore_id, (char *)msg);
		rte_mempool_put(message_pool, msg);
	}

	return 0;
}

int
main(int argc, char **argv)
{
	const unsigned flags = 0;
	const unsigned ring_size = 64;
	const unsigned pool_size = 1024;
	const unsigned pool_cache = 32;
	const unsigned priv_data_sz = 0;

	int ret;
	unsigned lcore_id;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

	/* Start of ring structure. 8< */
	if (rte_eal_process_type() == RTE_PROC_PRIMARY){
		send_ring = rte_ring_create(_PRI_2_SEC, ring_size, rte_socket_id(), flags);
		recv_ring = rte_ring_create(_SEC_2_PRI, ring_size, rte_socket_id(), flags);
		message_pool = rte_mempool_create(_MSG_POOL, pool_size,
				STR_TOKEN_SIZE, pool_cache, priv_data_sz,
				NULL, NULL, NULL, NULL,
				rte_socket_id(), flags);
	} else {
		recv_ring = rte_ring_lookup(_PRI_2_SEC);
		send_ring = rte_ring_lookup(_SEC_2_PRI);
		message_pool = rte_mempool_lookup(_MSG_POOL);
	}
	/* >8 End of ring structure. */
	if (send_ring == NULL)
		rte_exit(EXIT_FAILURE, "Problem getting sending ring\n");
	if (recv_ring == NULL)
		rte_exit(EXIT_FAILURE, "Problem getting receiving ring\n");
	if (message_pool == NULL)
		rte_exit(EXIT_FAILURE, "Problem getting message pool\n");

	RTE_LOG(INFO, APP, "Finished Process Init.\n");

	/* call lcore_recv() on every worker lcore */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_remote_launch(lcore_recv, NULL, lcore_id);
	}

	/* call cmd prompt on main lcore */
	struct cmdline *cl = cmdline_stdin_new(simple_mp_ctx, "\nsimple_mp > ");
	if (cl == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create cmdline instance\n");
	cmdline_interact(cl);
	cmdline_stdin_exit(cl);

	rte_eal_mp_wait_lcore();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
```

使用时，`rte_mempool_get`从`mempool`中获取一个对象，然后使用`rte_ring_enqueue`入队列，另一个进程通过`rte_ring_dequeue`出队列，使用完成后需要`rte_mempool_put`将对象放回`mempool`

## 多生产消费

在 `dpdk\lib\ring\rte_ring_elem_pvt.h`文件中

```c
/**
 * @internal Enqueue several objects on the ring
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Enqueue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Enqueue as many items as possible from ring
 * @param is_sp
 *   Indicates whether to use single producer or multi-producer head update
 * @param free_space
 *   returns the amount of space after the enqueue operation has finished
 * @return
 *   Actual number of objects enqueued.
 *   If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_do_enqueue_elem(struct rte_ring *r, const void *obj_table,
		unsigned int esize, unsigned int n,
		enum rte_ring_queue_behavior behavior, unsigned int is_sp,
		unsigned int *free_space)
{
	uint32_t prod_head, prod_next;
	uint32_t free_entries;

	n = __rte_ring_move_prod_head(r, is_sp, n, behavior,
			&prod_head, &prod_next, &free_entries);
	if (n == 0)
		goto end;

	__rte_ring_enqueue_elems(r, prod_head, obj_table, esize, n);

	__rte_ring_update_tail(&r->prod, prod_head, prod_next, is_sp, 1);
end:
	if (free_space != NULL)
		*free_space = free_entries - n;
	return n;
}
```

移动生产者头部：调用` __rte_ring_move_prod_head` 函数来更新生产者头部的位置。这个函数会检查缓冲区的可用空间，并确定可以入队多少对象。

检查是否成功：如果 n 变为 0，说明没有对象被入队，函数将跳到 end 标签并返回。

入队操作：调用 `__rte_ring_enqueue_elems` 函数将对象从 `obj_table` 中复制到环形缓冲区。

更新生产者尾部：调用 `__rte_ring_update_tail` 函数更新生产者的尾部位置，完成入队操作。

计算剩余空间：如果 `free_space` 参数不为 NULL，将剩余的空间量存入 free_space。

返回入队数量：返回实际入队的对象数量。

涉及到的函数如下：

```c
static __rte_always_inline unsigned int
__rte_ring_move_prod_head(struct rte_ring *r, unsigned int is_sp,
		unsigned int n, enum rte_ring_queue_behavior behavior,
		uint32_t *old_head, uint32_t *new_head,
		uint32_t *free_entries)
{
	const uint32_t capacity = r->capacity;
	unsigned int max = n;
	int success;

	do {
		/* Reset n to the initial burst count */
		n = max;

		*old_head = r->prod.head;

		/* add rmb barrier to avoid load/load reorder in weak
		 * memory model. It is noop on x86
		 */
		rte_smp_rmb();

		/*
		 *  The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * *old_head > cons_tail). So 'free_entries' is always between 0
		 * and capacity (which is < size).
		 */
		*free_entries = (capacity + r->cons.tail - *old_head);

		/* check that we have enough room in ring */
		if (unlikely(n > *free_entries))
			n = (behavior == RTE_RING_QUEUE_FIXED) ?
					0 : *free_entries;

		if (n == 0)
			return 0;

		*new_head = *old_head + n;
		if (is_sp) {
			r->prod.head = *new_head;
			success = 1;
		} else
			success = rte_atomic32_cmpset((uint32_t *)(uintptr_t)&r->prod.head,
					*old_head, *new_head);
	} while (unlikely(success == 0));
	return n;
}
```

保存初始状态：n 被重置为 max（最初的尝试步数），保存当前的生产者头指针到 old_head。

内存屏障：调用 `rte_smp_rmb()` 添加内存屏障，以防止在弱内存模型下的加载重排序。在x86架构上这通常是个空操作。

计算可用空间：计算环形缓冲区中剩余的可用空间量，并将其存储在 `free_entries` 中。计算方式是 `(capacity + r->cons.tail - *old_head)`，这确保了计算结果在 0 和容量之间。

检查空间是否足够：如果请求的空间 n 大于可用空间 `free_entries`，则根据队列行为决定要使用的空间。如果行为是固定大小的队列`(RTE_RING_QUEUE_FIXED)`，则将 n 设为 0；否则，将 n 设置为可用空间量 `free_entries`。

更新头指针：计算新的头指针 `*new_head`。
- 如果是单生产者模式，直接更新 `r->prod.head` 为新值并标记操作成功。
- 如果是多生产者模式，使用 `rte_atomic32_cmpset` 原子操作尝试更新生产者头指针，如果更新失败则重试。

返回结果：返回实际成功移动的步数 n。如果操作失败（例如在多生产者模式下竞争失败），函数会重新尝试，直到成功为止。

其中`rte_atomic32_cmpset`涉及到CAS操作

```c
static inline int
rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
	return rte_atomic_compare_exchange_strong_explicit(dst, &exp, src, rte_memory_order_acquire,
		rte_memory_order_acquire) ? 1 : 0;
}
```


`__rte_ring_update_tail` 函数更新生产者的尾部位置如下所示：

```c
static __rte_always_inline void
__rte_ring_update_tail(struct rte_ring_headtail *ht, uint32_t old_val,
		uint32_t new_val, uint32_t single, uint32_t enqueue)
{
	if (enqueue)
		rte_smp_wmb();
	else
		rte_smp_rmb();
	/*
	 * If there are other enqueues/dequeues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	if (!single)
		rte_wait_until_equal_32((volatile uint32_t *)(uintptr_t)&ht->tail, old_val,
			rte_memory_order_relaxed);

	ht->tail = new_val;
}
```


主要就是等待其他操作完成，如果 single 为假（即不只一个线程在操作），调用`rte_wait_until_equal_32() `函数。这个函数会自旋等待，直到 `ht->tail `的值与 `old_val` 相等，表示其他线程的操作已经完成。


出队函数与入队类似，不再赘述

```c
/**
 * @internal Dequeue several objects from the ring
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to pull from the ring.
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Dequeue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Dequeue as many items as possible from ring
 * @param is_sc
 *   Indicates whether to use single consumer or multi-consumer head update
 * @param available
 *   returns the number of remaining ring entries after the dequeue has finished
 * @return
 *   - Actual number of objects dequeued.
 *     If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_do_dequeue_elem(struct rte_ring *r, void *obj_table,
		unsigned int esize, unsigned int n,
		enum rte_ring_queue_behavior behavior, unsigned int is_sc,
		unsigned int *available)
{
	uint32_t cons_head, cons_next;
	uint32_t entries;

	n = __rte_ring_move_cons_head(r, (int)is_sc, n, behavior,
			&cons_head, &cons_next, &entries);
	if (n == 0)
		goto end;

	__rte_ring_dequeue_elems(r, cons_head, obj_table, esize, n);

	__rte_ring_update_tail(&r->cons, cons_head, cons_next, is_sc, 0);

end:
	if (available != NULL)
		*available = entries - n;
	return n;
}

```

