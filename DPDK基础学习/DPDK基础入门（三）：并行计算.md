
# CPU亲和性

CPU亲和性（CPU Affinity）是指将特定的进程或线程绑定到特定的CPU核心或一组核心上运行。这样做的目的是提高性能和效率，避免由于线程在不同核心间频繁迁移而导致的缓存失效（cache misses）和上下文切换（context switching）开销。通过CPU亲和性，可以更好地利用CPU缓存，提高数据处理速度，特别是在高负载的环境中。


Linux内核API提供了一些方法，让用户可以修改位掩码或查看当前的位掩码：

```c
sched_set_affinity()：用来修改位掩码
sched_get_affinity()：用来查看当前的位掩码
```

## 线程独占

除了绑定线程到特定核心之外，为了进一步优化性能，可以将这些核心从操作系统的调度系统中剥离。这意味着这些核心将不会被操作系统用来调度其他任务，从而最大程度地减少外部干扰对核心的影响。



使用了 isolcpus 启动参数来指定在 Linux 系统中隔离哪些 CPU 核心，isolcpus=2,3 表示在系统启动时，CPU 2 和 CPU 3 将被隔离，系统会尽量避免在这些核心上运行常规的进程。这些核心仍然可以通过 taskset 命令来运行特定的进程。



## DPDK中的多线程

DPDK的多线程是基于pthread接口创建的，属于抢占式线程模型，受内核支配。DPDK通过在多核设备上创建多个线程，每个线程绑定到单独的核上，减少线程调度的开销，来提高性能

DPDK可以作为控制线程也可以作为数据线程，控制线程一般绑定到主核上，受用户配置，传递配置参数给数据线程，数据线程分布在不同核上处理数据包。

DPDK（Data Plane Development Kit）中的 lcore 和 EAL（Environment Abstraction Layer）线程的管理机制：

- lcore（逻辑核心）： 在 DPDK 中，lcore 是逻辑核心的简称，通常对应于一个 EAL 线程。在 DPDK 的上下文中，lcore 实际上是一个线程，在系统中它是一个处理数据包的工作单元。

- EAL（环境抽象层）： EAL 是 DPDK 的一个组件，负责与底层硬件进行交互，并为 DPDK 应用程序提供一个抽象层。EAL 负责初始化环境、管理线程、设置 CPU 亲和性等。

- pthread 和 _lcore_id： DPDK 的 lcore 实际上是基于 POSIX 线程（pthread）封装的。在每个 EAL 线程中，有一个 TLS（线程局部存储）变量 _lcore_id。这个变量存储了当前线程所对应的逻辑核心 ID。这个 ID 是线程在 DPDK 中的标识。

# 指令并发

现代多核处理器几乎都采用了超标量的体系结构来提高指令的并发度，并进一步地允许对无依赖关系的指令乱序执行。这种用空间换时间的方法，极大提高了IPC，使得一个时钟周期完成多条指令成为可能。

DPDK中使用了SIMD（Single Instruction, Multiple Data）指令集来提高数据处理的效率。

SIMD 指令通过使用更宽的寄存器（如 YMM 寄存器）来处理多个数据单元，能够充分利用处理器缓存的带宽。


比如DPDK中的memcpy函数

```c
static __rte_always_inline void *
rte_memcpy_generic(void *dst, const void *src, size_t n)
{
	__m128i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8;
	void *ret = dst;
	size_t dstofss;
	size_t srcofs;

	/**
	 * Copy less than 16 bytes
	 */
	if (n < 16) {
		return rte_mov15_or_less(dst, src, n);
	}

	/**
	 * Fast way when copy size doesn't exceed 512 bytes
	 */
	if (n <= 32) {
		rte_mov16((uint8_t *)dst, (const uint8_t *)src);
		if (__rte_constant(n) && n == 16)
			return ret; /* avoid (harmless) duplicate copy */
		rte_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 64) {
		rte_mov32((uint8_t *)dst, (const uint8_t *)src);
		if (n > 48)
			rte_mov16((uint8_t *)dst + 32, (const uint8_t *)src + 32);
		rte_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 128) {
		goto COPY_BLOCK_128_BACK15;
	}
	if (n <= 512) {
		if (n >= 256) {
			n -= 256;
			rte_mov128((uint8_t *)dst, (const uint8_t *)src);
			rte_mov128((uint8_t *)dst + 128, (const uint8_t *)src + 128);
			src = (const uint8_t *)src + 256;
			dst = (uint8_t *)dst + 256;
		}
COPY_BLOCK_255_BACK15:
		if (n >= 128) {
			n -= 128;
			rte_mov128((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 128;
			dst = (uint8_t *)dst + 128;
		}
COPY_BLOCK_128_BACK15:
		if (n >= 64) {
			n -= 64;
			rte_mov64((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 64;
			dst = (uint8_t *)dst + 64;
		}
COPY_BLOCK_64_BACK15:
		if (n >= 32) {
			n -= 32;
			rte_mov32((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 32;
			dst = (uint8_t *)dst + 32;
		}
		if (n > 16) {
			rte_mov16((uint8_t *)dst, (const uint8_t *)src);
			rte_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
			return ret;
		}
		if (n > 0) {
			rte_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		}
		return ret;
	}

	/**
	 * Make store aligned when copy size exceeds 512 bytes,
	 * and make sure the first 15 bytes are copied, because
	 * unaligned copy functions require up to 15 bytes
	 * backwards access.
	 */
	dstofss = (uintptr_t)dst & 0x0F;
	if (dstofss > 0) {
		dstofss = 16 - dstofss + 16;
		n -= dstofss;
		rte_mov32((uint8_t *)dst, (const uint8_t *)src);
		src = (const uint8_t *)src + dstofss;
		dst = (uint8_t *)dst + dstofss;
	}
	srcofs = ((uintptr_t)src & 0x0F);

	/**
	 * For aligned copy
	 */
	if (srcofs == 0) {
		/**
		 * Copy 256-byte blocks
		 */
		for (; n >= 256; n -= 256) {
			rte_mov256((uint8_t *)dst, (const uint8_t *)src);
			dst = (uint8_t *)dst + 256;
			src = (const uint8_t *)src + 256;
		}

		/**
		 * Copy whatever left
		 */
		goto COPY_BLOCK_255_BACK15;
	}

	/**
	 * For copy with unaligned load
	 */
	MOVEUNALIGNED_LEFT47(dst, src, n, srcofs);

	/**
	 * Copy whatever left
	 */
	goto COPY_BLOCK_64_BACK15;
}
```

对于大于512字节的拷贝，首先对齐目标内存，然后使用256字节块的拷贝方式，如果拷贝量不足256字节，再使用128、64、32、16字节的块进行处理，利用了SSE和AVX指令集的优势。

```c
static __rte_always_inline void
rte_mov64(uint8_t *dst, const uint8_t *src)
{
#if defined __AVX512F__ && defined RTE_MEMCPY_AVX512
	__m512i zmm0;

	zmm0 = _mm512_loadu_si512((const void *)src);
	_mm512_storeu_si512((void *)dst, zmm0);
#else /* AVX2, AVX & SSE implementation */
	rte_mov32((uint8_t *)dst + 0 * 32, (const uint8_t *)src + 0 * 32);
	rte_mov32((uint8_t *)dst + 1 * 32, (const uint8_t *)src + 1 * 32);
#endif
}
```

当编译器检测到支持AVX512指令集时，函数使用 _mm512_loadu_si512 和 _mm512_storeu_si512 指令进行内存拷贝。这些指令可以同时处理512位的数据（即64字节），显著提高了拷贝速度。

在不支持AVX512的情况下，函数退回到使用 rte_mov32，进行32字节的数据拷贝。这个实现同样利用了AVX2/AVX/SSE指令集的并行处理能力，但处理的块大小较小，需要多次调用来完成64字节的拷贝。
