
# 系统及DPDK版本


系统：Ubuntu 20.04

DPDK：20.11.10

Pktgen-DPDK：22.04.1


> 关于DPDK，其实Ubuntu的软件源中就已经包含了最新的Stable版本的DPDK，如果不想自己编译的话，直接 apt install dpdk 也是可以的

# 安装编译依赖

```bash
sudo apt install build-essential python3-pip python3-pyelftools libnuma-dev libpcap0.8-dev pkg-config
sudo pip3 install meson ninja
```


# 编译dpdk

```bash
wget http://fast.dpdk.org/rel/dpdk-20.11.10.tar.xz
```


解压

```bash
tar -xvf dpdk-20.11.10.tar.xz 
```


进入解压完毕的DPDK源码根目录


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1a643e2c916f4b88b43339e922869739.png)

编译项目

```bash
meson -Dexamples=all build
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/949434cd29f0448b9b73ec8fbf82d6db.png)
到build目录 ，使用ninja编译

```bash
cd build
ninja
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ce2f3a6e74cf48d18c8d750938ff3eb5.png)


```bash
sudo ninja install
sudo ldconfig
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/9715fa5b6fa540749e32e7418a410d3f.png)

# 配置大页内存

```bash
sudo vim /etc/default/grub
```

找到 GRUB_CMDLINE_LINUX 行，大页内存每页大小为2M，一共设置1024页面，即2GB。

```bash
transparent_hugepage=never default_hugepagesz=2M hugepagesz=2M hugepages=1024
```

更新 GRUB 配置，然后重启系统。

```bash
sudo update-grub
reboot
```



验证大页内存

```cpp
cat /proc/meminfo |grep -i HugePages
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/c9fd18ffa0c742afbc5c9322c8e8a741.png)




# 加载网卡驱动

```bash
git clone http://dpdk.org/git/dpdk-kmods
```

编译

```bash
cd dpdk-kmods/linux/igb_uio
make
```

得到igb_uio.ko ，装载内核模块。

```bash
sudo modprobe uio
sudo insmod dpdk-kmods/linux/igb_uio/igb_uio.ko intr_mode=legacy
```

> 注意： 加载驱动时要带着参数intr_mode=legacy，如果不加参数，将会有问题！


# DPDK绑定网口

查看网口信息

```bash
lspci | grep Ethernet
lshw -class network -businfo
usertools/dpdk-devbind.py --status
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/8c5ae7719ac645a79496615299e2f927.png)

绑定网卡之前需要关闭linux下的网卡

```bash
sudo ifconfig ens33 down
```

```bash
sudo dpdk-devbind.py --bind=igb_uio 0000:02:01.0
```

查看状态

```bash
dpdk-devbind.py --status
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f6c84362d7a54b06b3f622eb7733be54.png)

# 测试程序

在  build/examples里运行 dpdk-helloworld

```bash
sudo ./dpdk-helloworld
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/07fc93fd69954a808239a20dbf8ea1dc.png)

> EAL: No available hugepages reported in hugepages-1048576kB

1048576kB 就是1G，这行 log 应该只是一个警告，因为我们根本没设置过 1G 的 hugepage，找不到是预料之中的。

最后出现 hello from core x 就是成功了
