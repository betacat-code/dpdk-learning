
# 安装编译netmap

```bash
git clone https://github.com/luigirizzo/netmap
```


进入LINUX目录

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/8d9da68a24554db98a6eff16a1928c70.png)
初始化环境

```bash
./configure
```

需要长时间等待完成，出现以下界面不用担心（需要等半个小时到一个小时）

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/de577c2ebfe04b71988c7955c70dd58f.png)



等待到出现这步就成功了


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/d36fa8c62be746e7b1732d067996c50f.png)
编译和安装

```bash
make && make install
```

会有一路这样的check 需要耐心等待

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2fe299d72254461f99e9e056112444a9.png)

## 编译问题

可能会出现如下，部分变量未初始化的问题。

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4306e4f864e54fc6bcd5c52dfc6e1307.png)
此时需要找到对应Makefile文件，将Mackfile中"CFLAGS += -Werror -Wall -Wunused-function"配置行的-Werror参数删掉。



# 使用netmap


每次使用前都需要insmod netmap.ko ，将编译出来的 netmap 内核模块加载到内核中。

> lsmod 指令可以查看内核已经加载的模块。insmod 指令加载的内核模块在每次内核重启之后都需要重新加载。

然后查看ls /dev/netmap -l，出现下面的设备就说明开启成功了。

```bash
sudo insmod netmap.ko 
ls /dev/netmap -l
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/83bebde8ff7e42758a72482dc1de6a8b.png)


恢复的话就是

```bash
rmmod netmap.ko
```






# 运行测试程序

粘贴了一个别人写的，使用netmap来测试ICMP协议的代码。

```bash
insmod netmap.ko
gcc -o icmp_netmap icmp_netmap.c
```

```cpp
#include <stdio.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
 
#define NETMAP_WITH_LIBS
 
#include <net/netmap_user.h>
#include <string.h>
 
#pragma pack(1)
#define ETH_ADDR_LENGTH 6
#define PROTO_IP 0x0800
#define PROTO_ARP 0x0806
#define PROTO_RARP    0x0835
#define PROTP_UDP 17
#define PROTO_ICMP    1
 
struct ethhdr {
    unsigned char h_dst[ETH_ADDR_LENGTH];//目地MAC地址
    unsigned char h_src[ETH_ADDR_LENGTH];//源MAC地址
    unsigned short h_proto;//类型
};
 
struct iphdr {
    unsigned char hdrlen: 4,	//版本
            version: 4;			//首部长度
    unsigned char tos;			//服务类型
    unsigned short totlen;		//总长度
    unsigned short id;			//标识
    unsigned short flag_offset;  //片偏移
    unsigned char ttl;			//生存时间（TTL）
    unsigned char type;			//协议
    unsigned short check;		//首部检验和
    unsigned int sip;			//源IP地址
    unsigned int dip;			//目的IP地址
};
 
struct ippkt {
    struct ethhdr eh; //14
    struct iphdr ip; //20
};
 
struct udphdr {
    unsigned short sport;		//源端口
    unsigned short dport;		//目的端口
    unsigned short length;		//封包长度
    unsigned short check;		//校验和
};
 
struct udppkt {	
    struct ethhdr eh; //14
    struct iphdr ip; //20
    struct udphdr udp;//8
    unsigned char data[0];
};
 
struct arphdr {
    unsigned short h_type;		//硬件类型
    unsigned short h_proto;		//协议类型
 
    unsigned char h_addrlen;	//硬件长度
    unsigned char h_protolen;	//协议长度
 
    unsigned short oper;		//操作码 ARP请求（1），ARP响应（2）
 
    unsigned char smac[ETH_ADDR_LENGTH];	//源硬件地址
    unsigned int sip;						//源逻辑地址
    unsigned char dmac[ETH_ADDR_LENGTH];	//目的硬件地址
    unsigned int dip;						//目的逻辑地址
};
 
struct arppkt {
    struct ethhdr eh;
    struct arphdr arp;
};
 
 
int str2mac(char *mac, char *str) {
    char *p = str;
    unsigned char value = 0x0;
    int i = 0;
    while (p != '\0') {
        if (*p == ':') {
            mac[i++] = value;
            value = 0x0;
        }
        else {
            unsigned char temp = *p;
            if (temp <= '9' && temp >= '0') {
                temp -= '0';
            }
            else if (temp <= 'f' && temp >= 'a') {
                temp -= 'a';
                temp += 10;
            }
            else if (temp <= 'F' && temp >= 'A') {
                temp -= 'A';
                temp += 10;
            }
            else {
                break;
            }
            value <<= 4;
            value |= temp;
        }
        p++;
    }
    mac[i] = value;
    return 0;
}
 
void echo_udp_pkt(struct udppkt *udp, struct udppkt *udp_rt) {
    memcpy(udp_rt, udp, sizeof(struct udppkt));
    memcpy(udp_rt->eh.h_dst, udp->eh.h_src, ETH_ADDR_LENGTH);
    memcpy(udp_rt->eh.h_src, udp->eh.h_dst, ETH_ADDR_LENGTH);
    udp_rt->ip.sip = udp->ip.dip;
    udp_rt->ip.dip = udp->ip.sip;
    udp_rt->udp.sport = udp->udp.dport;
    udp_rt->udp.dport = udp->udp.sport;
}
 
 
void echo_arp_pkt(struct arppkt *arp, struct arppkt *arp_rt, char *mac) {
    memcpy(arp_rt, arp, sizeof(struct arppkt));
    memcpy(arp_rt->eh.h_dst, arp->eh.h_src, ETH_ADDR_LENGTH);//以太网首部填入目的 mac
    str2mac(arp_rt->eh.h_src, mac);//以太网首部填入源mac
    arp_rt->eh.h_proto = arp->eh.h_proto;//以太网协议还是arp协议
    arp_rt->arp.h_addrlen = 6;
    arp_rt->arp.h_protolen = 4;
    arp_rt->arp.oper = htons(2); // ARP响应
    str2mac(arp_rt->arp.smac, mac);//arp报文填入源mac 
    arp_rt->arp.sip = arp->arp.dip; // arp报文填入发送端 ip
    memcpy(arp_rt->arp.dmac, arp->arp.smac, ETH_ADDR_LENGTH);//arp报文填入目的 mac 
    arp_rt->arp.dip = arp->arp.sip; // arp报文填入目的 ip
}
 
 
struct icmphdr {
    unsigned char type;	//类型 ping请求是8，ping回应是0
    unsigned char code;	//代码（Code）：4位，标明报文的类型。ping的代码为0
    unsigned short check; //校验和
    unsigned short identifier;	//标识符
    unsigned short seq;			//序号
    unsigned char data[32];		//选项数据
};
 
struct icmppkt {
    struct ethhdr eh;
    struct iphdr ip;
    struct icmphdr icmp;
};
 
unsigned short in_cksum(unsigned short *addr, int len) {
    register int nleft = len;
    register unsigned short *w = addr;
    register int sum = 0;
    unsigned short answer = 0;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}
 
void echo_icmp_pkt(struct icmppkt *icmp, struct icmppkt *icmp_rt) {
    memcpy(icmp_rt, icmp, sizeof(struct icmppkt));
    icmp_rt->icmp.type = 0x0; //
    icmp_rt->icmp.code = 0x0; //
    icmp_rt->icmp.check = 0x0;
    icmp_rt->ip.sip = icmp->ip.dip;
    icmp_rt->ip.dip = icmp->ip.sip;
    memcpy(icmp_rt->eh.h_dst, icmp->eh.h_src, ETH_ADDR_LENGTH);
    memcpy(icmp_rt->eh.h_src, icmp->eh.h_dst, ETH_ADDR_LENGTH);
    icmp_rt->icmp.check = in_cksum((unsigned short *) &icmp_rt->icmp, sizeof(struct icmphdr));
}
 
int main() {
    struct nm_pkthdr h;
    //这里换成自己的网卡
    struct nm_desc *nmr = nm_open("netmap:ens33", NULL, 0, NULL);
    if (nmr == NULL) {
        return -1;
    }
    printf("open ens33 seccess\n");
    struct pollfd pfd = {0};
    pfd.fd = nmr->fd;
    pfd.events = POLLIN;
	
    while (1) {
        printf("new data coming!\n");
        int ret = poll(&pfd, 1, -1);
        if (ret < 0) {
            continue;
        }
		
        if (pfd.revents & POLLIN) {
            unsigned char *stream = nm_nextpkt(nmr, &h);
            struct ethhdr *eh = (struct ethhdr *) stream;
            if (ntohs(eh->h_proto) == PROTO_IP) {
                struct ippkt *iph=(struct ippkt *)stream;
                if (iph->ip.type == PROTP_UDP) {
                    struct udppkt *udp = (struct udppkt *) stream;
                    int udplength = ntohs(udp->udp.length);
                    udp->data[udplength - 8] = '\0';
                    printf("udp ---> %s\n", udp->data);
                    struct udppkt udp_rt;
                    echo_udp_pkt(udp, &udp_rt);
                    nm_inject(nmr, &udp_rt, sizeof(struct udppkt));
                }
				else if (iph->ip.type == PROTO_ICMP) {
                    struct icmppkt *icmp = (struct icmppkt *) stream;
                    printf("icmp ---------- --> %d, %x\n", icmp->icmp.type, icmp->icmp.check);
                    if (icmp->icmp.type == 0x08) {
                        struct icmppkt icmp_rt = {0};
                        echo_icmp_pkt(icmp, &icmp_rt);
                        nm_inject(nmr, &icmp_rt, sizeof(struct icmppkt));
                    }
                }
            }
            else if (ntohs(eh->h_proto) == PROTO_ARP) {
                struct arppkt *arp = (struct arppkt *) stream;
                struct arppkt arp_rt;
                if (arp->arp.dip == inet_addr("192.168.240.130")) {
                    echo_arp_pkt(arp, &arp_rt, "00:0c:29:7b:e4:67");
                    nm_inject(nmr, &arp_rt, sizeof(arp_rt));
                    printf("arp ret\n");
                }
            }
			
        }
    }
    nm_close(nmr);
}
```


使用ifconfig看下自己Linux的网络地址，直接用物理机ping即可。

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/beecc4d07f73486c9ac6b0619a3b73b1.png)

