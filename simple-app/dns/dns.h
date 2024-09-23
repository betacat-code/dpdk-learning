#ifndef _DNS_H_
#define _DNS_H_

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_memcpy.h>

#define BUF_SIZE 1500
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

// 解析和构造 DNS 消息头部的字段。
static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x8000;
static const uint32_t RCODE_MASK = 0x000F;

// 响应类型
enum {
    Ok_ResponseType = 0,
    FormatError_ResponseType = 1,
    ServerFailure_ResponseType = 2,
    NameError_ResponseType = 3,
    NotImplemented_ResponseType = 4,
    Refused_ResponseType = 5
};

// 资源记录类型
enum {
    A_Resource_RecordType = 1,
    NS_Resource_RecordType = 2,
    CNAME_Resource_RecordType = 5,
    SOA_Resource_RecordType = 6,
    PTR_Resource_RecordType = 12,
    MX_Resource_RecordType = 15,
    TXT_Resource_RecordType = 16,
    AAAA_Resource_RecordType = 28,
    SRV_Resource_RecordType = 33
};

// 操作码
enum {
    QUERY_OperationCode = 0,
    IQUERY_OperationCode = 1,
    STATUS_OperationCode = 2,
    NOTIFY_OperationCode = 4, 
    UPDATE_OperationCode = 5 
};

// 响应码
enum {
    NoError_ResponseCode = 0,
    FormatError_ResponseCode = 1,
    ServerFailure_ResponseCode = 2,
    NameError_ResponseCode = 3
};

// 查询类型
enum {
    IXFR_QueryType = 251,
    AXFR_QueryType = 252,
    MAILB_QueryType = 253,
    MAILA_QueryType = 254,
    STAR_QueryType = 255
};

struct Question {
    char *qName;        // 问题的域名，例如 "www.example.com"。以字符指针形式存储，DNS 协议要求该名字使用特殊格式。
    uint16_t qType;     // 问题的类型。例如，1 代表 A 记录（IPv4 地址），28 代表 AAAA 记录（IPv6 地址）。
    uint16_t qClass;    // 问题的类。通常为 1，表示互联网类（IN）。
    struct Question* next;  // 指向下一个问题的指针，用于将多个问题组织成链表。因为 DNS 查询可以包含多个问题。
};

union ResourceData {
    struct {
        char *txt_data;  // 文本记录（TXT 记录）中的文本数据。
    } txt_record;
    
    struct {
        uint8_t addr[4];  // A 记录中的 IPv4 地址，4 字节的数组表示。
    } a_record;
    
    struct {
        char* MName;      // SOA 记录中的主域名服务器名称。
        char* RName;      // SOA 记录中的管理员邮箱。
        uint32_t serial;  // SOA 记录的序列号，用于版本控制。
        uint32_t refresh; // SOA 记录的刷新间隔。
        uint32_t retry;   // SOA 记录的重试时间间隔。
        uint32_t expire;  // SOA 记录的过期时间。
        uint32_t minimum; // SOA 记录的最小 TTL（生存时间）。
    } soa_record;
    
    struct {
        char *name;  // NS 记录中指向的名字服务器域名。
    } name_server_record;
    
    struct {
        char name;  // CNAME 记录中的规范名称（Canonical Name），即别名指向的正式名称。
    } cname_record;
    
    struct {
        char *name;  // PTR 记录中的域名，通常用于反向 DNS 查找。
    } ptr_record;
    
    struct {
        uint16_t preference;  // MX 记录中的优先级，值越低优先级越高。
        char *exchange;       // MX 记录中的邮件交换服务器的域名。
    } mx_record;
    
    struct {
        uint8_t addr[16];  // AAAA 记录中的 IPv6 地址，16 字节的数组表示。
    } aaaa_record;
    
    struct {
        uint16_t priority;  // SRV 记录中的优先级。
        uint16_t weight;    // SRV 记录中的权重。
        uint16_t port;      // SRV 记录中的端口号。
        char *target;       // SRV 记录中的目标服务器域名。
    } srv_record;
};

struct ResourceRecord {
    char *name;          // 资源记录的名称（域名）。
    uint16_t type;       //  资源记录的类型（例如 A、NS、MX、AAAA 等）。
    uint16_t rr_class;      // 资源记录的类，通常为 IN 类（1 表示互联网类）。
    uint16_t ttl;        // TTL（生存时间），表示该记录在缓存中保留的时间（以秒为单位）。
    uint16_t rd_length;  // 资源数据的长度，以字节为单位。
    union ResourceData rd_data;  // 资源记录的数据部分，使用上面定义的 ResourceData 联合体表示。
    struct ResourceRecord* next; // 指向下一个资源记录的指针，用于将多个资源记录组织成链表。
};

struct Message {
    uint16_t id;          // 标识符，用于匹配请求和响应。请求和响应的 ID 应相同。
    
    /* 标志位 */
    uint16_t qr;          // 查询/响应标志，0 表示查询，1 表示响应。
    uint16_t opcode;      // 操作码，表示查询类型，0 表示标准查询，1 表示反向查询。
    uint16_t aa;          // 授权回答标志，1 表示响应是来自授权域名服务器。
    uint16_t tc;          // 截断标志，1 表示响应被截断（超出 UDP 数据包大小）。
    uint16_t rd;          // 期望递归标志，1 表示客户端希望服务器执行递归查询。
    uint16_t ra;          // 可用递归标志，1 表示服务器支持递归查询。
    uint16_t rcode;       // 响应码，表示查询的状态，如 0 表示无错误，3 表示域名不存在。
    
    uint16_t qdCount;     // 问题记录数，表示查询中的问题数量。
    uint16_t anCount;     // 回答记录数，表示响应中的回答记录数量。
    uint16_t nsCount;     // 授权记录数，表示授权记录数量。
    uint16_t arCount;     // 附加记录数，表示附加记录数量。
    
    struct Question* questions;         // 指向问题记录的指针，可能有多个问题记录（链表）。
    struct ResourceRecord* answers;     // 指向回答记录的指针，可能有多个回答记录（链表）。
    struct ResourceRecord* authorities; // 指向授权记录的指针，可能有多个授权记录（链表）。
    struct ResourceRecord* additionals; // 指向附加记录的指针，可能有多个附加记录（链表）。
};


void add_A_record(const char* domain_name, const uint8_t ip[4]);

void add_AAAA_record(const char* domain_name, const uint8_t ip[16]);

int get_A_record(uint8_t addr[4], const char domain_name[]);

int get_AAAA_record(uint8_t addr[16], const char domain_name[]);

void print_hex(uint8_t* buf, size_t len);

void print_resource_record(struct ResourceRecord* rr);

void print_query(struct Message* msg);

size_t get16bits(const uint8_t** buffer);

void put8bits(uint8_t** buffer, uint8_t value);

void put16bits(uint8_t** buffer, uint16_t value);

void put32bits(uint8_t** buffer, uint32_t value);

char* decode_domain_name(const uint8_t **buf, size_t len);

void encode_domain_name(uint8_t** buffer, const char* domain);

void decode_header(struct Message* msg, const uint8_t** buffer);

void encode_header(struct Message* msg, uint8_t** buffer);

int decode_msg(struct Message* msg, const uint8_t* buffer, int size);

void resolver_process(struct Message* msg);

int encode_resource_records(struct ResourceRecord* rr, uint8_t** buffer);

int encode_msg(struct Message* msg, uint8_t** buffer);

void free_resource_records(struct ResourceRecord* rr);

void free_questions(struct Question* qq);


#endif