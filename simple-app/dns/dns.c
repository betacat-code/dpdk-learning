#include "dns.h"

// 定义哈希表的结构，用于存储域名和 IPv4 地址
typedef struct {
    char domain_name[256];
    uint8_t ip[4];
} A_Record;

// 定义哈希表的结构，用于存储域名和 IPv6 地址
typedef struct {
    char domain_name[256];
    uint8_t ip[16];
} AAAA_Record;

// 定义全局变量来存储 A 记录和 AAAA 记录
#define MAX_RECORDS 100
A_Record a_records[MAX_RECORDS];
AAAA_Record aaaa_records[MAX_RECORDS];
int a_record_count = 0;
int aaaa_record_count = 0;

// 添加 A 记录（IPv4）
void add_A_record(const char* domain_name, const uint8_t ip[4]) {
    if (a_record_count < MAX_RECORDS) {
        strncpy(a_records[a_record_count].domain_name, domain_name, 256);
        memcpy(a_records[a_record_count].ip, ip, 4);
        a_record_count++;
    } else {
        printf("A 记录表已满！\n");
    }
}

// 添加 AAAA 记录（IPv6）
void add_AAAA_record(const char* domain_name, const uint8_t ip[16]) {
    if (aaaa_record_count < MAX_RECORDS) {
        strncpy(aaaa_records[aaaa_record_count].domain_name, domain_name, 256);
        memcpy(aaaa_records[aaaa_record_count].ip, ip, 16);
        aaaa_record_count++;
    } else {
        printf("AAAA 记录表已满！\n");
    }
}

// 获取 A 记录（IPv4）
int get_A_record(uint8_t addr[4], const char domain_name[]) {
    for (int i = 0; i < a_record_count; i++) {
        if (strcmp(a_records[i].domain_name, domain_name) == 0) {
            memcpy(addr, a_records[i].ip, 4);
            return 0;
        }
    }
    return -1; // 未找到匹配的域名
}

// 获取 AAAA 记录（IPv6）
int get_AAAA_record(uint8_t addr[16], const char domain_name[]) {
    for (int i = 0; i < aaaa_record_count; i++) {
        if (strcmp(aaaa_records[i].domain_name, domain_name) == 0) {
            memcpy(addr, aaaa_records[i].ip, 16);
            return 0;
        }
    }
    return -1; // 未找到匹配的域名
}

void print_hex(uint8_t* buffer, size_t length) {
    printf("%zu bytes:\n", length);
    for (size_t index = 0; index < length; ++index)
        printf("%02x ", buffer[index]);
    printf("\n");
}

void print_resource_record(struct ResourceRecord* resource_record) {
    while (resource_record) {
        printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rd_length %u, ",
            resource_record->name,
            resource_record->type,
            resource_record->rr_class,
            resource_record->ttl,
            resource_record->rd_length
        );

        union ResourceData *resource_data = &resource_record->rd_data;
        switch (resource_record->type) {
            case A_Resource_RecordType:
                printf("Address Resource Record { address ");
                for (int i = 0; i < 4; ++i)
                    printf("%s%u", (i ? "." : ""), resource_data->a_record.addr[i]);
                printf(" }");
                break;
            case NS_Resource_RecordType:
                printf("Name Server Resource Record { name %s }",
                    resource_data->name_server_record.name
                );
                break;
            case CNAME_Resource_RecordType:
                printf("Canonical Name Resource Record { name '%s' }",
                    resource_data->cname_record.name
                );
                break;
            case SOA_Resource_RecordType:
                printf("SOA Record { MName '%s', RName '%s', serial %u, refresh %u, retry %u, expire %u, minimum %u }",
                    resource_data->soa_record.MName,
                    resource_data->soa_record.RName,
                    resource_data->soa_record.serial,
                    resource_data->soa_record.refresh,
                    resource_data->soa_record.retry,
                    resource_data->soa_record.expire,
                    resource_data->soa_record.minimum
                );
                break;
            case PTR_Resource_RecordType:
                printf("Pointer Resource Record { name '%s' }",
                    resource_data->ptr_record.name
                );
                break;
            case MX_Resource_RecordType:
                printf("Mail Exchange Record { preference %u, exchange '%s' }",
                    resource_data->mx_record.preference,
                    resource_data->mx_record.exchange
                );
                break;
            case TXT_Resource_RecordType:
                printf("Text Resource Record { txt_data '%s' }",
                    resource_data->txt_record.txt_data
                );
                break;
            case AAAA_Resource_RecordType:
                printf("AAAA Resource Record { address ");
                for (int i = 0; i < 16; ++i)
                    printf("%s%02x", (i ? ":" : ""), resource_data->aaaa_record.addr[i]);
                printf(" }");
                break;
            default:
                printf("Unknown Resource Record { ??? }");
        }
        printf(" }\n");
        resource_record = resource_record->next;
    }
}



void print_query(struct Message* message) {
    printf("QUERY { ID: %02x", message->id);
    printf(". FIELDS: [ QR: %u, OpCode: %u ]", message->qr, message->opcode);
    printf(", QDcount: %u", message->qdCount);
    printf(", ANcount: %u", message->anCount);
    printf(", NScount: %u", message->nsCount);
    printf(", ARcount: %u,\n", message->arCount);

    struct Question* question = message->questions;
    while (question) {
        printf("  Question { qName '%s', qType %u, qClass %u }\n",
            question->qName,
            question->qType,
            question->qClass
        );
        question = question->next;
    }

    print_resource_record(message->answers);
    print_resource_record(message->authorities);
    print_resource_record(message->additionals);

    printf("}\n");
}

// 网络序到主机序
size_t get16bits(const uint8_t** buffer) {
    uint16_t value;
    rte_memcpy(&value, *buffer, sizeof(uint16_t));
    *buffer += 2;
    return rte_be_to_cpu_16(value);
}

// 主机到网络
void put8bits(uint8_t** buffer, uint8_t value) {
    rte_memcpy(*buffer, &value, sizeof(uint8_t));
    *buffer += sizeof(uint8_t);
}

void put16bits(uint8_t** buffer, uint16_t value) {
    uint16_t net_value = rte_cpu_to_be_16(value);
    rte_memcpy(*buffer, &net_value, sizeof(uint16_t));
    *buffer += sizeof(uint16_t);
}

void put32bits(uint8_t** buffer, uint32_t value) {
    uint32_t net_value = rte_cpu_to_be_32(value); 
    rte_memcpy(*buffer, &net_value, sizeof(uint32_t));
    *buffer += sizeof(uint32_t);
}

// 示例: "3foo3bar3com0" => "foo.bar.com"
// 返回解码后域名的字符串，解码失败返回 NULL
char *decode_domain_name(const uint8_t **buf, size_t len) {
    char domain[256];  // 假设最大域名长度为 256
    for (int i = 1; i < MIN(256, len); i += 1) {
        uint8_t c = (*buf)[i];
        if (c == 0) {
            domain[i - 1] = 0;  // 结束域名字符串
            *buf += i + 1;  // 将缓冲区指针移动到域名后
            return strdup(domain);  // 返回域名的副本
        } else if (c <= 63) {
            domain[i - 1] = '.';  // 用点表示标签分隔
        } else {
            domain[i - 1] = c;  // 将字符附加到域名
        }
    }
    return NULL;  // 解码失败返回 NULL
}

// 将域名编码为 DNS 报文中使用的压缩格式
// 示例: "foo.bar.com" => "3foo3bar3com0"
// buffer 指向要写入编码数据的缓冲区的指针的指针
// domain 包含要编码的域名的以 null 结尾的字符串
// 修改了原数据指针的指向
void encode_domain_name(uint8_t** buffer, const char* domain) {
    uint8_t* buf = *buffer;
    const char* beg = domain;
    const char* pos;
    int len = 0;
    int i = 0;
    while ((pos = strchr(beg, '.'))) {
        len = pos - beg;  // 当前标签的长度
        buf[i] = len;  // 存储标签长度
        i += 1;
        memcpy(buf + i, beg, len);  // 复制标签内容
        i += len;
        beg = pos + 1;  // 移动到下一个标签
    }
    len = strlen(domain) - (beg - domain);  // 最后一个标签的长度
    buf[i] = len;  // 存储最后一个标签的长度
    i += 1;
    memcpy(buf + i, beg, len);  // 复制最后一个标签的内容
    i += len;
    buf[i] = 0;  // 域名结束指示符
    i += 1;
    *buffer += i;  // 将缓冲区指针移动到编码后的域名后
}

// msg DNS 消息结构体指针
// buffer 指向包含 DNS 消息的缓冲区的指针的指针
void decode_header(struct Message* msg, const uint8_t** buffer){
    msg->id = get16bits(buffer);
    uint32_t fields = get16bits(buffer);
    msg->qr = (fields & QR_MASK) >> 15;
    msg->opcode = (fields & OPCODE_MASK) >> 11;
    msg->aa = (fields & AA_MASK) >> 10;
    msg->tc = (fields & TC_MASK) >> 9;
    msg->rd = (fields & RD_MASK) >> 8;
    msg->ra = (fields & RA_MASK) >> 7;
    msg->rcode = (fields & RCODE_MASK);
    msg->qdCount = get16bits(buffer);
    msg->anCount = get16bits(buffer);
    msg->nsCount = get16bits(buffer);
    msg->arCount = get16bits(buffer);
}


void encode_header(struct Message* msg, uint8_t** buffer){
    put16bits(buffer, msg->id);
    uint16_t fields = 0;
    fields |= (msg->qr << 15) & QR_MASK;
    fields |= (msg->opcode << 11) & OPCODE_MASK;
    fields |= (msg->aa << 10) & AA_MASK;
    fields |= (msg->tc << 9) & TC_MASK;
    fields |= (msg->rd << 8) & RD_MASK;
    fields |= (msg->ra << 7) & RA_MASK;
    fields |= (msg->rcode) & RCODE_MASK;
    put16bits(buffer, fields);
    put16bits(buffer, msg->qdCount);
    put16bits(buffer, msg->anCount);
    put16bits(buffer, msg->nsCount);
    put16bits(buffer, msg->arCount);
}

/*
 * 解析 DNS 消息
 *
 * Parameters:
 * - msg: 指向保存解析结果的 Message 结构体的指针
 * - buffer: 指向包含 DNS 消息的字节流的指针
 * - size: 消息字节流的大小
 *
 * Returns:
 * - 成功解析返回 0，否则返回 -1
 */
int decode_msg(struct Message* msg, const uint8_t* buffer, int size) {
    
    decode_header(msg, &buffer);
    // 检查是否只包含问题部分
    if (msg->anCount != 0 || msg->nsCount != 0 || msg->arCount != 0) {
        printf("Only questions expected!\n");
        return -1;
    }

    // 解析问题部分
    uint32_t qcount = msg->qdCount;
    struct Question* qs = NULL;

    for (int i = 0; i < qcount; ++i) {
        // 分配内存以存储新的问题
        struct Question* q = malloc(sizeof(struct Question));
        if (q == NULL) {
            perror("Memory allocation failed");
            return -1;
        }

        // 解析域名
        q->qName = decode_domain_name(&buffer, size);
        if (q->qName == NULL) {
            printf("Error decoding domain name for question %d\n", i);
            free(q); // 释放分配的内存
            return -1;
        }

        // 解析问题类型和类
        q->qType = get16bits(&buffer);
        q->qClass = get16bits(&buffer);

        // 将新问题添加到问题链表的开头
        q->next = qs;
        qs = q;
    }

    // 更新消息结构体中的问题链表头指针
    msg->questions = qs;
    return 0;
}

// 处理 DNS 解析请求，生成相应的 DNS 响应消息
// 指向包含 DNS 查询消息的 Message 结构体的指针

void resolver_process(struct Message* msg) {
    struct ResourceRecord* beg; //临时保存 msg->answers的指针
    struct ResourceRecord* rr; // 存储与问题（Question）相匹配的答案数据
    struct Question* q; // 用于下文遍历
    int rc;

    // 设置响应的标志位和响应码
    msg->qr = 1; // 这是一个响应消息
    msg->aa = 1; // 该服务器具有授权回答能力
    msg->ra = 0; // 不支持递归查询
    msg->rcode = Ok_ResponseType; // 响应码默认为正常响应

    // 清空原有的资源记录计数
    msg->anCount = 0;
    msg->nsCount = 0;
    msg->arCount = 0;

    // 遍历每个查询问题并生成相应的资源记录
    q = msg->questions;
    while (q) {
        // 分配内存以存储新的资源记录
        rr = malloc(sizeof(struct ResourceRecord));
        if (rr == NULL) {
            perror("Memory allocation failed");
            return;
        }
        memset(rr, 0, sizeof(struct ResourceRecord));

        // 设置资源记录的基本信息
        rr->name = strdup(q->qName);
        rr->type = q->qType;
        rr->rr_class = q->qClass;
        rr->ttl = 3600; // TTL 设置为 1 小时，单位为秒；0 表示不缓存

        // 根据问题类型填充资源记录数据
        switch (q->qType) {
            case A_Resource_RecordType:
                rr->rd_length = 4;
                rc = get_A_record(rr->rd_data.a_record.addr, q->qName);
                if (rc < 0) {
                    free(rr->name);
                    free(rr);
                    goto next; // 跳转到处理下一个问题
                }
                break;
            case AAAA_Resource_RecordType:
                rr->rd_length = 16;
                rc = get_AAAA_record(rr->rd_data.aaaa_record.addr, q->qName);
                if (rc < 0) {
                    free(rr->name);
                    free(rr);
                    goto next; 
                }
                break;
            /*
            只支持 查询 ipv4 或者 ipv6的
            case NS_Resource_RecordType:
            case CNAME_Resource_RecordType:
            case SOA_Resource_RecordType:
            case PTR_Resource_RecordType:
            case MX_Resource_RecordType:
            case TXT_Resource_RecordType:
            */
            default:
                // 不支持的问题类型，释放资源记录并设置响应码为不支持
                free(rr->name);
                free(rr);
                msg->rcode = NotImplemented_ResponseType;
                printf("Cannot answer question of type %d.\n", q->qType);
                goto next; 
        }

        // 增加响应中的资源记录计数
        msg->anCount++;

        // 将新生成的资源记录添加到响应消息的 answers 链表中
        beg = msg->answers;
        msg->answers = rr;
        rr->next = beg;

        next:
        // 处理下一个问题
        q = q->next;
    }
}

// 将 ResourceRecord 链表中的资源记录编码到 buffer 中
int encode_resource_records(struct ResourceRecord* rr, uint8_t** buffer){
    while (rr){
        // Answer questions by attaching resource sections.
        encode_domain_name(buffer, rr->name);
        put16bits(buffer, rr->type);
        put16bits(buffer, rr->rr_class);
        put32bits(buffer, rr->ttl);
        put16bits(buffer, rr->rd_length);
        switch (rr->type){
            case A_Resource_RecordType:
                for(int i = 0; i < 4; ++i)
                    put8bits(buffer, rr->rd_data.a_record.addr[i]);
                break;
            case AAAA_Resource_RecordType:
                for(int i = 0; i < 16; ++i)
                    put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
                break;
            default:
                fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
            return 1;
        }
        rr = rr->next;
    }
    return 0;
}

// 将 Message 结构体中的数据编码为符合 DNS 消息格式的二进制数据
int encode_msg(struct Message* msg, uint8_t** buffer) {
    struct Question* q;  // 用于遍历问题链表
    int rc;              // 返回编码结果，0表示成功
    encode_header(msg, buffer);

    // 编码所有的 DNS 问题部分 (Questions)
    q = msg->questions;
    while (q) {
        // 编码问题的域名（qName）
        encode_domain_name(buffer, q->qName);
        // 编码问题的类型（qType）和类（qClass）
        put16bits(buffer, q->qType);
        put16bits(buffer, q->qClass);
        // 继续处理下一个问题
        q = q->next;
    }

    // 编码资源记录部分 (Answers, Authorities, Additionals)
    // 依次对 answers, authorities, additionals 部分的资源记录进行编码
    rc = 0; 
    rc |= encode_resource_records(msg->answers, buffer);     // 编码 answers 部分
    rc |= encode_resource_records(msg->authorities, buffer); // 编码 authorities 部分
    rc |= encode_resource_records(msg->additionals, buffer); // 编码 additionals 部分

    // 如果某个资源记录编码失败，rc 会变为非零值，表示出现错误
    return rc;
}



void free_resource_records(struct ResourceRecord* rr){
    struct ResourceRecord* next;
    while (rr) {
        free(rr->name);
        next = rr->next;
        free(rr);
        rr = next;
    }
}

void free_questions(struct Question* qq){
    struct Question* next;
    while (qq) {
        free(qq->qName);
        next = qq->next;
        free(qq);
        qq = next;
    }
}