#include "utils.h"

#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief ip转字符串
 *
 * @param ip ip地址
 * @return char* 生成的字符串
 */
char *iptos(uint8_t *ip) {
    static char output[3 * 4 + 3 + 1];
    sprintf(output, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return output;
}

/**
 * @brief mac转字符串
 *
 * @param mac mac地址
 * @return char* 生成的字符串
 */
char *mactos(uint8_t *mac) {
    static char output[2 * 6 + 5 + 1];
    sprintf(output, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return output;
}

/**
 * @brief 时间戳转字符串
 *
 * @param timestamp 时间戳
 * @return char* 生成的字符串
 */
char *timetos(time_t timestamp) {
    static char output[20];
    struct tm *utc_time = gmtime(&timestamp);
    sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d", utc_time->tm_year + 1900, utc_time->tm_mon + 1, utc_time->tm_mday, utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec);
    return output;
}

/**
 * @brief ip前缀匹配
 *
 * @param ipa 第一个ip
 * @param ipb 第二个ip
 * @return uint8_t 两个ip相同的前缀长度
 */
uint8_t ip_prefix_match(uint8_t *ipa, uint8_t *ipb) {
    uint8_t count = 0;
    for (size_t i = 0; i < 4; i++) {
        uint8_t flag = ipa[i] ^ ipb[i];
        for (size_t j = 0; j < 8; j++) {
            if (flag & (1 << 7))
                return count;
            else
                count++, flag <<= 1;
        }
    }
    return count;
}

/**
 * @brief 计算16位校验和
 *
 * @param buf 要计算的数据包
 * @param len 要计算的长度
 * @return uint16_t 校验和
 */
uint16_t checksum16(uint16_t *data, size_t len) {
       uint32_t sum = 0;
    uint16_t word;

    while (len > 1) {
        memcpy(&word, data, 2);  // 安全地从 data 读两个字节
        sum += word;
        data = (uint16_t *)((uint8_t *)data + 2);  // 移动两个字节
        len -= 2;
    }

    if (len == 1) {
        uint8_t last_byte = *(uint8_t *)data;
        sum += last_byte << 8;  // 最后一个字节左移，高位对齐
    }

    // 折叠进位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

#pragma pack(1)
typedef struct peso_hdr {
    uint8_t src_ip[4];     // 源IP地址
    uint8_t dst_ip[4];     // 目的IP地址
    uint8_t placeholder;   // 必须置0,用于填充对齐
    uint8_t protocol;      // 协议号
    uint16_t total_len16;  // 整个数据包的长度
} peso_hdr_t;
#pragma pack()

/**
 * @brief 计算传输层协议（如TCP/UDP）的校验和
 *
 * @param protocol  传输层协议号（如NET_PROTOCOL_UDP、NET_PROTOCOL_TCP）
 * @param buf       待计算的数据包缓冲区
 * @param src_ip    源IP地址
 * @param dst_ip    目的IP地址
 * @return uint16_t 计算得到的16位校验和
 */
uint16_t transport_checksum(uint8_t protocol, buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip) {
    // TO-DO
    // 这边读入的是已经把首部校验和置为0的数据包
    if (protocol == NET_PROTOCOL_UDP) {
        int padflag = 0;
        if(buf->len % 2) {
            buf_add_padding(buf, 1);  // 如果buf的长度是奇数，补齐为偶数
            padflag++;
        }
        // 计算udp校验和
        // 为了加入伪头部，可以申请一个临时缓冲，把buf里的数据拷出来，再填写伪头部字段计算
        uint8_t temp[12 + buf->len]; 
        
        memcpy(temp + 12, buf->data, buf->len);  // 先把数据包拷贝到临时缓冲区
        // 伪头部的结构: | 4B src ip | 4B dest ip |0 1B|protocol 1B |UDP长度 2B|
        
        memcpy(temp, src_ip, 4);  // 拷贝源ip
        memcpy(temp + 4, dst_ip, 4);  // 拷贝目的ip
        memset(temp + 8, 0, 1);  // 填充一个字节为0
        temp[9] = protocol;  // 填充协议号
        memcpy(temp + 10, temp+16, 2);  // 填充udp长度  temp+16就是长度字段

        // 计算校验和
        uint16_t jyh = checksum16((uint16_t *)temp, 12 + buf->len);  // 计算校验和
        if(padflag) {
            buf_remove_padding(buf, 1);

        }
        return jyh;
    } else if (protocol == NET_PROTOCOL_TCP) {
        int padflag = 0;
        // 1. 处理TCP头部长度和数据填充
        // 获取TCP头部长度（HLEN，高4位，单位为4字节）
        uint8_t hlen = (buf->data[12] >> 4) & 0x0F;  // TCP头部前16字节中的第13字节高4位
        uint16_t tcp_total_len = buf->len;  // 总长度 可以直接从buf的len得到

        // 2. 确保总长度为偶数（头部+数据）
        if (tcp_total_len % 2) {
            buf_add_padding(buf, 1);  // 填充1字节0
            padflag++;
        }

        // 3. 构造临时缓冲区（伪头部 + TCP头部 + 数据）
        uint16_t temp_len = 12 + tcp_total_len;  // 伪头部12字节 + TCP总长度
        uint8_t temp[temp_len];

        // 4. 填充伪头部
        memcpy(temp, src_ip, 4);          // 源IP
        memcpy(temp + 4, dst_ip, 4);      // 目的IP
        memset(temp + 8, 0, 1);           // 保留字节置0
        temp[9] = protocol;               // 协议号（TCP=6）
        // 填充TCP总长度（注意：需转换为网络字节序，若原buf中长度为网络序则直接拷贝）
        uint16_t tcp_len_net = swap16(tcp_total_len);   // 这个数据因为tcp头部不存，从buf->len获得，就需要转字节序
        memcpy(temp + 10, &tcp_len_net, 2);           // 填充到伪头部最后2字节

        // 5. 填充TCP头部和数据（头部已置0校验和，需确保校验和字段为0）
        memcpy(temp + 12, buf->data, tcp_total_len);  // 拷贝头部（含置0的校验和）和数据

        // 6. 计算校验和
        uint16_t jyh = checksum16((uint16_t *)temp, temp_len);

        // 7. 移除填充（若有）
        if (padflag) {
            buf_remove_padding(buf, 1);
        }

        return jyh;
    }
    
}