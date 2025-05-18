#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO

    // 如果我们需要发包，就应该用发送缓冲区，先初始化成一个arp包
    
    buf_init(&txbuf, sizeof(arp_pkt_t));
    // arp协议是直接生成整个报文。
    // 声明一个指针arp_pkt_t型的直接操纵数据区
    arp_pkt_t* arp_pkt = (arp_pkt_t*)txbuf.data;
    // 无回报ARP包（ARP announcement） ：是一种用于向局域网（LAN）宣告本机要使用某个 IP 地址的数据包，它是一个 Sender IP 和 Target IP 都填充为本机 IP 地址的 ARP request。
    // 填写包内容。注意参考标注的初始包填写。
    arp_pkt->hw_len = arp_init_pkt.hw_len;
    arp_pkt->pro_len = arp_init_pkt.pro_len;
    arp_pkt->hw_type16 = arp_init_pkt.hw_type16;
    arp_pkt->pro_type16 = arp_init_pkt.pro_type16;
    memcpy(arp_pkt->sender_mac, arp_init_pkt.sender_mac, NET_MAC_LEN);
    memcpy(arp_pkt->sender_ip, arp_init_pkt.sender_ip, NET_IP_LEN);
    // 设置接收方mac和ip。由于是广播包，mac应为全1. 无回报arp包，目的ip也是自己的ip
    // memset(arp_pkt->target_mac, 0xff, NET_MAC_LEN);  以太网协议定义了广播包地址
    // memcpy(arp_pkt->target_mac, ether_broadcast_mac, NET_MAC_LEN);
    memcpy(arp_pkt->target_mac, arp_init_pkt.target_mac, NET_MAC_LEN);   // 参考报文内容填的全0，因为我们根本不知道目标mac
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);         //设置目标ip。对于初始化那个广播包，调用的时候填的是自己的ip，这里就填成自己的
    arp_pkt->opcode16 = swap16(ARP_REQUEST);

    // 调用ethernet_out发送数据包
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t* arp_pkt = (arp_pkt_t*)txbuf.data;
    arp_pkt->hw_len = arp_init_pkt.hw_len;
    arp_pkt->pro_len = arp_init_pkt.pro_len;
    arp_pkt->hw_type16 = arp_init_pkt.hw_type16;
    arp_pkt->pro_type16 = arp_init_pkt.pro_type16;
    memcpy(arp_pkt->sender_mac, arp_init_pkt.sender_mac, NET_MAC_LEN);
    memcpy(arp_pkt->sender_ip, arp_init_pkt.sender_ip, NET_IP_LEN);

    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);   // 参考报文内容填的全0，因为我们根本不知道目标mac
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);         //设置目标ip。对于初始化那个广播包，调用的时候填的是自己的ip，这里就填成自己的
    arp_pkt->opcode16 = swap16(ARP_REPLY);

    // 调用ethernet_out发送数据包
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);

}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // 检查数据长度
    if (buf->len < sizeof(arp_pkt_t)) {
        return;  //直接丢弃
    } 
    // 报头检查 
    arp_pkt_t * arp_pkt = (arp_pkt_t*)buf->data; 
    if (arp_pkt->hw_type16 == arp_init_pkt.hw_type16)   //ARP 报头的硬件类型  
        if (arp_pkt->pro_type16 == arp_init_pkt.pro_type16)  //上层协议类型
            if(arp_pkt->hw_len == arp_init_pkt.hw_len) //MAC 硬件地址长度
                if(arp_pkt->pro_len == arp_init_pkt.pro_len)  //IP 协议地址长度
                    if(arp_pkt->opcode16 == swap16(0x1) || arp_pkt->opcode16 == swap16(2)) {
                        // 所有检查通过
                        // map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);  // 设置arp表
                        map_set(&arp_table, arp_pkt->sender_ip, src_mac);
                        //调用 map_get() 函数查看该接收报文的 IP 地址是否有对应的 arp_buf 缓存。
                        buf_t* buf = map_get(&arp_buf, arp_pkt->sender_ip);
                        if (buf) {
                            // 有缓存，把缓存包发出去，然后从map中删去
                            ethernet_out(buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);   // 这个数据包是来自IP层的
                            map_delete(&arp_buf, arp_pkt->sender_ip);  // 删除缓存

                        } else {
                            //无缓存，看是不是请求本机

                            // 注意！！！这里比较两个ip地址相等，得用memcmp函数，原本写 == 的比较方法调试半天
                            if (arp_pkt->opcode16 == swap16(ARP_REQUEST) && memcmp(arp_pkt->target_ip, arp_init_pkt.sender_ip, NET_IP_LEN) == 0) {
                                // arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);  // 如果是请求本机的，发送响应
                                arp_resp(arp_pkt->sender_ip, src_mac); 
                            }

                        }
                    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    // map是每个协议自己有自己的map

    uint8_t * mac;
    mac = (uint8_t*)map_get(&arp_table, ip);  // 查表
    // 根据结果是否查到
    if (mac) {
        ethernet_out(buf, mac, NET_PROTOCOL_IP);  // 如果查到，直接发送
    } else if (map_get(&arp_buf, ip)) {
        // 如果查buf表有包，此时不能再发送 ARP 请求
        return;
    } else {
        // 否则则调用 map_set() 函数将来自 IP 层的数据包缓存到 arp_buf 中，
        // 然后调用 arp_req() 函数，发送一个请求目标 IP 地址对应的 MAC 地址的 ARP request 报文。
        map_set(&arp_buf, ip, buf);  // 设置buf表
        arp_req(ip);
    }

}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}