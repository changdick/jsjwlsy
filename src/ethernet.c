#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // TO-DO
    // 检查长度
    if(buf->len < sizeof(ether_hdr_t)) {
        // 如果数据长度小于以太网头部长度直接丢弃不处理
        return;
    }
    // 进行处理
    // 解读头部
    ether_hdr_t * hdr = (ether_hdr_t*)buf->data;
    net_protocol_t protocol = swap16(hdr->protocol16);

    buf_remove_header(buf, sizeof(ether_hdr_t));  // 去除以太网头部
    net_in(buf, protocol, hdr->src);  // 调用net_in函数处理上层协议
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // TO-DO

    // 检查数据长度,如数据长度不足46（最小数据长）需要补
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }

    // 添加以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;     // 申请一个指针，hdr，hdr的值是把buf->data这个指针转类型赋值的。这个hdr其实就是用(ether_hdr_t *) 来解读buf->data这个指针。使得buf->data所指的这接下来14B空间，可以通过hdr来操控。
    // 接下来可以通过过hdr指针直接设置以太网头内容。
    
    memcpy(hdr->dst, mac, NET_MAC_LEN);  // 设置目标MAC地址
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN); 
    hdr->protocol16 = swap16(protocol);

    driver_send(buf);  //调用发送
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
