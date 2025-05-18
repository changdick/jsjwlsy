#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    // step1 包长度检查
    if (buf->len < sizeof(udp_hdr_t)) {
        return;
    }
    udp_hdr_t * udp_hdr = (udp_hdr_t *)buf->data;
    if (buf->len < swap16(udp_hdr->total_len16)) {
        return;
    }
    // step2 校验和验证
    uint16_t checksum_temp = udp_hdr->checksum16;
    udp_hdr->checksum16 = 0;
    uint16_t checksunn = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip); //源和目的ip没有办法在这一层的包数据中得到；
    if(checksunn != checksum_temp) {
        return;  // 校验和不匹配  // debug：为什么校验和一定不一样？
    }
    udp_hdr->checksum16 = checksum_temp;
    // step3 回调函数
    uint16_t dst_port = swap16(udp_hdr->dst_port16);
    udp_handler_t * handler = map_get(&udp_table, &dst_port);
    if(handler) {
        // 调用注册的处理函数
        buf_remove_header(buf , sizeof(udp_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, swap16(udp_hdr->src_port16));  // 调用处理函数
     
    } else {
        // 未找到处理函数的情况
        // 增加ip头部
        buf_add_header(buf, sizeof(ip_hdr_t)); // 值应该不用设置。因为buf本身是下层处理函数 ip_in传上来的，所以把头部长度加回来就恢复成本来的ip报
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);  // 发送不可达
       
    }

}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // TO-DO
    // 这个包buf是udp_send函数来的，udp_send应该是更高层调用的。buf里面仅有数据部分
    
    // step1 加首部
    buf_add_header(buf, sizeof(udp_hdr_t));   
    // step2 设置首部的值
    udp_hdr_t * udp_hdr = (udp_hdr_t *)buf->data;
    udp_hdr->src_port16 = swap16(src_port);
    udp_hdr->dst_port16 = swap16(dst_port);
    udp_hdr->total_len16 = swap16(buf->len);
    udp_hdr->checksum16 = 0;  //校验和先置为0
    // step3 调用计算校验和
    uint16_t checksunn = transport_checksum(NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);
    udp_hdr->checksum16 = checksunn;

    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);  // 调用ip_out函数
    
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}