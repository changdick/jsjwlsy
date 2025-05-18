#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // 检查数据长度
    if(buf->len < sizeof(ip_hdr_t)) {
        return;  //直接丢弃
    }
    // 报头检查
    // 仿照之前实验，要操纵ip报头来检查，需要申请一个IP头类型的指针，用这个指针类型来解析buf的data段。其实buf->data就是一个指针，但是没有准确的类型
    ip_hdr_t * ip_header = (ip_hdr_t *)buf->data;
    uint16_t ip_hdr_len = ip_header->hdr_len * IP_HDR_LEN_PER_BYTE;
    // ip报头内容检查
    // 包括： 版本号是否为IPv4，总长度字段是否相遇等于数据包长度
    if (ip_header->version == IP_VERSION_4 && swap16(ip_header->total_len16) <= buf->len) {
        // 版本号和总长度都正确
        
        // 储存校验和
        uint16_t checksum_tmp = ip_header->hdr_checksum16; 
        // 计算校验和
        ip_header->hdr_checksum16 = 0;  // 先清空校验和
        uint16_t checksum = checksum16((uint16_t*)ip_header, sizeof(ip_hdr_t));  // 计算校验和   //按照我们的代码，首部长度是写死的。但是按理说应该用首部中的首部长度字段
        //对比
        if (checksum != checksum_tmp){
            return; // 校验和不相等丢弃

        } 

        ip_header->hdr_checksum16 = checksum_tmp;
        
        // 处理数据包
        // 对比ip地址,这是数组，应用memcmp
        if (memcmp(ip_header->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
            // 如果不是本机的ip地址
            return;  //丢弃
        } 
        
        // 去除填充
        // 对比包的总长度和ip头部的总长度
        if(buf->len > swap16(ip_header->total_len16)) {
            // 说明有填充字段
            buf_remove_padding(buf, buf->len - swap16(ip_header->total_len16));
        }

        // 去掉报头
        buf_remove_header(buf, sizeof(ip_hdr_t));  // 去除ip头部

        int netinret = net_in(buf, ip_header->protocol, ip_header->src_ip);  // 调用net_in函数处理上层协议  // 为什么第三个参数是src_mac? 
        if(netinret == -1) {
            // 如果没有处理程序，丢弃
            
            buf_add_header(buf, sizeof(ip_hdr_t));
            icmp_unreachable(buf, ip_header->src_ip, ICMP_CODE_PROTOCOL_UNREACH);  // 发送不可达
        }
            
    }

}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO

    // 这个函数需要设置完整的ip头部内容。如果内容有误就会出错
    // 经过调试确定 2B的总长度字段要大小端转换， 标志与分段的16bit也要大小端转换

    // 申请一个ip头部
    buf_add_header(buf, sizeof(ip_hdr_t));  // 添加ip头部
    // 填写头部
    ip_hdr_t * ip_header = (ip_hdr_t *)buf->data;
    ip_header->version = IP_VERSION_4;
    ip_header->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;  // 头部长度
    ip_header->tos = 0;  // 服务类型
    ip_header->total_len16 = swap16(buf->len);  // 总长度 大小端转换是要的
    ip_header->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | (offset / IP_HDR_OFFSET_PER_BYTE));  // 标志与分段
    ip_header->id16 = swap16(id);  // 标识符

    ip_header->ttl = IP_DEFALUT_TTL;  // 存活时间
    ip_header->protocol = protocol;  // 上层协议
    memcpy(ip_header->dst_ip, ip, NET_IP_LEN);  // 目标ip地址
    memcpy(ip_header->src_ip, net_if_ip, NET_IP_LEN);  // 源ip地址
    ip_header->hdr_checksum16 = 0;
    uint16_t checksum = checksum16((uint16_t*)ip_header, sizeof(ip_hdr_t));  // 计算校验和
    ip_header->hdr_checksum16 = checksum;  // 设置校验和
    arp_out(buf, ip);  // 调用arp_out函数发送
}  


/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    // 这个buf是上层下来的，没有ip头的。ip头在 fragmentout函数才装
    static uint16_t ip_id = 0;
    uint16_t current_id = ip_id++;
    // 检查上层下来的包长度
    if(buf->len > ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)) {
        // 包长超过了Ip协议最大负载长（1480） 需要分片

        // 为了分片，可以直接操纵 buf的data部分
        uint8_t * data_ptr = buf->data;  // 用data_ptr 直接遍历数据部分
        size_t remain_data = buf->len;  // 剩余数据长度
        int offset = 0;  // 偏移用于标记传给ip_header的偏移量
        size_t current_data_size = 0;
        while (remain_data > 1480) {
            current_data_size = 1480;
            // 创建新缓冲区
            buf_t ip_buf = {0};
            buf_init(&ip_buf, current_data_size);  // 创建新的buf
            memcpy(ip_buf.data, data_ptr, current_data_size);  // 拷贝数据
            
            ip_fragment_out(&ip_buf, ip, protocol, current_id, offset, 1);  // 发送分片

            offset += current_data_size;
            remain_data -= current_data_size;
            data_ptr += current_data_size;  // 移动指针
        }
        
         // 处理最后一个分片
        current_data_size = remain_data; 
        buf_t ip_buf = {0};
        buf_init(&ip_buf, current_data_size);  // 创建新的buf
        memcpy(ip_buf.data, data_ptr, remain_data);  // 拷贝数据
        if (remain_data % 8 != 0) {
            // 计算需要填充的字节数
            int padding = 8 - (remain_data % 8);
            // 填充数据
            buf_add_padding(&ip_buf, padding);
        }
        
        // 发送最后一个分片
        ip_fragment_out(&ip_buf, ip, protocol, current_id, offset, 0);

        
    } else {
        // 直接调用ip_fragment_out发
        ip_fragment_out(buf, ip, protocol,current_id  ,0, 0);  // id16是ip头部的id
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}
