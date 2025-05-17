#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // TO-DO
    // 初始化buf 这是个icmp包
    buf_init(&txbuf, sizeof(icmp_hdr_t) + req_buf->len - sizeof(icmp_hdr_t));   // 按理说是 icmp头 加上 请求包的数据
    icmp_hdr_t * icmp_header = (icmp_hdr_t*)txbuf.data;
    icmp_header->type = ICMP_TYPE_ECHO_REPLY; //type为回显响应
    icmp_header->code = 0; // code为0
    icmp_header->checksum16 = 0; // 校验和先清空
    // id:如果是ICMP应答报文，则只需拷贝来自ICMP请求报文的标识符字段；
    icmp_hdr_t * icmp_header_req = (icmp_hdr_t*)req_buf->data;
    icmp_header->id16 = icmp_header_req->id16; // id
    //  seq 如果是ICMP应答报文，则只需拷贝来自ICMP请求报文的序列号字段；
    icmp_header->seq16 = icmp_header_req->seq16;

    // 后面搭载的数据部分拷贝自req buf
    memcpy(txbuf.data + sizeof(icmp_hdr_t), req_buf->data + sizeof(icmp_hdr_t), req_buf->len - sizeof(icmp_hdr_t));

    // icmp 校验和是全部的校验和
    uint16_t checksum = checksum16(txbuf.data, txbuf.len);  // 计算校验和

    icmp_header->checksum16 = checksum;  // 设置校验和

    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);  // 发送icmp响应


}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    // 检查数据长度
    if (buf->len < sizeof(icmp_hdr_t)) {
        return;  //直接丢弃
    }
    // 查看ICMP类型。要解释ICMp头部，就要把buf的data解读为icmp头类型的
    icmp_hdr_t * icmp_header = (icmp_hdr_t *)buf->data;

    uint8_t type = icmp_header->type;
    uint8_t code = icmp_header->code;

    // 看是不是回显
    if (type == ICMP_TYPE_ECHO_REQUEST)
        icmp_resp(buf, src_ip);  // 回显请求，发送响应
    
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    // 初始化buf 这是个icmp包
    buf_init(&txbuf, sizeof(icmp_hdr_t) + 28);   // 按理说是 icmp头 加上 ip数据包的头和8字节数据部分，这边直接用28了

    icmp_hdr_t * icmp_header = (icmp_hdr_t*)txbuf.data;

    icmp_header->type = ICMP_TYPE_UNREACH; //type为不可达
    icmp_header->code = code; // code为不可达

    icmp_header->checksum16 = 0; // 校验和先清空

    // 差错报文的id和seq属于未用，必须为0

    icmp_header->id16 = 0; // id
    // memset(&(icmp_header->seq16), 0, 1); // 数字签名，应该不会有人像我这样写吧
    icmp_header->seq16 = 0; // seq

    memcpy(txbuf.data + sizeof(icmp_hdr_t), recv_buf->data, 28); // 直接拷贝数据部分

    // icmp 校验和是全部的校验和
    uint16_t checksum = checksum16(txbuf.data, txbuf.len);  // 计算校验和

    icmp_header->checksum16 = checksum;  // 设置校验和

    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);  // 发送icmp不可达



}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}