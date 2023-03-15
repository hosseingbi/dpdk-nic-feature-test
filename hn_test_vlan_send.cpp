#include "hn_test_vlan_send.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

hn_test_vlan_send::hn_test_vlan_send(u_int32_t lcore_id)
    :hn_test(lcore_id)
{
    ip_src =  inet_addr(ip_src_start_str.c_str());
    ip_dst =  inet_addr(ip_dst_start_str.c_str());
    src_port = htons(src_port);
    dst_port = htons(dst_port);

    proto = 0x06;
    
    // proto base packet according to ip_proto
    if(proto == 0x06) // tcp
        create_base_pkt_tcp();
    else if(proto == 0x11)
        create_base_pkt_udp();
    else
    {
        std::cerr<<"IP protocol "<< (int)proto<< " is not supported."<<std::endl;
        exit(-1);
    }

}

hn_test_vlan_send::~hn_test_vlan_send()
{}

int hn_test_vlan_send::get_burst_pkts(rte_mbuf **m, u_int32_t max_burst_size, u_int32_t &ret_burst_size, rte_mempool *mempool) 
{
    ret_burst_size = 0;
    for(u_int32_t i=0; i< max_burst_size && round_pkt_counter < round_num_pkts; i++)
    {
        rte_ether_hdr *tx_eth_hdr;
        rte_ipv4_hdr *tx_ip_hdr;
        rte_tcp_hdr *tx_tcp_hdr = NULL;
        rte_udp_hdr *tx_udp_hdr = NULL;

        rte_mbuf *tx_mbuf = rte_pktmbuf_alloc(mempool);
            if(!tx_mbuf)
                continue;

        tx_eth_hdr = rte_pktmbuf_mtod(tx_mbuf, rte_ether_hdr *);
        tx_ip_hdr = (rte_ipv4_hdr *)(tx_eth_hdr + 1);

        if(proto == 0x06) // tcp
            tx_tcp_hdr = (rte_tcp_hdr *)(tx_ip_hdr + 1);
        else if (proto == 0x11) // udp
            tx_udp_hdr = (rte_udp_hdr *)(tx_ip_hdr + 1);
        else
            return -1;

        memcpy((char*)tx_eth_hdr, base_pkt.get(), base_pkt_size);

        // update ip header
        tx_ip_hdr->src_addr = ip_src;
        tx_ip_hdr->dst_addr = ip_dst;
        
        // update transport layer
        if(proto == 0x06) // tcp
        {
            tx_tcp_hdr->src_port = src_port;
            tx_tcp_hdr->dst_port = dst_port;
        }
        else if (proto == 0x11) // udp
        {
            tx_udp_hdr->src_port = src_port;
            tx_udp_hdr->dst_port = dst_port;
        }


        tx_mbuf->l2_len = sizeof(rte_ether_hdr);
        tx_mbuf->l2_type = 1;
        tx_mbuf->l3_len = sizeof(rte_ipv4_hdr);
        tx_mbuf->l3_type = 9;
        tx_mbuf->packet_type = 401;
        tx_mbuf->pkt_len = base_pkt_size;
        tx_mbuf->data_len = tx_mbuf->pkt_len;
        tx_mbuf->nb_segs = 1;
        if(proto == 0x06) // tcp
        {
            tx_mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
            tx_tcp_hdr->cksum = rte_ipv4_phdr_cksum(tx_ip_hdr, tx_mbuf->ol_flags);
        }
        else if(proto == 0x11) // udp
        {
            tx_mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM;
            tx_udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(tx_ip_hdr, tx_mbuf->ol_flags);
        }

        m[ret_burst_size++] = tx_mbuf;
        round_pkt_counter++;
        update_steps();
    }

    if(round_pkt_counter == round_num_pkts)
    {
        round_pkt_counter = 0;
        round_counter++;

        if(round_counter == num_of_rounds)
            return 0; // call it end of the test
    }

    return 1;
}

int hn_test_vlan_send::process_rx_burst_pkts(__rte_unused rte_mbuf **m, __rte_unused u_int32_t size, __rte_unused u_int32_t queue_id) 
{
    return 0;
}

void hn_test_vlan_send::show_the_test_results() 
{
    std::cout<<"Test is done!!!"<<std::endl;
}

void hn_test_vlan_send::create_base_pkt_tcp()
{
    rte_ether_hdr *tx_eth_hdr;
    rte_ipv4_hdr *tx_ip_hdr;
    rte_tcp_hdr *tx_tcp_hdr;
    char *tx_payload;

    u_int8_t tcp_header_size = sizeof(rte_tcp_hdr);

    u_int32_t payload_size = 200;
    u_int32_t tmp_send_seq = rand();
    u_int32_t tmp_rcv_ack = rand();

    base_pkt = std::shared_ptr<char>(new char[sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + tcp_header_size + payload_size], std::default_delete<char[]>());

    tx_eth_hdr = (rte_ether_hdr *)base_pkt.get();
    tx_ip_hdr = (rte_ipv4_hdr *)(tx_eth_hdr + 1);
    tx_tcp_hdr = (rte_tcp_hdr *)(tx_ip_hdr + 1);
    tx_payload = ((char*)tx_tcp_hdr + tcp_header_size);

    // filling eth header
    rte_memcpy(&tx_eth_hdr->src_addr, &src_mac_addr, sizeof(rte_ether_addr));
    rte_memcpy(&tx_eth_hdr->dst_addr, &dst_mac_addr, sizeof(rte_ether_addr));
    tx_eth_hdr->ether_type = htons(0x0800);

    // filling ip_header
    tx_ip_hdr->version_ihl = 0x45;
    tx_ip_hdr->type_of_service = 0x00;
    tx_ip_hdr->total_length = htons(sizeof(rte_ipv4_hdr) + tcp_header_size + payload_size);
    tx_ip_hdr->packet_id = htons( rand()%65535);
    tx_ip_hdr->fragment_offset = 0x0000;
    tx_ip_hdr->time_to_live = 128;
    tx_ip_hdr->next_proto_id = 0x06;
    tx_ip_hdr->hdr_checksum = 0;
    tx_ip_hdr->src_addr = ip_src;
    tx_ip_hdr->dst_addr = ip_dst;

    //filling tcp_header
    tx_tcp_hdr->src_port = src_port;
    tx_tcp_hdr->dst_port = dst_port;
    tx_tcp_hdr->sent_seq = tmp_send_seq;

    tx_tcp_hdr->recv_ack = tmp_rcv_ack;
    tx_tcp_hdr->data_off = (u_int8_t)(tcp_header_size / 4) * 16;
    tx_tcp_hdr->tcp_flags = 0x10;
    tx_tcp_hdr->rx_win = 8192;    
    tx_tcp_hdr->cksum = 0;
    tx_tcp_hdr->tcp_urp = 0x00;

    memset(tx_payload, 'X', payload_size);

    base_pkt_size = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + tcp_header_size + payload_size;

}

void hn_test_vlan_send::create_base_pkt_udp()
{
    rte_ether_hdr *tx_eth_hdr;
    rte_ipv4_hdr *tx_ip_hdr;
    rte_udp_hdr *tx_udp_hdr;
    char *tx_payload;

    u_int8_t udp_header_size = sizeof(rte_udp_hdr);

    u_int32_t payload_size = 200;

    base_pkt = std::shared_ptr<char>(new char[sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + udp_header_size + payload_size], std::default_delete<char[]>());

    tx_eth_hdr = (rte_ether_hdr *)base_pkt.get();
    tx_ip_hdr = (rte_ipv4_hdr *)(tx_eth_hdr + 1);
    tx_udp_hdr = (rte_udp_hdr *)(tx_ip_hdr + 1);
    tx_payload = ((char*)tx_udp_hdr + udp_header_size);

    // filling eth header
    rte_memcpy(&tx_eth_hdr->src_addr, &src_mac_addr, sizeof(rte_ether_addr));
    rte_memcpy(&tx_eth_hdr->dst_addr, &dst_mac_addr, sizeof(rte_ether_addr));
    tx_eth_hdr->ether_type = htons(0x0800);

    // filling ip_header
    tx_ip_hdr->version_ihl = 0x45;
    tx_ip_hdr->type_of_service = 0x00;
    tx_ip_hdr->total_length = htons(sizeof(rte_ipv4_hdr) + udp_header_size + payload_size);
    tx_ip_hdr->packet_id = htons( rand()%65535);
    tx_ip_hdr->fragment_offset = 0x0000;
    tx_ip_hdr->time_to_live = 128;
    tx_ip_hdr->next_proto_id = 0x11;
    tx_ip_hdr->hdr_checksum = 0;
    tx_ip_hdr->src_addr = ip_src;
    tx_ip_hdr->dst_addr = ip_dst;

    //filling udp_header
    tx_udp_hdr->src_port = src_port;
    tx_udp_hdr->dst_port = dst_port;
    tx_udp_hdr->dgram_len = htons(udp_header_size + payload_size);
    tx_udp_hdr->dgram_cksum = 0;

    memset(tx_payload, 'X', payload_size);

    base_pkt_size = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + udp_header_size + payload_size;

}

void hn_test_vlan_send::update_steps()
{
    ip_src = htonl(htonl(ip_src) + ip_src_step);
    ip_dst = htonl(htonl(ip_dst) + ip_dst_step);
    src_port = htons(htons(src_port) + src_port_step);
    dst_port = htons(htons(dst_port) + dst_port_step);
}

void hn_test_vlan_send::update_nic_global_config(hn_driver *nic_driver, u_int16_t port_id, rte_eth_conf &port_conf) 
{
    nic_driver->set_rss_config(port_id, port_conf);
}

void hn_test_result_vlan_send::show_test_results()
{
    std::cout<<"Test Result: Success!!!"<<std::endl;
}

