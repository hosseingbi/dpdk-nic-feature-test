#include "hn_test_dhcp.h"


hn_test_dhcp::hn_test_dhcp(u_int32_t lcore_id)
    :hn_test(lcore_id)
{
    discover_ip_src =  inet_addr(discover_ip_src_str.c_str());
    discover_ip_dst =  inet_addr(discover_ip_dst_str.c_str());
    discover_src_port = htons(discover_src_port);
    discover_dst_port = htons(discover_dst_port);   
}

hn_test_dhcp::~hn_test_dhcp()
{}

void hn_test_dhcp::create_discover_payload(char *payload, u_int16_t &size)
{
    size = 0;
    // filling the header part
    dhcp_header *dhcp_hdr = (dhcp_header *)payload;
    dhcp_hdr->op = m_type::BOOTREQUEST;
    dhcp_hdr->type = htype::ETHERNET;
    dhcp_hdr->hlen = 6;
    dhcp_hdr->hops = 0;
    discover_xid = rand();
    dhcp_hdr->xid = discover_xid;
    dhcp_hdr->secs = 0;
    dhcp_hdr->flags = 0;
    dhcp_hdr->ciaddr = 0;
    dhcp_hdr->yiaddr = 0;
    dhcp_hdr->siaddr = 0;
    dhcp_hdr->giaddr = 0;
    memset(dhcp_hdr->chaddr, 0, sizeof(dhcp_hdr->chaddr));
    memcpy(dhcp_hdr->chaddr, discover_src_mac_addr, sizeof(rte_ether_addr));
    memset(dhcp_hdr->sname, 0, sizeof(dhcp_hdr->sname));
    memset(dhcp_hdr->file, 0, sizeof(dhcp_hdr->file));
    dhcp_hdr->magic_cookie = htonl(0x63825363);

    size += sizeof(dhcp_header);
    // filling the option part
    
    payload[size++] = 53; // type
    payload[size++] = 1; // lenght
    payload[size++] = (char)msg_type::DISCOVER; // value

    payload[size++] = 55; // type
    payload[size++] = 3; // lenght
    payload[size++] = (char)opt_type::SUBNET_MASK;
    payload[size++] = (char)opt_type::BROADCAST_ADDRESS;
    payload[size++] = (char)opt_type::ROUTER;
    payload[size++] = (char)opt_type::END;

    // add paddings
    RTE_ASSERT(dhcp_payload_max_size >= size);
    memset(payload + size, 0, dhcp_payload_max_size - size);

    size = dhcp_payload_max_size;
}

void hn_test_dhcp::create_dhcp_discover_packet(rte_mbuf *m)
{
    rte_ether_hdr *tx_eth_hdr;
    rte_ipv4_hdr *tx_ip_hdr;
    rte_udp_hdr *tx_udp_hdr;
    char *tx_payload;

    u_int8_t udp_header_size = sizeof(rte_udp_hdr);
    u_int16_t payload_size = 0;

    tx_eth_hdr = rte_pktmbuf_mtod(m, rte_ether_hdr *);
    tx_ip_hdr = (rte_ipv4_hdr *)(tx_eth_hdr + 1);
    tx_udp_hdr = (rte_udp_hdr *)(tx_ip_hdr + 1);
    tx_payload = ((char*)tx_udp_hdr + udp_header_size);

    create_discover_payload(tx_payload, payload_size);

    // filling eth header
    rte_memcpy(&tx_eth_hdr->src_addr, &discover_src_mac_addr, sizeof(rte_ether_addr));
    rte_memcpy(&tx_eth_hdr->dst_addr, &discover_dst_mac_addr, sizeof(rte_ether_addr));
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
    tx_ip_hdr->src_addr = discover_ip_src;
    tx_ip_hdr->dst_addr = discover_ip_dst;

    //filling udp_header
    tx_udp_hdr->src_port = discover_src_port;
    tx_udp_hdr->dst_port = discover_dst_port;
    tx_udp_hdr->dgram_len = htons(udp_header_size + payload_size);
    tx_udp_hdr->dgram_cksum = 0;

    m->l2_len = sizeof(rte_ether_hdr);
    m->l2_type = 1;
    m->l3_len = sizeof(rte_ipv4_hdr);
    m->l3_type = 9;
    m->packet_type = 401;
    m->pkt_len = htons(tx_ip_hdr->total_length) + m->l2_len;
    m->data_len = m->pkt_len;
    m->nb_segs = 1;
    m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM;
    tx_udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(tx_ip_hdr, m->ol_flags);
}

void hn_test_dhcp::create_request_payload(char *payload, u_int16_t &size)
{
    size = 0;
    // filling the header part
    dhcp_header *dhcp_hdr = (dhcp_header *)payload;
    dhcp_hdr->op = m_type::BOOTREQUEST;
    dhcp_hdr->type = htype::ETHERNET;
    dhcp_hdr->hlen = 6;
    dhcp_hdr->hops = 0;
    dhcp_hdr->xid = discover_xid;
    dhcp_hdr->secs = 0;
    dhcp_hdr->flags = 0;
    dhcp_hdr->ciaddr = 0;
    dhcp_hdr->yiaddr = 0;
    dhcp_hdr->siaddr = 0;
    dhcp_hdr->giaddr = 0;
    memset(dhcp_hdr->chaddr, 0, sizeof(dhcp_hdr->chaddr));
    memcpy(dhcp_hdr->chaddr, discover_src_mac_addr, sizeof(rte_ether_addr));
    memset(dhcp_hdr->sname, 0, sizeof(dhcp_hdr->sname));
    memset(dhcp_hdr->file, 0, sizeof(dhcp_hdr->file));
    dhcp_hdr->magic_cookie = htonl(0x63825363);

    size += sizeof(dhcp_header);
    // filling the option part
    
    payload[size++] = (char)opt_type::MESSAGE_TYPE; // type
    payload[size++] = 1; // lenght
    payload[size++] = (char)msg_type::REQUEST; // value

    payload[size++] = (char)opt_type::DHCP_SERVER; // type
    payload[size++] = 4; // lenght
    *((u_int32_t *)(payload+size)) = offered_dhcp_server_identifier; // value
    size += 4;

    payload[size++] = (char)opt_type::REQUESTED_ADDRESS; // type
    payload[size++] = 4; // lenght
    *((u_int32_t *)(payload+size)) = offered_ip_addr; // value
    size += 4;

    payload[size++] = (char)opt_type::PARAMETER_REQUEST_LIST; // type
    payload[size++] = 3; // lenght
    payload[size++] = (char)opt_type::SUBNET_MASK;
    payload[size++] = (char)opt_type::BROADCAST_ADDRESS;
    payload[size++] = (char)opt_type::ROUTER;
    payload[size++] = (char)opt_type::END;

    // add paddings
    RTE_ASSERT(dhcp_payload_max_size >= size);
    memset(payload + size, 0, dhcp_payload_max_size - size);

    size = dhcp_payload_max_size;
}

void hn_test_dhcp::create_dhcp_request_packet(rte_mbuf *m)
{
    rte_ether_hdr *tx_eth_hdr;
    rte_ipv4_hdr *tx_ip_hdr;
    rte_udp_hdr *tx_udp_hdr;
    char *tx_payload;

    u_int8_t udp_header_size = sizeof(rte_udp_hdr);
    u_int16_t payload_size = 0;

    tx_eth_hdr = rte_pktmbuf_mtod(m, rte_ether_hdr *);
    tx_ip_hdr = (rte_ipv4_hdr *)(tx_eth_hdr + 1);
    tx_udp_hdr = (rte_udp_hdr *)(tx_ip_hdr + 1);
    tx_payload = ((char*)tx_udp_hdr + udp_header_size);

    create_request_payload(tx_payload, payload_size);

    // filling eth header
    rte_memcpy(&tx_eth_hdr->src_addr, &discover_src_mac_addr, sizeof(rte_ether_addr));
    rte_memcpy(&tx_eth_hdr->dst_addr, &discover_dst_mac_addr, sizeof(rte_ether_addr));
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
    tx_ip_hdr->src_addr = discover_ip_src;
    tx_ip_hdr->dst_addr = discover_ip_dst;

    //filling udp_header
    tx_udp_hdr->src_port = discover_src_port;
    tx_udp_hdr->dst_port = discover_dst_port;
    tx_udp_hdr->dgram_len = htons(udp_header_size + payload_size);
    tx_udp_hdr->dgram_cksum = 0;

    m->l2_len = sizeof(rte_ether_hdr);
    m->l2_type = 1;
    m->l3_len = sizeof(rte_ipv4_hdr);
    m->l3_type = 9;
    m->packet_type = 401;
    m->pkt_len = htons(tx_ip_hdr->total_length) + m->l2_len;
    m->data_len = m->pkt_len;
    m->nb_segs = 1;
    m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM;
    tx_udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(tx_ip_hdr, m->ol_flags);
}

int hn_test_dhcp::get_burst_pkts(rte_mbuf **m, u_int32_t max_burst_size, u_int32_t &ret_burst_size, rte_mempool *mempool)
{
    ret_burst_size = 0;
    if(!max_burst_size)
        return 1;

    switch(dhcp_state)
    {
    case DHCP_STATE_DISCOVER:
        {
            rte_mbuf *tx_mbuf = rte_pktmbuf_alloc(mempool);
            if(!tx_mbuf)
                return 1;
            create_dhcp_discover_packet(tx_mbuf);
            dhcp_state = DHCP_STATE_DISCOVER_SENT;
            m[ret_burst_size++] = tx_mbuf;
        }
        break;
    case DHCP_STATE_DISCOVER_SENT:
        break;

    case DHCP_STATE_REQUEST:
        {
            rte_mbuf *tx_mbuf = rte_pktmbuf_alloc(mempool);
            if(!tx_mbuf)
                return 1;
            create_dhcp_request_packet(tx_mbuf);
            dhcp_state = DHCP_STATE_REQUEST_SENT;
            m[ret_burst_size++] = tx_mbuf;
        }
        break;
    case DHCP_STATE_REQUEST_SENT:
        break;

    case DHCP_STATE_COMPLETED:
        return 0;
        break;
    case DHCP_STATE_FAILED:
        return 0;
        break;
    default:
        return -1;
    }

    return 1;
}

int hn_test_dhcp::process_rx_burst_pkts(rte_mbuf **m, u_int32_t size)
{
    for(u_int32_t i=0; i<size; i++)
    {
        switch(dhcp_state)
        {
        case DHCP_STATE_DISCOVER:
            break;
        case DHCP_STATE_DISCOVER_SENT:
            if(parse_offer_packet(m[i]) == 0)
                dhcp_state = DHCP_STATE_REQUEST;
            break;

        case DHCP_STATE_REQUEST:
            break;
        case DHCP_STATE_REQUEST_SENT:
            if(parse_ack_packet(m[i]) == 0)
                dhcp_state = DHCP_STATE_COMPLETED;
            break;
        case DHCP_STATE_COMPLETED:
            break;
        case DHCP_STATE_FAILED:
            break;
        default:
            return -1;
        }
    }

    return 0;
}

void hn_test_dhcp::show_the_test_results()
{}

void hn_test_dhcp::update_nic_global_config(hn_driver *nic_driver, u_int16_t port_id, rte_eth_conf &port_conf)
{
    nic_driver->set_rss_config(port_id, port_conf);
}

int hn_test_dhcp::extract_options(char *opt_payload, u_int16_t opt_size)
{
    u_int8_t opt_len;
    for(u_int32_t offset=0; offset<opt_size;)
    {
        switch((opt_type)opt_payload[offset++])
        {
        case opt_type::MESSAGE_TYPE:
            opt_len = opt_payload[offset++];
            if(opt_len != 1)
                return -1;
            dhcp_extracted_opts.msgtype = (msg_type)opt_payload[offset++];
            break;
        
        case opt_type::DHCP_SERVER:
            opt_len = opt_payload[offset++];
            if(opt_len != 4)
                return -1;
            dhcp_extracted_opts.dhcp_server_address = *((u_int32_t *)(opt_payload+offset));
            offset+=4;
            break;
        case opt_type::LEASE_TIME :
            opt_len = opt_payload[offset++];
            if(opt_len != 4)
                return -1;
            dhcp_extracted_opts.lease_time = htonl(*((u_int32_t *)(opt_payload+offset)));
            offset+=4;
            break;
        case opt_type::SUBNET_MASK:
            opt_len = opt_payload[offset++];
            if(opt_len != 4)
                return -1;
            dhcp_extracted_opts.subnet_mask = *((u_int32_t *)(opt_payload+offset));
            offset+=4;
            break;
        case opt_type::BROADCAST_ADDRESS:
            opt_len = opt_payload[offset++];
            if(opt_len != 4)
                return -1;
            dhcp_extracted_opts.broadcast_addr = *((u_int32_t *)(opt_payload+offset));
            offset+=4;
            break;
        case opt_type::ROUTER:
            opt_len = opt_payload[offset++];
            if(opt_len != 4)
                return -1;
            dhcp_extracted_opts.router = *((u_int32_t *)(opt_payload+offset));
            offset+=4;
            break;
        
        case opt_type::END:
            return 0;
            break;
        default:
            offset++;
            break; 
        }
    }

    return -1;
}

int hn_test_dhcp::parse_offer_payload(char *payload, u_int16_t size)
{
    u_int16_t offset = 0;
    if(size < sizeof(dhcp_header))
        return -1;
    
    dhcp_header *dhcp_hdr = (dhcp_header *)payload;

    if(dhcp_hdr->op != m_type::BOOTREPLY)
        return -1;
    
    if(dhcp_hdr->type != htype::ETHERNET)
        return -1;
    
    if(dhcp_hdr->hlen != 6)
        return -1;
    
    if(dhcp_hdr->xid != discover_xid)
        return -1;

    if(memcmp(dhcp_hdr->chaddr, discover_src_mac_addr, sizeof(rte_ether_addr)))
        return -1;
    
    if(dhcp_hdr->magic_cookie != htonl(0x63825363))
        return -1;

    offered_ip_addr = dhcp_hdr->yiaddr;
    
    offset = sizeof(dhcp_header);

    int ret = extract_options(payload + offset, size - offset);

    if(ret)
        return -1;
    
    if(dhcp_extracted_opts.msgtype != msg_type::OFFER)
        return -1;
    
    offered_dhcp_server_identifier = dhcp_extracted_opts.dhcp_server_address;
    offered_broadcast_addr = dhcp_extracted_opts.broadcast_addr;
    offered_subnet_mask= dhcp_extracted_opts.broadcast_addr;
    offered_router = dhcp_extracted_opts.broadcast_addr;

    return 0;
}

int hn_test_dhcp::parse_offer_packet(rte_mbuf *m)
{
    rte_ether_hdr   *rx_eth_hdr;
    rte_ipv4_hdr    *rx_ip_hdr;
    rte_udp_hdr     *rx_udp_hdr;
    char            *rx_payload;
    u_int8_t udp_header_size = sizeof(rte_udp_hdr);
    u_int16_t payload_size = 0;

    if(m->pkt_len < sizeof(rte_ether_hdr)+sizeof(rte_ipv4_hdr)+udp_header_size+sizeof(dhcp_header))
        return -1;

    rx_eth_hdr  = rte_pktmbuf_mtod(m, rte_ether_hdr *);
    rx_ip_hdr   = (rte_ipv4_hdr *)(rx_eth_hdr + 1);

    // checking ethernet header
    if(memcmp(&rx_eth_hdr->dst_addr, discover_src_mac_addr, sizeof(rte_ether_addr)))
        return -1;
    
    if(rx_eth_hdr->ether_type != htons(0x0800))
        return -1;

    // checking the ip header
    u_int16_t ip_hdr_len = (rx_ip_hdr->version_ihl & 0x0f) * 4;
    u_int16_t ip_tot_len = htons(rx_ip_hdr->total_length);
    if(ip_tot_len != (m->pkt_len - sizeof(rte_ether_hdr)))
        return -1;

    if(rx_ip_hdr->next_proto_id != 0x11)
        return -1;
    
    rx_udp_hdr  = (rte_udp_hdr *)(((char *)rx_ip_hdr) + ip_hdr_len);
    rx_payload  = ((char*)rx_udp_hdr + udp_header_size);

    // check udp header
    if(rx_udp_hdr->src_port != htons(67))
        return -1;
    
    if(rx_udp_hdr->dst_port != htons(68))
        return -1;
    
    if(htons(rx_udp_hdr->dgram_len) != (ip_tot_len - ip_hdr_len) )
        return -1;

    // check udp payload
    payload_size = htons(rx_udp_hdr->dgram_len) - sizeof(rte_udp_hdr);
    int ret = parse_offer_payload(rx_payload,  payload_size);

    if(ret)
        return -1;

    return 0;
}

int hn_test_dhcp::parse_ack_payload(char *payload, u_int16_t size)
{
    u_int16_t offset = 0;
    if(size < sizeof(dhcp_header))
        return -1;
    
    dhcp_header *dhcp_hdr = (dhcp_header *)payload;

    if(dhcp_hdr->op != m_type::BOOTREPLY)
        return -1;
    
    if(dhcp_hdr->type != htype::ETHERNET)
        return -1;
    
    if(dhcp_hdr->hlen != 6)
        return -1;
    
    if(dhcp_hdr->xid != discover_xid)
        return -1;

    if(memcmp(dhcp_hdr->chaddr, discover_src_mac_addr, sizeof(rte_ether_addr)))
        return -1;
    
    if(dhcp_hdr->magic_cookie != htonl(0x63825363))
        return -1;

    offered_ip_addr = dhcp_hdr->yiaddr;
    
    offset = sizeof(dhcp_header);

    int ret = extract_options(payload + offset, size - offset);

    if(ret)
        return -1;
    
    if(dhcp_extracted_opts.msgtype != msg_type::ACK)
        return -1;
    
    offered_dhcp_server_identifier = dhcp_extracted_opts.dhcp_server_address;
    offered_broadcast_addr = dhcp_extracted_opts.broadcast_addr;
    offered_subnet_mask= dhcp_extracted_opts.broadcast_addr;
    offered_router = dhcp_extracted_opts.broadcast_addr;

    return 0;
}

int hn_test_dhcp::parse_ack_packet(rte_mbuf *m)
{
    rte_ether_hdr   *rx_eth_hdr;
    rte_ipv4_hdr    *rx_ip_hdr;
    rte_udp_hdr     *rx_udp_hdr;
    char            *rx_payload;
    u_int8_t udp_header_size = sizeof(rte_udp_hdr);
    u_int16_t payload_size = 0;

    if(m->pkt_len < sizeof(rte_ether_hdr)+sizeof(rte_ipv4_hdr)+udp_header_size+sizeof(dhcp_header))
        return -1;

    rx_eth_hdr  = rte_pktmbuf_mtod(m, rte_ether_hdr *);
    rx_ip_hdr   = (rte_ipv4_hdr *)(rx_eth_hdr + 1);

    // checking ethernet header
    if(memcmp(&rx_eth_hdr->dst_addr, discover_src_mac_addr, sizeof(rte_ether_addr)))
        return -1;
    
    if(rx_eth_hdr->ether_type != htons(0x0800))
        return -1;

    // checking the ip header
    u_int16_t ip_hdr_len = (rx_ip_hdr->version_ihl & 0x0f) * 4;
    u_int16_t ip_tot_len = htons(rx_ip_hdr->total_length);
    if(ip_tot_len != (m->pkt_len - sizeof(rte_ether_hdr)))
        return -1;

    if(rx_ip_hdr->next_proto_id != 0x11)
        return -1;
    
    rx_udp_hdr  = (rte_udp_hdr *)(((char *)rx_ip_hdr) + ip_hdr_len);
    rx_payload  = ((char*)rx_udp_hdr + udp_header_size);

    // check udp header
    if(rx_udp_hdr->src_port != htons(67))
        return -1;
    
    if(rx_udp_hdr->dst_port != htons(68))
        return -1;
    
    if(htons(rx_udp_hdr->dgram_len) != (ip_tot_len - ip_hdr_len) )
        return -1;

    // check udp payload
    payload_size = htons(rx_udp_hdr->dgram_len) - sizeof(rte_udp_hdr);
    int ret = parse_ack_payload(rx_payload,  payload_size);

    if(ret)
        return -1;

    return 0;
}