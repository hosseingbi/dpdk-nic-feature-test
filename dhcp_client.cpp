#include "dhcp_client.h"
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <sstream>

dhcp_client::dhcp_client(u_int32_t number_of_dhcp_requests, rte_ether_addr *base_hw_addr, u_int16_t max_number_retransmit, 
        u_int32_t timeout_in_msec)
{
    num_requests = number_of_dhcp_requests;
    num_retransmit = max_number_retransmit;
    timeout_msec = timeout_in_msec;
    mac_inc_seed = htonl(rand() % (1<<24));
    memcpy(&client_base_hw_addr, base_hw_addr, sizeof(rte_ether_addr));
    increament_base_hw_addr();

    for(u_int32_t i=0; i< num_requests; i++)
    {
        dhcp_client_session *new_session= new dhcp_client_session(mac_inc_seed, &client_base_hw_addr, num_retransmit, timeout_msec);
        all_sessions[mac_inc_seed] = new_session;
        not_resolved.push_back(new_session);
        increament_base_hw_addr();
    }
}

dhcp_client::~dhcp_client()
{
    for(auto it: all_sessions)
    {
        delete it.second;
    }
}

void dhcp_client::increament_base_hw_addr()
{
    memcpy(&client_base_hw_addr.addr_bytes[3], ((char*)(&mac_inc_seed)+1), 3);
    mac_inc_seed = htonl(htonl(mac_inc_seed) + 1);
}

std::string dhcp_client::convert_macaddr_to_str(const rte_ether_addr &addr)
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
        addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);
    return std::string(mac_str);
}

int dhcp_client::handle_tx(rte_mbuf **m, rte_mempool *mempool)
{
    if(not_resolved.size() == 0) // if all the dhcp are resolved (either in success or failure), call it the end of dhcp resolving process
        return 0;

    dhcp_client_session *dhcp_session = not_resolved.front();
    not_resolved.pop_front();

    int ret = dhcp_session->get_pkt(m, mempool);
    switch(ret)
    {
    case 2: // success and there is a mbuf to be send
        break;
    case 1: // success but no mbuf to send
        break;
    case 0: // dhcp process is compelted
        ret = 1;
        if(dhcp_session->get_dhcp_state() == dhcp_client_session::DHCP_STATE_COMPLETED)
            num_resolved_success++;
        else
            num_resolved_failure++;
        return ret;
        break;
    case -1:
        ret = 1;
        break;
    }

    not_resolved.push_back(dhcp_session);
    return ret;
}

int dhcp_client::handle_rx(rte_mbuf *m)
{
    rte_ether_hdr   *rx_eth_hdr;
    rte_ipv4_hdr    *rx_ip_hdr;
    rte_udp_hdr     *rx_udp_hdr;
    char            *rx_payload;
    u_int8_t udp_header_size = sizeof(rte_udp_hdr);

    if(m->pkt_len < sizeof(rte_ether_hdr)+sizeof(rte_ipv4_hdr)+udp_header_size+sizeof(dhcp_client_session::dhcp_header))
        return -1;

    rx_eth_hdr  = rte_pktmbuf_mtod(m, rte_ether_hdr *);
    rx_ip_hdr   = (rte_ipv4_hdr *)(rx_eth_hdr + 1);
    
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
    
    dhcp_client_session::dhcp_header *dhcp_hdr = (dhcp_client_session::dhcp_header *)rx_payload;
    auto it = all_sessions.find(dhcp_hdr->xid);
    if(it == all_sessions.end()) // session not found
        return -1;
    
    it->second->process_rx(m);

    return 0;
}

u_int32_t dhcp_client::dump_result_json(char **ret_data)
{
    rapidjson::Document d;
    d.SetObject();

    rapidjson::Document::AllocatorType& allocator = d.GetAllocator();
    rapidjson::Value val(rapidjson::kObjectType);
    std::string tmpstr = "";

    val.SetUint(all_sessions.size());
    d.AddMember("tot_requests", val, allocator);

    val.SetUint(num_resolved_success);
    d.AddMember("num_success", val, allocator);

    val.SetUint(num_resolved_failure);
    d.AddMember("num_failure", val, allocator);

    rapidjson::Value dhcp_responses(rapidjson::kArrayType);
    rapidjson::Value response(rapidjson::kObjectType);

    for(auto it: all_sessions)
    {
        if(it.second->get_dhcp_state() != dhcp_client_session::DHCP_STATE_COMPLETED) // if this session didn't finished successfully
            continue;
        
        rte_ether_addr client_hw_addr;
        it.second->get_client_hw_addr(client_hw_addr);

        response.SetObject();
        tmpstr = convert_macaddr_to_str(client_hw_addr);
        val.SetString(tmpstr.c_str(), static_cast<rapidjson::SizeType>(tmpstr.length()), allocator);
        response.AddMember("hw_address", val, allocator);

        val.SetUint(it.second->get_ip_address());
        response.AddMember("ip_address", val, allocator);

        val.SetUint(it.second->get_subnet_mask());
        response.AddMember("subnet_mask", val, allocator);

        val.SetUint(it.second->get_broadcast_address());
        response.AddMember("broadcast_address", val, allocator);

        val.SetUint(it.second->get_router());
        response.AddMember("default_gw", val, allocator);

        val.SetUint(it.second->get_lease_time());
        response.AddMember("lease_time", val, allocator);

        dhcp_responses.PushBack(response, allocator);
    }

    d.AddMember("dhcp_responses", dhcp_responses, allocator);

    // Convert JSON document to string
    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    d.Accept(writer);
    
    *ret_data = (char *)malloc(strbuf.GetSize());
    memcpy(*ret_data, strbuf.GetString(), strbuf.GetSize());
    
    return strbuf.GetSize();;
}