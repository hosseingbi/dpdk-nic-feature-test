#include "hn_test_rss_vxlan.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>



static int port_rss_reta_update(uint16_t portid, u_int32_t nb_queues)
{
    int ret;
    int reta;
    xena_reta_conf reta_conf; 
    u_int8_t idx, shift;
    u_int16_t core_num;
    u_int32_t c;
    int16_t pid = portid;
    memset(reta_conf, 0 , sizeof(reta_conf));

    for (reta = 0; reta < 512; reta++) {
        idx   = reta / RTE_ETH_RETA_GROUP_SIZE;
        shift = reta % RTE_ETH_RETA_GROUP_SIZE;

        core_num = (reta % nb_queues);

        for (c = 0; c < nb_queues; c++) 
        {      
            if (c == core_num) 
            {
                break;
            }
        }

        reta_conf[idx].mask |= (1ULL << shift);
        reta_conf[idx].reta[shift] = c;
    }

    // Update RSS Table
    ret = rte_eth_dev_rss_reta_update(pid, reta_conf, 512);
    return ret;
}

static int port_rss_reta_query(u_int16_t pid, xena_reta_conf_ptr reta_conf)
{
  int ret;
  int reta, idx, shift;
  int reta_size = 512;

  for (reta = 0; reta < reta_size; reta++) {
    idx   = reta / RTE_ETH_RETA_GROUP_SIZE;
    shift = reta % RTE_ETH_RETA_GROUP_SIZE; 
    reta_conf[idx].mask |= (1ULL << shift);
  }
  ret = rte_eth_dev_rss_reta_query(pid, reta_conf, reta_size);
  if (ret != 0) {
  }
  return ret;
}

static int port_rss_reta_index_to_queue(__rte_unused u_int16_t pid, u_int16_t i, xena_reta_conf_ptr reta_conf)
{
  u_int8_t idx, shift;
  idx   = i / RTE_ETH_RETA_GROUP_SIZE;
  shift = i % RTE_ETH_RETA_GROUP_SIZE;
  return reta_conf[idx].reta[shift]; 
}

hn_test_rss_vxlan::hn_test_rss_vxlan(u_int32_t lcore_id)
    :hn_test(lcore_id)
{
}

hn_test_rss_vxlan::~hn_test_rss_vxlan()
{}

int hn_test_rss_vxlan::get_burst_pkts(__rte_unused rte_mbuf **m, __rte_unused u_int32_t max_burst_size, u_int32_t &ret_burst_size, __rte_unused rte_mempool *mempool) 
{
    ret_burst_size = 0;
    return 1;
}

int hn_test_rss_vxlan::process_rx_burst_pkts(__rte_unused rte_mbuf **m , u_int32_t size, u_int32_t queue_id) 
{
     for(u_int32_t i=0; i< size; i++)
    {
        if (RTE_ETH_IS_IPV4_HDR(m[i]->packet_type))
        {
            rte_ether_hdr * eth_hdr = rte_pktmbuf_mtod(m[i], rte_ether_hdr *);
            rte_ipv4_hdr * ip_hdr = (rte_ipv4_hdr *)(eth_hdr + 1);
            if(ip_hdr ->next_proto_id == 0x11) // udp
            {
                rte_udp_hdr *udp_hdr = (rte_udp_hdr *)(ip_hdr + 1);
                if(udp_hdr->dst_port == htons(4789)) // vxlan
                {
                    rte_vxlan_hdr *vxlan_hdr = (rte_vxlan_hdr *)(udp_hdr + 1);
                    rte_ether_hdr * inner_eth_hdr = (rte_ether_hdr *)(vxlan_hdr + 1);
                    rte_ipv4_hdr * inner_ip_hdr = (rte_ipv4_hdr *)(inner_eth_hdr + 1);
                    if(inner_ip_hdr ->next_proto_id == 0x6) // tcp
                    {
                        u_int16_t rss_index = m[i]->hash.rss & 511;
                        int tmp_queue_id = port_rss_reta_index_to_queue(0, rss_index, (xena_reta_conf_ptr)&retaconf);
                        if(tmp_queue_id != queue_id)
                        {
                            printf("shapalagh\n");
                        }
                    }
                }
            }
        }
    }
    return 0;
}

void hn_test_rss_vxlan::update_nic_global_config(hn_driver *nic_driver, u_int16_t port_id, rte_eth_conf &port_conf) 
{
    nic_driver->set_rss_vxlan_inner_config(port_id, port_conf);
}

void hn_test_rss_vxlan::update_nic_after_start(hn_driver *nic_driver, u_int16_t port_id, u_int32_t nb_queues) 
{
    nic_driver[port_id].set_rss_vxlan_rte_flow_config(port_id, nb_queues);

    // apply reta configuration
    port_rss_reta_update(port_id, nb_queues);

    xena_reta_conf  tmp_reta_conf;
    memset(&tmp_reta_conf, 0, sizeof(xena_reta_conf));
    port_rss_reta_query(port_id, (xena_reta_conf_ptr)&tmp_reta_conf);

}

void hn_test_rss_vxlan::show_the_test_results() 
{
}

void hn_test_rss_vxlan::before_receiving(u_int16_t port_id)
{
    memset(&retaconf, 0, sizeof(xena_reta_conf));
    port_rss_reta_query(port_id, (xena_reta_conf_ptr)&retaconf);
}

void hn_test_result_rss_vxlan::show_test_results()
{
}

