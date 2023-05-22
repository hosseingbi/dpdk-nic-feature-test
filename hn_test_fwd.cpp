#include "hn_test_fwd.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

hn_test_fwd::hn_test_fwd(u_int32_t lcore_id)
    :hn_test(lcore_id)
{
}

hn_test_fwd::~hn_test_fwd()
{}

int hn_test_fwd::get_burst_pkts(rte_mbuf **m, u_int32_t max_burst_size, u_int32_t &ret_burst_size, rte_mempool *mempool) 
{
    return 0;
}

int hn_test_fwd::process_rx_burst_pkts(rte_mbuf **m, u_int32_t size) 
{

    // uint16_t tot_packets_sent = 0;
    // do {
    //     u_int16_t sent = rte_eth_tx_burst(0/*port id*/, queue_id, &pkts_burst[burst_offset], ret_burst_size - burst_offset);
    //     tot_packets_sent 
    // } while 
    // u_int16_t sent = rte_eth_tx_burst(0/*port id*/, queue_id, &pkts_burst[burst_offset], ret_burst_size - burst_offset);
	// 		burst_offset += sent;
	// 		if(burst_offset >= ret_burst_size)
	// 			burst_offset = 0;

    return 0;
}

void hn_test_fwd::show_the_test_results() 
{
}

void hn_test_fwd::update_nic_global_config(hn_driver *nic_driver, u_int16_t port_id, rte_eth_conf &port_conf) 
{
    nic_driver->set_rss_config(port_id, port_conf);
}

void hn_test_result_fwd::show_test_results()
{
}

