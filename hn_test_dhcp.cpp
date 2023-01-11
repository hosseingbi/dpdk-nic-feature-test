#include "hn_test_dhcp.h"


hn_test_dhcp::hn_test_dhcp(u_int32_t lcore_id)
    :hn_test(lcore_id)
{
    client_base_hw_addr.addr_bytes[0] = 0x0a;
    client_base_hw_addr.addr_bytes[1] = 0x0b;
    client_base_hw_addr.addr_bytes[2] = 0x0c;
    client_base_hw_addr.addr_bytes[3] = 0x00;
    client_base_hw_addr.addr_bytes[4] = 0x00;
    client_base_hw_addr.addr_bytes[5] = 0x00;

    dhcp_client_ = std::shared_ptr<dhcp_client>(new dhcp_client(num_dhcp_requests, &client_base_hw_addr));
}

hn_test_dhcp::~hn_test_dhcp()
{
}

int hn_test_dhcp::get_burst_pkts(rte_mbuf **m, u_int32_t max_burst_size, u_int32_t &ret_burst_size, rte_mempool *mempool)
{
    ret_burst_size = 0;
    if(!max_burst_size)
        return 1;

    int ret = dhcp_client_->handle_tx(&m[0], mempool);
    if(ret == 2)
        ret_burst_size = 1;
    else if(ret == 0)
        return 0; // call it end of the test
    return 1;
}

int hn_test_dhcp::process_rx_burst_pkts(rte_mbuf **m, u_int32_t size)
{
    for(u_int32_t i = 0; i< size; i++)
        dhcp_client_->handle_rx(m[i]);

    return 0;
}

void hn_test_dhcp::show_the_test_results()
{
    char *test_res;
    u_int32_t test_res_size = dhcp_client_->dump_result_json(&test_res);
    std::cout.write(test_res, test_res_size);

    free(test_res);
}

void hn_test_dhcp::update_nic_global_config(hn_driver *nic_driver, u_int16_t port_id, rte_eth_conf &port_conf)
{
    nic_driver->set_rss_config(port_id, port_conf);
}


void hn_test_result_dhcp::show_test_results()
{
}