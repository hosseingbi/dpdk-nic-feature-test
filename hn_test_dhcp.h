#ifndef HN_TEST_DHCP_H
#define HN_TEST_DHCP_H

#include <iostream>
#include <memory>
#include <rte_mbuf.h>
#include <unordered_map>
#include "hn_test.h"
#include "dhcp_client.h"

class hn_test_dhcp: public hn_test
{
private:
    enum {num_dhcp_requests=100 };
    std::shared_ptr<dhcp_client> dhcp_client_;
    rte_ether_addr client_base_hw_addr;

public:
    hn_test_dhcp(u_int32_t lcore_id);
    ~hn_test_dhcp();

    /**
     * @brief 
     *      creates an instance of this object
     * @param lcore 
     * @return hn_test* 
     */
    static hn_test* create(u_int32_t lcore) { return new hn_test_dhcp(lcore);}

    int get_burst_pkts(rte_mbuf **m, u_int32_t max_burst_size, u_int32_t &ret_burst_size, rte_mempool *mempool);

    int process_rx_burst_pkts(rte_mbuf **m, u_int32_t size);

    void show_the_test_results();

    void update_nic_global_config(hn_driver *nic_driver, u_int16_t port_id, rte_eth_conf &port_conf) override;

    void update_nic_after_start(__rte_unused hn_driver *nic_driver, __rte_unused u_int16_t port_id) override {};
};

class hn_test_result_dhcp: public hn_test_result
{
private:
public:

    hn_test_result_dhcp(std::vector<hn_test *> tests):hn_test_result(tests){}

    static hn_test_result_dhcp* create(std::vector<hn_test *> tests) { return new hn_test_result_dhcp(tests);}

    void show_test_results();
};

#endif