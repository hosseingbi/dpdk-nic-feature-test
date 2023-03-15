#ifndef HN_TEST_VLAN_SEND_H
#define HN_TEST_VLAN_SEND_H

#include <iostream>
#include <memory>
#include <rte_mbuf.h>
#include <unordered_map>
#include <rte_hash_crc.h>
#include "hn_test.h"

class hn_test_vlan_send: public hn_test
{
private:
    enum {num_of_rounds = 1, round_num_pkts = 10};
    u_int8_t src_mac_addr[6] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    u_int8_t dst_mac_addr[6] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    std::string ip_src_start_str = "12.1.1.1";
    std::string ip_dst_start_str = "46.1.1.1";
    u_int32_t ip_src_step = 1;
    u_int32_t ip_dst_step = 1;
    u_int32_t ip_src;
    u_int32_t ip_dst;

    u_int16_t src_port = 31000;
    u_int16_t src_port_step = 0;
    u_int16_t dst_port = 1000;
    u_int16_t dst_port_step = 1;
    u_int8_t proto = 17;

    std::shared_ptr<char> base_pkt;
    u_int32_t base_pkt_size = 0;

    u_int32_t round_counter = 0;
    u_int32_t round_pkt_counter = 0;

    void create_base_pkt_tcp();
    void create_base_pkt_udp();

    void update_steps();

public:
    hn_test_vlan_send(u_int32_t lcore_id);
    ~hn_test_vlan_send();

    /**
     * @brief Create a udp object
     *      creates a udp instance of this object
     * @param lcore 
     * @return hn_test* 
     */
    static hn_test* create(u_int32_t lcore) { return new hn_test_vlan_send(lcore);}

    /**
     * @brief Get a burst of mbufs from the given mempool and prepared them for the test.
     * 
     * @param m 
     *      refers to the array of prepared mbufs
     * @param max_burst_size 
     *      maximum number of pkts in each burst
     * @param ret_burst_size
     *      the number of mbufs in this burst will be stored into this variable
     * @param mempool 
     *      pointer to the tx mempool
     * @return int 
     *      -1 means the test should be ended with some technical failure
     *      0 means end of the test
     *      1 means there are more packets to be sent
     */
    int get_burst_pkts(rte_mbuf **m, u_int32_t max_burst_size, u_int32_t &ret_burst_size, rte_mempool *mempool) override;

    /**
     * @brief 
     *      process a burst of received packets
     * 
     * @param m 
     *      refers to the arrays of received mbufs
     * @param size 
     *      the number of mbufs in the array
     * @return int 
     *      -1 means the test should be ended with some technical failure
     *      0 means success
     */
    int process_rx_burst_pkts(rte_mbuf **m, u_int32_t size , u_int32_t queue_id) override;

    /**
     * @brief 
     *      it prints out the result of the tests
     * 
     */
    void show_the_test_results() override;

    void update_nic_global_config(hn_driver *nic_driver, u_int16_t port_id, rte_eth_conf &port_conf) override;

    void update_nic_after_start(__rte_unused hn_driver *nic_driver, __rte_unused u_int16_t port_id, __rte_unused u_int32_t nb_queues) override {}
    
};


class hn_test_result_vlan_send: public hn_test_result
{
public:
    hn_test_result_vlan_send(std::vector<hn_test *> tests)
        :hn_test_result(tests) {}


    static hn_test_result_vlan_send* create(std::vector<hn_test *> tests) { return new hn_test_result_vlan_send(tests);}

    void show_test_results() override;
    
};

#endif // HN_TEST_VLAN_SEND_H