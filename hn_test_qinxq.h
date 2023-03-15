#ifndef HN_TEST_QINXQ_H
#define HN_TEST_QINXQ_H

#include <iostream>
#include <memory>
#include <rte_mbuf.h>
#include <unordered_map>
#include <rte_hash_crc.h>
#include "hn_test.h"

#define XENA_RETA_CONF_SIZE 8

typedef struct rte_eth_rss_reta_entry64 xena_reta_conf[XENA_RETA_CONF_SIZE];
typedef struct rte_eth_rss_reta_entry64 *xena_reta_conf_ptr;



class hn_test_qinxq: public hn_test
{
private:
    xena_reta_conf retaconf;

public:
    hn_test_qinxq(u_int32_t lcore_id);
    ~hn_test_qinxq();


    /**
     * @brief Create a tcp object
     *      creates a tcp instance of this object
     * @param lcore 
     * @return hn_test* 
     */
    static hn_test* create(u_int32_t lcore) {return new hn_test_qinxq(lcore); }

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
    int process_rx_burst_pkts(rte_mbuf **m, u_int32_t size, u_int32_t queue_id) override;

    /**
     * @brief 
     *      it prints out the result of the tests
     * 
     */
    void show_the_test_results() override;

    void update_nic_global_config(hn_driver *nic_driver, u_int16_t port_id, rte_eth_conf &port_conf) override;

    void update_nic_after_start(__rte_unused hn_driver *nic_driver, __rte_unused u_int16_t port_id, u_int32_t nb_queues) override;

    void before_receiving(u_int16_t port_id) override;
    
};


class hn_test_result_qinxq: public hn_test_result
{
public:
    hn_test_result_qinxq(std::vector<hn_test *> tests)
        :hn_test_result(tests) {}


    static hn_test_result_qinxq* create(std::vector<hn_test *> tests) { return new hn_test_result_qinxq(tests);}

    void show_test_results() override;
    
};

#endif