#include <iostream>
#include <vector>
#include <rte_mbuf.h>

class hn_test
{
protected:
    u_int32_t lcore_id;
public:
    hn_test(u_int32_t lcore_id):lcore_id(lcore_id){}
    ~hn_test(){}

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
    virtual int get_burst_pkts(rte_mbuf **m, u_int32_t max_burst_size, u_int32_t &ret_burst_size, rte_mempool *mempool) = 0;

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
    virtual int process_rx_burst_pkts(rte_mbuf **m, u_int32_t size) = 0;

    /**
     * @brief 
     *      it prints out the result of the tests
     * 
     */
    virtual void show_the_test_results() = 0;

    u_int32_t get_lcore_id() {return lcore_id;}
};


class hn_test_result
{
protected:
    std::vector<hn_test *> tests;

public:
    hn_test_result(std::vector<hn_test *> tests):tests(tests) {}

    virtual void show_test_results() = 0;
};