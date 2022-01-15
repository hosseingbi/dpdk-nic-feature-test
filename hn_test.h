#ifndef HN_TEST_H
#define HN_TEST_H

#include <iostream>
#include <vector>
#include <map>
#include <functional>
#include <rte_mbuf.h>
#include "hn_driver.h"

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

    virtual void update_nic_global_config(hn_driver *nic_driver, u_int16_t port_id, rte_eth_conf &port_conf) {}

    virtual void update_nic_after_start(hn_driver *nic_driver, u_int16_t port_id) {}

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

class hn_test_extend
{
private:
    /**
     * @brief it keeps a mapping between the name of the type of the test and a function that creates an instance of that test.
     */
    std::map<std::string, std::function<hn_test*(u_int32_t)>> test_map;
public:

    /**
     * @brief Get all the types name place all of the in a string seperated by '|'.
     * 
     * @return std::string 
     */
    std::string get_all_types_name_str()
    {
        std::string valid_types;
        for(auto it = test_map.begin(); it != test_map.end(); it++)
        {
            if(it != test_map.begin())
                valid_types += "|";
            valid_types += it->first;
        }

        return valid_types;
    }

    /**
     * @brief 
     *      it registers a test type
     * @param test_type_name 
     * @param test_creator_handler 
     */
    void register_test(std::string test_type_name, std::function<hn_test*(u_int32_t)> test_creator_handler)
    {
        test_map[test_type_name] = test_creator_handler;
    }

    std::function<hn_test*(u_int32_t)> get_creator_handler(std::string test_type_name) 
    {
        auto it = test_map.find(test_type_name);
        if(it == test_map.end())
            return nullptr;
        
        return it->second;
    }
};


#endif // HN_TEST_H