#include <iostream>
#include <memory>
#include <rte_mbuf.h>
#include <unordered_map>
#include <rte_hash_crc.h>
#include "hn_test.h"

struct ipv4_5tuple
{
    u_int32_t ip_src;
    u_int32_t ip_dst;
    u_int16_t port_src;
    u_int16_t port_dst;
    u_int8_t  proto;
    inline bool operator==(const ipv4_5tuple &other) const
    {
        if(ip_src == other.ip_src && ip_dst == other.ip_dst && port_src == other.port_src && port_dst == other.port_dst && proto == other.proto)
            return true;
        else
            return false;
    }
    inline ipv4_5tuple& operator=(const ipv4_5tuple &rhs)
    {
        if (this == &rhs)      
            return *this;
        
        this->ip_src = rhs.ip_src;
        this->ip_dst = rhs.ip_dst;
        this->port_src = rhs.port_src;
        this->port_dst = rhs.port_dst;
        this->proto = rhs.proto;        
        return *this;
    }
}__attribute__((__packed__));

static inline uint32_t ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
    const struct ipv4_5tuple *k;
    uint32_t t;
    const uint32_t *p;
    k = (const struct ipv4_5tuple *)data;
    t = k->proto;
    p = (const uint32_t *)&k->port_src;
    init_val = rte_hash_crc_4byte(t, init_val);
    init_val = rte_hash_crc_4byte(k->ip_src, init_val);
    init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
    init_val = rte_hash_crc_4byte(*p, init_val);
    return init_val;
}

struct ipv4_5tuple_keyhasher
{
    u_int32_t operator()(const ipv4_5tuple& data) const
    {
        return ipv4_hash_crc(&data, sizeof(ipv4_5tuple), 0);
    }
};

class hn_test_rss: public hn_test
{
private:
    enum {num_of_rounds = 100, round_num_pkts = 10000};
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

    std::unordered_map<ipv4_5tuple,u_int32_t,ipv4_5tuple_keyhasher> _5tuples;

    void create_base_pkt_tcp();
    void create_base_pkt_udp();

    void update_steps();

public:
    hn_test_rss(u_int32_t lcore_id, u_int8_t ip_proto = 17);
    ~hn_test_rss();

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
    int process_rx_burst_pkts(rte_mbuf **m, u_int32_t size) override;

    /**
     * @brief 
     *      it prints out the result of the tests
     * 
     */
    void show_the_test_results() override;

    std::unordered_map<ipv4_5tuple,u_int32_t,ipv4_5tuple_keyhasher> *get_5tuples() {return &_5tuples;}
};


class hn_test_result_rss: public hn_test_result
{

public:
    hn_test_result_rss(std::vector<hn_test *> tests)
        :hn_test_result(tests) {}

    void show_test_results() override;
};