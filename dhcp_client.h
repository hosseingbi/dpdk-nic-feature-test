#ifndef DHCP_CLIENT_H
#define DHCP_CLIENT_H

#include <iostream>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <unordered_map>
#include <list>
#include "dhcp_client_session.h"

class dhcp_client{
private:
    enum {max_num_retransmit=3, max_retransmit_timeout_msec=5000};
    std::unordered_map<u_int32_t, dhcp_client_session*> all_sessions;
    std::list<dhcp_client_session *> not_resolved;
    u_int32_t num_resolved_success = 0;
    u_int32_t num_resolved_failure = 0;
    u_int32_t num_requests;
    rte_ether_addr client_base_hw_addr;
    u_int32_t num_retransmit;
    u_int32_t timeout_msec;
    u_int32_t mac_inc_seed;

    void increament_base_hw_addr();

    std::string convert_macaddr_to_str(const rte_ether_addr &addr);

public:
    dhcp_client(u_int32_t number_of_dhcp_requests, rte_ether_addr *base_hw_addr, u_int16_t max_number_retransmit = max_num_retransmit, 
        u_int32_t timeout_in_msec=max_retransmit_timeout_msec);
    ~dhcp_client();

    /**
     * @brief 
     * 
     * @param m 
     * @param mempool 
     * @return int 
     *      0   dhcp process successfully compelted
     *      1   success but no mbuf to send
     *      2   success and there is a mbuf to be send
     *      <0  failure
     */
    int handle_tx(rte_mbuf **m, rte_mempool *mempool);

    int handle_rx(rte_mbuf *m);

    /**
     * @brief 
     *      return a json formatted data of all the success resolved sessions
     * @param ret_data 
     *      
     * @return u_int32_t 
     *      the size of the data
     */
    u_int32_t dump_result_json(char **ret_data);
};



#endif // DHCP_CLIENT_H