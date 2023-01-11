#ifndef DHCP_CLIENT_SESSION_H
#define DHCP_CLIENT_SESSION_H

#include <iostream>
#include <memory>
#include <rte_mbuf.h>
#include <unordered_map>
#include <rte_ether.h>


class dhcp_client_session
{
public:
    enum class m_type : uint8_t {
        BOOTREQUEST = 1,
        BOOTREPLY = 2
    };

    enum class htype : uint8_t {
        ETHERNET = 1
    };

    enum class opt_type : uint8_t {
        PAD = 0,
        SUBNET_MASK = 1,
        ROUTER = 3,
        DOMAIN_NAME_SERVERS = 6,
        INTERFACE_MTU = 26,
        BROADCAST_ADDRESS = 28,
        REQUESTED_ADDRESS = 50,
        LEASE_TIME = 51,
        MESSAGE_TYPE = 53,
        DHCP_SERVER = 54,
        PARAMETER_REQUEST_LIST = 55,
        RENEWAL_TIME = 58,
        REBINDING_TIME = 59,
        CLASSLESS_ROUTE = 121,
        END = 255
    };

    enum class msg_type : uint8_t {
        DISCOVER = 1,
        OFFER = 2,
        REQUEST = 3,
        DECLINE = 4,
        ACK = 5,
        NAK = 6,
        RELEASE = 7,
        INFORM = 8,
        LEASEQUERY = 10,
        LEASEUNASSIGNED = 11,
        LEASEUNKNOWN = 12,
        LEASEACTIVE = 13,
        INVALID = 255
    };

    struct dhcp_header {
        m_type op = m_type::BOOTREQUEST; // Message op code / message type.
        htype type = htype::ETHERNET;             // Hardware address type
        uint8_t hlen = 6;           // Hardware address length
        uint8_t hops = 0;           // Client sets to zero, used by relay agents
        uint32_t xid = 0;           // Client sets Transaction ID, a random number
        uint16_t secs = 0;          // Client sets seconds elapsed since op start
        uint16_t flags = 0;         // Flags
        uint32_t ciaddr;  // Client IP address
        uint32_t yiaddr;  // 'your' (client) IP address.
        uint32_t siaddr;  // IP address of next server to use in bootstrap
        uint32_t giaddr;  // Relay agent IP address
        uint8_t chaddr[16] = { 0, };     // Client hardware address.
        char sname[64] = { 0, };         // unused
        char file[128] = { 0, };         // unused
        u_int32_t magic_cookie;

    } __attribute__((packed));
    enum dhcp_state_t{DHCP_STATE_DISCOVER, DHCP_STATE_DISCOVER_SENT, DHCP_STATE_REQUEST, DHCP_STATE_REQUEST_SENT, DHCP_STATE_COMPLETED, DHCP_STATE_FAILED};



private:
    dhcp_state_t dhcp_state;

    enum {dhcp_payload_max_size=300};
    u_int8_t discover_src_mac_addr[6] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    u_int8_t discover_dst_mac_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    struct dhcp_extracted_options
    {
        u_int32_t   dhcp_server_address;
        msg_type    msgtype;
        u_int32_t   lease_time;
        u_int32_t   subnet_mask;
        u_int32_t   broadcast_addr;
        u_int32_t   router;
    }dhcp_extracted_opts;

    std::string discover_ip_src_str = "0.0.0.0";
    std::string discover_ip_dst_str = "255.255.255.255";
    u_int32_t discover_ip_src;
    u_int32_t discover_ip_dst;
    u_int16_t discover_src_port = 68;
    u_int16_t discover_dst_port = 67;
    u_int32_t discover_xid;
    u_int16_t discover_max_num_retransmit;
    u_int16_t discover_num_retransmit = 0;
    u_int32_t discover_last_sent; 
    u_int32_t discover_timeout; // in msec

    u_int32_t offered_dhcp_server_identifier;
    u_int32_t offered_ip_addr;
    u_int32_t offered_subnet_mask;
    u_int32_t offered_broadcast_addr;
    u_int32_t offered_router;
    u_int32_t offered_lease_time;

    void create_discover_payload(char *payload, u_int16_t &size);
    void create_dhcp_discover_packet(rte_mbuf *m);

    /**
     * @brief 
     * 
     * @param payload 
     * @param size 
     * @return int 
     *      return 0 in the case of sucess
     *      return -1 in the case of failure
     *      return -2 in the case of failure state (in this case the dhcp_state should goes immediately to failure state)
     */
    int parse_offer_payload(char *payload, u_int16_t size);
    int parse_offer_packet(rte_mbuf *m);
    int parse_ack_payload(char *payload, u_int16_t size);
    int parse_ack_packet(rte_mbuf *m);
    int extract_options(char *opt_payload, u_int16_t opt_size);

    void create_request_payload(char *payload, u_int16_t &size);
    void create_dhcp_request_packet(rte_mbuf *m);

    /**
     * @brief Linux_GetCurrentSystemTime
     *      returns the linux timestamp in milisecond
     * @return
     */
    int Linux_GetCurrentSystemTime();

public:
    dhcp_client_session(u_int32_t transaction_id, rte_ether_addr *client_hw_addr, u_int16_t max_number_retransmit, u_int32_t timeout_in_msec);
    ~dhcp_client_session();

    /**
     * @brief Get the pkt object
     * 
     * @param m 
     *      created mbuf
     * @param mempool 
     *      pointer to the mempool that m should be created from
     * @return int 
     *      0   dhcp process compeleted (to see if it is success or failure, dhcp_status)
     *      1   success but no mbuf to send
     *      2   success and there is a mbuf to be send
     *      <0  failure
     */
    int get_pkt(rte_mbuf **m, rte_mempool *mempool);

    int process_rx(rte_mbuf *m);

    u_int32_t get_identifier_address() { return offered_dhcp_server_identifier;}
    u_int32_t get_ip_address() {return offered_ip_addr;}
    u_int32_t get_subnet_mask() {return offered_subnet_mask;}
    u_int32_t get_broadcast_address() {return offered_broadcast_addr;}
    u_int32_t get_router() { return offered_router;}
    u_int32_t get_lease_time() { return offered_lease_time;}
    u_int32_t get_dhcp_state() { return dhcp_state;}
    void      get_client_hw_addr(rte_ether_addr &client_hw_addr) { memcpy(&client_hw_addr, discover_src_mac_addr, sizeof(rte_ether_addr)); }
};


# endif // DHCP_CLIENT_SESSION_H