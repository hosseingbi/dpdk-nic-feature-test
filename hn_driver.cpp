#include "hn_driver.h"

void hn_driver::set_rss_config(__rte_unused u_int16_t port_id, rte_eth_conf &port_conf) 
{
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP | ETH_RSS_NONFRAG_IPV6_TCP | ETH_RSS_NONFRAG_IPV6_UDP;
}

void hn_driver::set_fdir_global_config(__rte_unused u_int16_t port_id, __rte_unused  rte_eth_conf &port_conf) 
{
}

void hn_driver::set_fdir_filter(u_int16_t port_id)
{
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_queue queue;
    struct rte_flow_item_ipv4 ip_spec;
    struct rte_flow_item_ipv4 ip_mask;
    /* >8 End of declaring structs being used. */
    int res;

    queue.index = 1; // set dst queue

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* Set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    /* >8 End of setting the rule attribute. */

    /*
        * create the action sequence.
        * one action only,  move packet to queue
        */
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
        * set the first level of the pattern (ETH).
        * since in this example we just want to get the
        * ipv4 we set this level to allow all.
        */

    /* Set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    /* >8 End of setting the first level of the pattern. */

    /*
        * setting the second level of the pattern (IP).
        * in this example this is the level we care about
        * so we set it according to the parameters.
        */

    /* Setting the second level of the pattern. 8< */
    memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    ip_spec.hdr.type_of_service = 0x01;
    ip_mask.hdr.type_of_service = 0xFF;

    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;
    /* >8 End of setting the second level of the pattern. */

    /* The final level must be always type end. 8< */
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    /* >8 End of final level must be always type end. */

    rte_flow_error error;
    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, &error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, &error);
    /* >8 End of validation the rule and create it. */

    if(!flow)
    {
        printf("Flow can't be created %d message: %s\n", error.type, error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow");
    }
    
}