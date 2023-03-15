#include "hn_driver.h"

enum layer_name {
	L2,
	L3,
	L4,
	TUNNEL,
	L2_INNER,
	L3_INNER,
	L4_INNER,
	END
};

void hn_driver::set_rss_config(__rte_unused u_int16_t port_id, rte_eth_conf &port_conf) 
{
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_NONFRAG_IPV6_UDP;
}

void hn_driver::set_rss_vxlan_inner_config(__rte_unused u_int16_t port_id, rte_eth_conf &port_conf)
{
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP;
}

void hn_driver::set_rss_vxlan_rte_flow_config(uint16_t port_id, u_int32_t nb_queues)
{
    u_int16_t queues[RTE_MAX_LCORE];
    for(u_int32_t i=0; i<nb_queues; i++)
        queues[i] = i;
    struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr;

    memset(&attr, 0, sizeof(rte_flow_attr));
    attr.group = 0;
    attr.ingress = 1;
    attr.priority = 1;

    rte_flow_item pattern[8];
    for(u_int32_t i=0; i<=END; i++)
    {
        pattern[i].type = RTE_FLOW_ITEM_TYPE_VOID;
        pattern[i].spec = NULL;
        pattern[i].mask = NULL;
        pattern[i].last = NULL;
    }

	// uint8_t symmetric_rss_key[] = {
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// };

    uint8_t xena_hash_key[] = 
    {
        0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
        0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
        0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
        0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
        0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA
    }; 


	struct rte_flow_action_rss rss;
    memset(&rss, 0, sizeof(rte_flow_action_rss));
    rss.level = 2;
    rss.queue = queues;
    rss.queue_num = nb_queues;
    rss.types = RTE_ETH_RSS_IP|RTE_ETH_RSS_NONFRAG_IPV4_UDP|RTE_ETH_RSS_NONFRAG_IPV4_TCP;
    rss.key = xena_hash_key;
    rss.key_len = sizeof(xena_hash_key);


	struct rte_flow_action actions[2];
    memset(&actions, 0, 2*sizeof(rte_flow_action));
    actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    actions[0].conf = &rss;
    actions[1].type = RTE_FLOW_ACTION_TYPE_END;



	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L3].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[TUNNEL].type = RTE_FLOW_ITEM_TYPE_VXLAN;
    pattern[L2_INNER].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L3_INNER].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L4_INNER].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[END].type = RTE_FLOW_ITEM_TYPE_END;

	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow) 
    {
		printf("can't create UL symmetric RSS flow on inner ip. %s\n", error.message);
	}
}

void hn_driver::set_rss_qinxq_config(__rte_unused u_int16_t port_id, rte_eth_conf &port_conf)
{
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP;
}

void hn_driver::set_rss_qinxq_rte_flow_config(uint16_t port_id, u_int32_t nb_queues, __rte_unused u_int32_t nb_vlans)
{
    u_int16_t queues[RTE_MAX_LCORE];
    for(u_int32_t i=0; i<nb_queues; i++)
        queues[i] = i;
    struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr;
    struct rte_flow_item_eth  item_eth_mask;
    struct rte_flow_item_eth  item_eth_spec;
    struct rte_flow_item_vlan  item_vlan_mask[6];
    struct rte_flow_item_vlan  item_vlan_spec[6];

    struct rte_flow_item_raw item_raw_spec;
    struct rte_flow_item_raw item_raw_mask;

    memset(&item_raw_spec, 0, sizeof(struct rte_flow_item_raw));
    memset(&item_raw_mask, 0, sizeof(struct rte_flow_item_raw));

    memset(&item_eth_mask, 0, sizeof(struct rte_flow_item_eth));
    memset(&item_eth_spec, 0, sizeof(struct rte_flow_item_eth));
    
    memset(item_vlan_mask, 0, sizeof(struct rte_flow_item_vlan) * 6);
    memset(item_vlan_spec, 0, sizeof(struct rte_flow_item_vlan) * 6);

    memset(&attr, 0, sizeof(rte_flow_attr));
    attr.group = 0;
    attr.ingress = 1;
    attr.priority = 1;

    rte_flow_item pattern[8];
    for(u_int32_t i=0; i<=END; i++)
    {
        pattern[i].type = RTE_FLOW_ITEM_TYPE_VOID;
        pattern[i].spec = NULL;
        pattern[i].mask = NULL;
        pattern[i].last = NULL;
    }

	// uint8_t symmetric_rss_key[] = {
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// 	0x6D, 0x5A, 0x6D, 0x5A,
	// };

    uint8_t xena_hash_key[] = 
    {
        0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
        0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
        0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
        0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
        0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA
    }; 


	struct rte_flow_action_rss rss;
    memset(&rss, 0, sizeof(rte_flow_action_rss));
    rss.level = 1;
    rss.queue = queues;
    rss.queue_num = nb_queues;
    rss.types = RTE_ETH_RSS_IP|RTE_ETH_RSS_NONFRAG_IPV4_UDP|RTE_ETH_RSS_NONFRAG_IPV4_TCP;
    rss.key = xena_hash_key;
    rss.key_len = sizeof(xena_hash_key);

    struct rte_flow_action_queue queue;
    queue.index = 1;


	struct rte_flow_action actions[2];
    memset(&actions, 0, 2*sizeof(rte_flow_action));
    actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    actions[0].conf = &queue;
    actions[1].type = RTE_FLOW_ACTION_TYPE_END;




    


    item_eth_spec.hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_VLAN);
    item_eth_mask.hdr.ether_type = RTE_BE16(0xFFFF);

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].mask = &item_eth_mask;
    pattern[0].spec = &item_eth_spec;

    // item_vlan_spec.has_more_vlan = 1;
    // item_vlan_mask.has_more_vlan = 1;
    item_vlan_spec[0].hdr.eth_proto = RTE_BE16(RTE_ETHER_TYPE_VLAN);
    item_vlan_mask[0].hdr.eth_proto = RTE_BE16(0xFFFF);

    pattern[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
    pattern[1].mask = &item_vlan_mask[0];
    pattern[1].spec = &item_vlan_spec[0];

    item_vlan_spec[1].hdr.eth_proto = RTE_BE16(RTE_ETHER_TYPE_IPV4);
    item_vlan_mask[1].hdr.eth_proto = RTE_BE16(0xFFFF);

    pattern[2].type = RTE_FLOW_ITEM_TYPE_VLAN;
    pattern[2].mask = &item_vlan_mask[1];
    pattern[2].spec = &item_vlan_spec[1];
    pattern[3].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[4].type = RTE_FLOW_ITEM_TYPE_END;

	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow) 
    {
		printf("can't create UL symmetric RSS flow on inner ip. %s\n", error.message);
	}
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