#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <sys/param.h>
#include <iostream>
#include <vector>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>

#include "hn_test_rss.h"

#define NB_SOCKETS        8
#define MEMPOOL_CACHE_SIZE 256

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF(nports) RTE_MAX(	\
	(nports*nb_rx_queue*nb_rxd +		\
	nports*nb_lcores*MAX_PKT_BURST +	\
	nports*n_tx_queue*nb_txd +		\
	nb_lcores*MEMPOOL_CACHE_SIZE),		\
	(unsigned)8192)

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_TX_MBUF(nports) RTE_MAX(	\
	(nports*MAX_PKT_BURST +	\
	nports*nb_txd +		\
	MEMPOOL_CACHE_SIZE),		\
	(unsigned)8192)

#define JUMBO_FRAME_MAX_SIZE	0x2600
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define MAX_PKT_BURST 32

static rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS][NB_SOCKETS];
static rte_mempool *pktmbuf_tx_pool[RTE_MAX_ETHPORTS][RTE_MAX_LCORE];
static std::vector<u_int32_t> lcoreids;
static std::vector<u_int32_t> rx_lcoreids;
static std::vector<u_int32_t> tx_lcoreids;

static rte_eth_conf port_conf;

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static int init_mem(uint16_t portid, u_int32_t nb_mbuf, u_int32_t nb_tx_mbuf)
{
	char buf[PATH_MAX];
	int socketid;

	/* traverse through lcores and initialize structures on each socket */

	for (auto lcore_id : rx_lcoreids) 
	{

		socketid = rte_lcore_to_socket_id(lcore_id);

		if (socketid == SOCKET_ID_ANY)
			socketid = 0;

        if (socketid >= NB_SOCKETS)
			rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n", socketid, lcore_id, NB_SOCKETS);


        if (pktmbuf_pool[portid][socketid] == NULL) 
		{
			snprintf(buf, sizeof(buf), "mbuf_pool_%d:%d", portid, socketid);
			pktmbuf_pool[portid][socketid] = rte_pktmbuf_pool_create(buf, nb_mbuf, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (pktmbuf_pool[portid][socketid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n", socketid);
			else
				printf("Allocated mbuf pool on socket %d\n", socketid);
		}

	}

	for (auto lcore_id : tx_lcoreids) 
	{
		socketid = rte_lcore_to_socket_id(lcore_id);
	    if (pktmbuf_tx_pool[portid][lcore_id] == NULL) 
		{
			snprintf(buf, sizeof(buf), "mbuf_tx_pool_%d:%d", portid, lcore_id);
			pktmbuf_tx_pool[portid][lcore_id] = rte_pktmbuf_pool_create(buf, nb_tx_mbuf, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (pktmbuf_tx_pool[portid][lcore_id] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init tx mbuf pool on lcore_id %d\n", lcore_id);
			else
				printf("Allocated tx mbuf pool on lcore_id %d\n", lcore_id);
		}
	}

	return 0;
}

void non_trivial_init()
{	
	port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	port_conf.rxmode.mtu = JUMBO_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN;
	port_conf.rxmode.split_hdr_size = 0;
	port_conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
	port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_IP;
	port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
	port_conf.txmode.offloads = (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
}

int main(int argc, char **argv)
{
	non_trivial_init();

    /* init EAL */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");

    u_int32_t nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No ports found!\n");

	for (u_int32_t lcore_id = 0, i=0; lcore_id < RTE_MAX_LCORE; lcore_id++) 
	{
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		lcoreids.push_back(lcore_id);
		if(i%2)
			rx_lcoreids.push_back(lcore_id);
		else
			tx_lcoreids.push_back(lcore_id);
		i++;
	}

	u_int32_t nb_mbuf = RTE_MAX((nb_ports * rx_lcoreids.size() * nb_rxd + nb_ports * rx_lcoreids.size() * MAX_PKT_BURST + nb_ports * rx_lcoreids.size() * nb_rxd + 
									rx_lcoreids.size() * MEMPOOL_CACHE_SIZE), (unsigned)8192);
	u_int32_t nb_tx_mbuf = RTE_MAX((nb_ports * tx_lcoreids.size() * nb_txd + nb_ports * tx_lcoreids.size() * MAX_PKT_BURST + nb_ports * tx_lcoreids.size() * nb_txd + 
									tx_lcoreids.size() * MEMPOOL_CACHE_SIZE), (unsigned)8192);

    uint16_t portid;
	RTE_ETH_FOREACH_DEV(portid) 
	{

		init_mem(portid, nb_mbuf, nb_tx_mbuf);

		rte_eth_conf local_port_conf = port_conf;
		rte_eth_dev_info dev_info;

		/* limit the frame size to the maximum supported by NIC */
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n", portid, strerror(-ret));
		
		// change some port configs regarding hardware capabilities
		local_port_conf.rxmode.mtu = RTE_MIN( dev_info.max_mtu, local_port_conf.rxmode.mtu);
		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) 
			printf("Port %u modified RSS hash function based on hardware support,requested:%#" PRIx64 " configured:%#" PRIx64 "\n", portid,
				port_conf.rx_adv_conf.rss_conf.rss_hf, local_port_conf.rx_adv_conf.rss_conf.rss_hf);

		int socket = rte_lcore_to_socket_id(portid);
		if (socket == SOCKET_ID_ANY)
			socket = 0;

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot adjust number of descriptors: err=%d, port=%d\n", ret, portid);
		
		
		ret = rte_eth_dev_configure(portid, (uint16_t)rx_lcoreids.size(), (uint16_t)tx_lcoreids.size(), &local_port_conf);
		if (ret < 0) {
			printf("\n");
			rte_exit(EXIT_FAILURE, "Cannot configure device: "
				"err=%d, port=%d\n",
				ret, portid);
		}

		// initialize tx queues
		for (u_int32_t i=0; i < tx_lcoreids.size(); i++) 
		{
			u_int32_t lcore_id = tx_lcoreids[i];
			int socketid = rte_lcore_to_socket_id(lcore_id);

			if (socketid == SOCKET_ID_ANY)
				socketid = 0;

			printf("txq=%u,%d,%d ", lcore_id, i, socketid);
			fflush(stdout);

			rte_eth_txconf *txconf = &dev_info.default_txconf;
			txconf->offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, i, nb_txd, socketid, txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, portid);
		}

		// initialize rx queues
		for (u_int32_t i=0; i < rx_lcoreids.size(); i++) 
		{
			u_int32_t lcore_id = rx_lcoreids[i];
			int socketid = rte_lcore_to_socket_id(lcore_id);

			if (socketid == SOCKET_ID_ANY)
				socketid = 0;

			printf("rxq=%u,%d,%d ", lcore_id, i, socketid);
			fflush(stdout);

			rte_eth_rxconf *rxq_conf = &dev_info.default_rxconf;
			rxq_conf->offloads = local_port_conf.rxmode.offloads;
			ret = rte_eth_rx_queue_setup(portid, i, nb_rxd, socketid, rxq_conf, pktmbuf_pool[portid][socketid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, portid);
		}

		
	}

    return 0;
}