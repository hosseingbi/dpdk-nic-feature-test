#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
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
#include <map>
#include <mutex>

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
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

static rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS][NB_SOCKETS];
static rte_mempool *pktmbuf_tx_pool[RTE_MAX_ETHPORTS][RTE_MAX_LCORE];
static std::vector<u_int32_t> lcoreids;
static std::vector<u_int32_t> rx_lcoreids;
static std::vector<u_int32_t> tx_lcoreids;
static hn_test *hn_tests[RTE_MAX_LCORE];

static rte_eth_conf port_conf;

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
static bool test_is_running = true;
static u_int32_t nb_test_finished = 0;
static std::mutex test_mutex;

enum TestType{HN_TEST_TYPE_RSS_IP = 0, HN_TEST_TYPE_RSS_UDP, HN_TEST_TYPE_RSS_TCP, HN_TEST_TYPE_FDIR}hn_test_type;
static std::map<std::string, TestType> test_valid_types = {{"RSS_IP",HN_TEST_TYPE_RSS_IP}, {"RSS_UDP",HN_TEST_TYPE_RSS_UDP}, 
															{"RSS_TCP",HN_TEST_TYPE_RSS_TCP}, {"FDIR",HN_TEST_TYPE_FDIR}};


static void print_usage(const char *prgname)
{
	std::string valid_types;
	for(auto it = test_valid_types.begin(); it != test_valid_types.end(); it++)
	{
		if(it != test_valid_types.begin())
			valid_types += "|";
		valid_types += it->first;
	}
	printf("%s [EAL options] -- --type <valid_type>\n\n"
	"Valid Types are: %s\n",
	prgname, valid_types.c_str());
}

static int parse_type(char *type)
{
	std::string type_str(type);
	bool found = false;
	for(auto vtype : test_valid_types)
	{
		if(vtype.first == type_str)
		{
			hn_test_type = vtype.second;
			found = true;
			break;
		}
	}
	if(!found)
	{
		std::cout<<"Wrong test type!!!"<<std::endl;
		std::cout<<"Valid types are: ";
		for(auto vtype : test_valid_types)
			std::cout<<vtype.first<<" ";
		std::cout<<std::endl;
		return -1;
	}

	return 0;
}

/**
 * @brief 
 * 		Parse the argument given in the command line of the application
 * @param argc 
 * @param argv 
 * @return int 
 */
static int parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{"type", required_argument, NULL, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "h", lgopts, &option_index)) != EOF) {

		switch (opt) {
		case 'h':
			print_usage(prgname);
			break;

		/* long options */
		case 0:
			if (!strncmp(lgopts[option_index].name, "type", 4)) 
			{
				int ret = parse_type(optarg);
				if(ret < 0)
					return -1;
			}

			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

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

void *print_stats(__rte_unused void *dummy) 
{
	while(true)
	{
		// print stats
		sleep(1);
	}
}

void print_final_result()
{}

/**
 * @brief 
 * 		wait for all the tests to be finished. Then you can set the test_is_running flag to false
 */
static void join_all_tests()
{
	test_mutex.lock();
	nb_test_finished++;
	test_mutex.unlock();
	while(nb_test_finished < tx_lcoreids.size()) {usleep(10000);}
	
	test_is_running = false;
}

void rx_main_loop(u_int32_t lcore_id, u_int16_t queueu_id)
{
	rte_mbuf *pkts_burst[MAX_PKT_BURST];

	while (test_is_running) 
	{
		u_int16_t nb_rx = rte_eth_rx_burst(1/* portid */, queueu_id, pkts_burst, MAX_PKT_BURST);
		if(hn_tests[lcore_id]->process_rx_burst_pkts(pkts_burst, nb_rx) < 0)
		{
			std::cerr<<"The test ended due to some technical failure"<<std::endl;
			exit(-1);
		}
	}
}

void tx_main_loop(u_int32_t lcore_id, u_int32_t queue_id)
{
	rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint64_t diff_tsc, cur_tsc, prev_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	prev_tsc = 0;
	u_int16_t burst_offset = 0;
	u_int32_t ret_burst_size = 0;

	while(true)
	{
		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) 
		{
			if(!burst_offset)
			{
				int ret = hn_tests[lcore_id]->get_burst_pkts(pkts_burst, MAX_PKT_BURST, ret_burst_size, pktmbuf_tx_pool[0][lcore_id]);
				if(ret == -1)
				{
					std::cerr<<"Some technical errors occured during sending the pkts!!!"<<std::endl;
					exit(-1);
				}
				else if(ret == 0)
					break; // end of the test
			}

			u_int16_t sent = rte_eth_tx_burst(0/*port id*/, queue_id, &pkts_burst[burst_offset], ret_burst_size - burst_offset);
			burst_offset += sent;
			if(burst_offset >= ret_burst_size)
				burst_offset = 0;
			prev_tsc = cur_tsc;
		}
	}

	join_all_tests();
}

static int main_loop(__rte_unused void *dummy)
{
	u_int32_t lcore_id = rte_lcore_id();
	enum LcoreType{LCORE_T_NONE = 0, LCORE_T_RX = 1, LCORE_T_TX = 2} lcore_type;
	lcore_type = LCORE_T_NONE;
	u_int32_t queue_id = 0;

	for(u_int32_t i=0; i<rx_lcoreids.size(); i++)
	{
		if(rx_lcoreids[i] == lcore_id)
		{
			lcore_type = LCORE_T_RX;
			queue_id = i;
			break;
		}
	}

	if(lcore_type == LCORE_T_NONE)
	{
		for(u_int32_t i=0; i<tx_lcoreids.size(); i++)
		{
			if(tx_lcoreids[i] == lcore_id)
			{
				lcore_type = LCORE_T_TX;
				queue_id = i;
				break;
			}
		}
	}

	if(lcore_id == rte_get_main_lcore())
	{
		pthread_t th_stats;
		pthread_create(&th_stats, NULL, print_stats, NULL);
	}

	switch(lcore_type)
	{
	case LCORE_T_NONE:
		std::cerr<<"lcore is not categorized neither of RX and TX cores!!!"<<std::endl;
		return -1;
		break;

	case LCORE_T_RX:
		tx_main_loop(lcore_id, queue_id);
		break;

	case LCORE_T_TX:
		rx_main_loop(lcore_id, queue_id);
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	non_trivial_init();

    /* init EAL */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid hn_test parameters\n");
	

    u_int32_t nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No ports found!\n");

	if(nb_ports != 2)
	{
		std::cerr<<"Number of ports should be equal to 2"<<std::endl;
		exit(-1);
	}

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

	u_int32_t lcore_id;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) 
	{
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	/* print the result of the test */
	print_final_result();

	/* clean up the EAL */
	rte_eal_cleanup();

    return 0;
}