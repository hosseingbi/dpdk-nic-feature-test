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
#include "hn_test_fdir.h"
#include "hn_driver_ixgbe.h"
#include "hn_driver_mlx5.h"

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
static hn_test_result *hn_tests_result;

static rte_eth_conf port_conf;

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
static bool test_is_running = true;
static u_int32_t nb_test_finished = 0;
static std::mutex test_mutex;

static hn_test_extend test_types;
static std::function<hn_test*(u_int32_t)> test_creator_handler;
static std::function<hn_test_result*(std::vector<hn_test *>)> test_result_creator_handler;
static hn_driver_extend nic_drivers;

static void register_test_types()
{
	test_types.register_test("rss_ip", hn_test_rss::create_udp, hn_test_result_rss::create);
	test_types.register_test("rss_udp", hn_test_rss::create_udp, hn_test_result_rss::create);
	test_types.register_test("rss_tcp", hn_test_rss::create_tcp, hn_test_result_rss::create);
	test_types.register_test("fdir", hn_test_fdir::create, hn_test_result_fdir::create);
}

static void register_drivers()
{
	nic_drivers.register_driver("net_ixgbe", hn_driver_ixgbe::create);
	nic_drivers.register_driver("net_mlx5", hn_driver_mlx5::create);
}


static void print_usage(const char *prgname)
{
	std::string valid_types = test_types.get_all_types_name_str();	
	printf("%s [EAL options] -- --type <valid_type>\n\n"
	"Valid Types are: %s\n",
	prgname, valid_types.c_str());
}

static uint8_t human_tbl[]={
    ' ',
    'K',
    'M',
    'G',
    'T'
};


std::string double_to_human_str(double num, std::string units)
{
    double abs_num=num;
    if (num<0.0) 
        abs_num=-num;
    int i=0;
    int max_cnt=sizeof(human_tbl)/sizeof(human_tbl[0]);
    double div =1.0;
    double f=1000.0;
    while ((abs_num > f ) && (i < max_cnt - 1)){
        abs_num/=f;
        div*=f;
        i++;
    }

    char buf [100];
    sprintf(buf,"%10.2f %c%s",num/div,human_tbl[i],units.c_str());
    std::string res(buf);
    return (res);
}

static int parse_type(char *type)
{
	std::string type_str(type);

	test_creator_handler = test_types.get_test_creator_handler(type_str);
	test_result_creator_handler = test_types.get_test_result_creator_handler(type_str);
	if(!test_creator_handler)
	{
		std::cout<<"Wrong test type!!!"<<std::endl;
		std::cout<<"Valid types are: "<< test_types.get_all_types_name_str()<<std::endl;		
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

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status()
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) 
	{
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) 
		{
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) 
			{
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n", portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) 
			{
				rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
				printf("Port %d %s\n", portid, link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) 
			{
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) 
		{
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) 
		{
			print_flag = 1;
			printf("\ndone\n");
		}
	}
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
	port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
	port_conf.rxmode.mtu = JUMBO_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN;
	port_conf.rxmode.split_hdr_size = 0;
	port_conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
	port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
	port_conf.txmode.offloads = (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
}

void *print_stats(__rte_unused void *dummy) 
{
	// set affinity to lcore 2
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(2, &cpuset);
	pthread_t current_thread = pthread_self();
	pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);

	rte_eth_stats stats[2];
	u_int64_t last_obytes[2] = {0};
	u_int64_t tx_rate[2] = {0};

	while(test_is_running)
	{
		for(u_int16_t portid=0; portid<2; portid++)
		{
			rte_eth_stats_get(portid,&stats[portid]);
			tx_rate[portid] = (stats[portid].obytes - last_obytes[portid])*8;
			last_obytes[portid] = stats[portid].obytes;
		}
		
		
		// clear screen
		const char clr[] = { 27, '[', '2', 'J', '\0' };
		const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };
			/* Clear screen and move to top left */
		printf("%s%s", clr, topLeft);

		printf(" %10s ","ports");
		for(u_int16_t portid=0; portid<2; portid++)
			printf("| %15d ",portid);
		printf("\n");
        printf(" -----------------------------------------------------------------------------------------\n");
		std::string names[]={"opackets","obytes","ipackets","ibytes","ierrors","oerrors","Tx Bw"};
		for (u_int16_t i=0; i<7; i++) 
		{
            printf(" %10s ",names[i].c_str());
            int j=0;
            for (j=0; j<2;j++) 
			{
                uint64_t cnt;
                switch (i) {
                case 0:
                    cnt=stats[j].opackets;
                    printf("| %15lu ",cnt);
                    break;
                case 1:
                    cnt=stats[j].obytes;
                    printf("| %15lu ",cnt);

                    break;
                case 2:
                    cnt=stats[j].ipackets;
                    printf("| %15lu ",cnt);

                    break;
                case 3:
                    cnt=stats[j].ibytes;
                    printf("| %15lu ",cnt);

                    break;
                case 4:
                    cnt=stats[j].ierrors;
                    printf("| %15lu ",cnt);

                    break;
                case 5:
                    cnt=stats[j].oerrors;
                    printf("| %15lu ",cnt);

                    break;
                case 6:
                    printf("| %15s ",double_to_human_str((double)tx_rate[j],"bps").c_str());
                    break;
                default:
                    cnt=0xffffff;
                }
            } /* ports */
            printf( "\n");
        }

		sleep(1);
	}

	return NULL;
}

void print_final_result()
{

	for(auto lcore: rx_lcoreids)
		hn_tests[lcore]->show_the_test_results();
	hn_tests_result->show_test_results();
}

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
	
	sleep(1); // wait 1 sec for packets to arrive

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
		rte_pktmbuf_free_bulk(pkts_burst, nb_rx);
	}
}

void tx_main_loop(u_int32_t lcore_id, u_int32_t queue_id)
{
	rte_mbuf *pkts_burst[MAX_PKT_BURST];
	// uint64_t diff_tsc, cur_tsc, prev_tsc;
	// const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	// prev_tsc = 0;
	u_int16_t burst_offset = 0;
	u_int32_t ret_burst_size = 0;

	while(true)
	{
		// cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		// diff_tsc = cur_tsc - prev_tsc;
		// if (unlikely(diff_tsc > drain_tsc)) 
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
			// prev_tsc = cur_tsc;
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

	case LCORE_T_TX:
		tx_main_loop(lcore_id, queue_id);
		break;

	case LCORE_T_RX:
		rx_main_loop(lcore_id, queue_id);
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	non_trivial_init();
	register_test_types();
	register_drivers();

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

	if(lcoreids.size() == 0)
	{
		std::cerr<<"The number of Lcores can not be zero"<<std::endl;
		exit(-1);
	}

	if(lcoreids.size() % 2)
	{
		std::cerr<<"The number of Lcores should be even"<<std::endl;
		exit(-1);
	}


	// initializing test instances
	std::vector<hn_test*> tmp_tests;
	for(auto lcore : lcoreids)
	{
		hn_tests[lcore] = test_creator_handler(lcore);
		tmp_tests.push_back(hn_tests[lcore]);
	}
	hn_tests_result = test_result_creator_handler(tmp_tests);


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
		// local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
		// if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) 
		// 	printf("Port %u modified RSS hash function based on hardware support,requested:%#" PRIx64 " configured:%#" PRIx64 "\n", portid,
		// 		port_conf.rx_adv_conf.rss_conf.rss_hf, local_port_conf.rx_adv_conf.rss_conf.rss_hf);

		auto driver_creator_handler = nic_drivers.get_creator_handler(std::string(dev_info.driver_name));
		if(!driver_creator_handler)
			exit(-1);
		
		// set driver global configuration
		std::shared_ptr<hn_driver> driver = std::shared_ptr<hn_driver>(driver_creator_handler());
		hn_tests[rx_lcoreids[0]]->update_nic_global_config(driver.get(), portid, local_port_conf);

		int socket = rte_lcore_to_socket_id(portid);
		if (socket == SOCKET_ID_ANY)
			socket = 0;

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot adjust number of descriptors: err=%d, port=%d\n", ret, portid);
		
		
		ret = rte_eth_dev_configure(portid, (uint16_t)rx_lcoreids.size(), (uint16_t)tx_lcoreids.size(), &local_port_conf);
		if (ret < 0) 
		{
			printf("\n");
			rte_exit(EXIT_FAILURE, "Cannot configure device: " "err=%d, port=%d\n", ret, portid);
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

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret, portid);

		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable: err=%s, port=%d\n", rte_strerror(-ret), portid);

		// set driver after nic start configuration
		hn_tests[rx_lcoreids[0]]->update_nic_after_start(driver.get(), portid);
	}

	check_all_ports_link_status();

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