cmake_minimum_required(VERSION 3.0.0)
project(mlx5-test VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(mlx5-test main.cpp hn_test_rss.cpp hn_test_fdir.cpp hn_test_rss_vxlan.cpp hn_driver.cpp hn_driver_mlx5.cpp hn_driver_ixgbe.cpp )

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

set(DPDK_BASE_PATH "/usr/src/dpdk-22.07")
set(DPDK_LIB_DIR "${DPDK_BASE_PATH}/debug/lib")
set(DPDK_DRIVERS_LIB_DIR "${DPDK_BASE_PATH}/debug/drivers")

set(DPDK_LIBS rte_node rte_graph rte_bpf rte_flow_classify rte_pipeline rte_table rte_port rte_fib rte_ipsec rte_vhost rte_stack 
                             rte_security rte_sched rte_reorder rte_rib rte_regexdev rte_rawdev rte_pdump rte_power rte_member rte_lpm rte_latencystats 
                             rte_kni rte_jobstats rte_ip_frag rte_gso rte_gro rte_eventdev rte_efd rte_distributor rte_cryptodev rte_compressdev rte_cfgfile 
                             rte_bitratestats rte_bbdev rte_acl rte_timer rte_hash rte_metrics rte_cmdline rte_pci rte_ethdev rte_meter rte_net rte_mbuf 
                             rte_mempool rte_rcu rte_ring rte_eal rte_telemetry rte_kvargs)


set(DPDK_DRIVER_LIBS rte_common_cpt rte_common_dpaax rte_common_iavf rte_common_octeontx rte_bus_auxiliary rte_bus_dpaa rte_bus_fslmc
                        rte_bus_ifpga rte_bus_pci rte_bus_vdev rte_bus_vmbus rte_common_cnxk rte_common_qat rte_common_sfc_efx rte_mempool_bucket rte_mempool_cnxk
                        rte_mempool_dpaa rte_mempool_dpaa2 rte_mempool_octeontx rte_mempool_ring rte_mempool_stack rte_dma_cnxk rte_dma_dpaa rte_dma_dpaa2 
                        rte_dma_hisilicon rte_dma_idxd rte_dma_ioat rte_dma_skeleton rte_net_af_packet
                        rte_net_ark rte_net_atlantic rte_net_avp rte_net_axgbe rte_net_bnx2x rte_net_bnxt rte_net_bond rte_net_cnxk rte_net_cxgbe rte_net_dpaa rte_net_dpaa2
                        rte_net_e1000 rte_net_ena rte_net_enetc rte_net_enic rte_net_failsafe rte_net_fm10k rte_net_hinic rte_net_hns3 rte_net_i40e rte_net_iavf
                        rte_net_ice rte_net_igc rte_net_ionic rte_net_ixgbe rte_net_kni rte_net_liquidio rte_net_memif rte_net_netvsc rte_net_nfp rte_net_ngbe
                        rte_net_null rte_net_octeontx rte_net_octeontx_ep rte_net_pfe rte_net_qede rte_net_ring rte_net_softnic
                        rte_net_tap rte_net_thunderx rte_net_txgbe rte_net_vdev_netvsc rte_net_vhost rte_net_virtio rte_net_vmxnet3 rte_net_mlx5 rte_raw_cnxk_bphy rte_raw_dpaa2_cmdif
                        rte_raw_ntb rte_raw_skeleton rte_crypto_bcmfs rte_crypto_caam_jr
                        rte_crypto_cnxk rte_crypto_dpaa_sec rte_crypto_dpaa2_sec rte_crypto_nitrox rte_crypto_null rte_crypto_octeontx
                        rte_crypto_scheduler rte_crypto_virtio rte_compress_octeontx rte_vdpa_ifc rte_event_cnxk rte_event_dlb2 rte_event_dpaa
                        rte_event_dpaa2 rte_event_dsw rte_event_opdl rte_event_skeleton rte_event_sw rte_event_octeontx rte_baseband_acc100
                        rte_baseband_fpga_5gnr_fec rte_baseband_fpga_lte_fec rte_baseband_null rte_baseband_turbo_sw 
                        rte_crypto_mlx5 rte_compress_mlx5 rte_regex_mlx5 rte_vdpa_mlx5 rte_common_mlx5)

set(EXTRA_LIBS pthread m dl numa ibverbs mlx5)

list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/eal/include/)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/config/)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/eal/linux/include/)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/eal/x86/include)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/eal/common)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/eal)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/kvargs )
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/metrics)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/telemetry)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/mempool)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/ring)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/net)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/mbuf)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/ethdev)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/meter)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/cmdline)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/lib/hash)
list(APPEND DPDK_INCLUDE_PATHS ${DPDK_BASE_PATH}/debug)

set(DPDK_DEFS _FILE_OFFSET_BITS=64 _GNU_SOURCE ALLOW_EXPERIMENTAL_API)


set(LDDPDK -lrte_common_cpt,-lrte_common_dpaax,-lrte_common_iavf,-lrte_common_octeontx,-lrte_bus_auxiliary,-lrte_bus_dpaa,-lrte_bus_fslmc,-lrte_bus_ifpga,-lrte_bus_pci,-lrte_bus_vdev,-lrte_bus_vmbus,-lrte_common_cnxk,-lrte_common_mlx5,-lrte_common_qat,-lrte_common_sfc_efx,-lrte_mempool_bucket,-lrte_mempool_cnxk,-lrte_mempool_dpaa,-lrte_mempool_dpaa2,-lrte_mempool_octeontx,-lrte_mempool_ring,-lrte_mempool_stack,-lrte_dma_cnxk,-lrte_dma_dpaa,-lrte_dma_dpaa2,-lrte_dma_hisilicon,-lrte_dma_idxd,-lrte_dma_ioat,-lrte_dma_skeleton,-lrte_net_af_packet,-lrte_net_ark,-lrte_net_atlantic,-lrte_net_avp,-lrte_net_axgbe,-lrte_net_bnx2x,-lrte_net_bnxt,-lrte_net_bond,-lrte_net_cnxk,-lrte_net_cxgbe,-lrte_net_dpaa,-lrte_net_dpaa2,-lrte_net_e1000,-lrte_net_ena,-lrte_net_enetc,-lrte_net_enetfec,-lrte_net_enic,-lrte_net_failsafe,-lrte_net_fm10k,-lrte_net_hinic,-lrte_net_hns3,-lrte_net_i40e,-lrte_net_iavf,-lrte_net_ice,-lrte_net_igc,-lrte_net_ionic,-lrte_net_ixgbe,-lrte_net_kni,-lrte_net_liquidio,-lrte_net_memif,-lrte_net_mlx5,-lrte_net_netvsc,-lrte_net_nfp,-lrte_net_ngbe,-lrte_net_null,-lrte_net_octeontx,-lrte_net_octeontx_ep,-lrte_net_pcap,-lrte_net_pfe,-lrte_net_qede,-lrte_net_ring,-lrte_net_softnic,-lrte_net_tap,-lrte_net_thunderx,-lrte_net_txgbe,-lrte_net_vdev_netvsc,-lrte_net_vhost,-lrte_net_virtio,-lrte_net_vmxnet3,-lrte_raw_cnxk_bphy,-lrte_raw_cnxk_gpio,-lrte_raw_dpaa2_cmdif,-lrte_raw_ntb,-lrte_raw_skeleton,-lrte_crypto_bcmfs,-lrte_crypto_caam_jr,-lrte_crypto_cnxk,-lrte_crypto_dpaa_sec,-lrte_crypto_dpaa2_sec,-lrte_crypto_mlx5,-lrte_crypto_nitrox,-lrte_crypto_null,-lrte_crypto_octeontx,-lrte_crypto_scheduler,-lrte_crypto_virtio,-lrte_compress_mlx5,-lrte_compress_octeontx,-lrte_compress_zlib,-lrte_regex_mlx5,-lrte_regex_cn9k,-lrte_vdpa_ifc,-lrte_vdpa_mlx5,-lrte_vdpa_sfc,-lrte_event_cnxk,-lrte_event_dlb2,-lrte_event_dpaa,-lrte_event_dpaa2,-lrte_event_dsw,-lrte_event_opdl,-lrte_event_skeleton,-lrte_event_sw,-lrte_event_octeontx,-lrte_baseband_acc100,-lrte_baseband_fpga_5gnr_fec,-lrte_baseband_fpga_lte_fec,-lrte_baseband_la12xx,-lrte_baseband_null,-lrte_baseband_turbo_sw,-lrte_node,-lrte_graph,-lrte_flow_classify,-lrte_pipeline,-lrte_table,-lrte_pdump,-lrte_port,-lrte_fib,-lrte_ipsec,-lrte_vhost,-lrte_stack,-lrte_security,-lrte_sched,-lrte_reorder,-lrte_rib,-lrte_dmadev,-lrte_regexdev,-lrte_rawdev,-lrte_power,-lrte_pcapng,-lrte_member,-lrte_lpm,-lrte_latencystats,-lrte_kni,-lrte_jobstats,-lrte_ip_frag,-lrte_gso,-lrte_gro,-lrte_gpudev,-lrte_eventdev,-lrte_efd,-lrte_distributor,-lrte_cryptodev,-lrte_compressdev,-lrte_cfgfile,-lrte_bpf,-lrte_bitratestats,-lrte_bbdev,-lrte_acl,-lrte_timer,-lrte_hash,-lrte_metrics,-lrte_cmdline,-lrte_pci,-lrte_ethdev,-lrte_meter,-lrte_net,-lrte_mbuf,-lrte_mempool,-lrte_rcu,-lrte_ring,-lrte_eal,-lrte_telemetry,-lrte_kvargs)

set(DPDK_FLAGS "-pipe -Wall -Winvalid-pch -include rte_config.h -Wextra -Wcast-qual -Wdeprecated -Wformat -Wformat-nonliteral -Wundef -Wwrite-strings -Wno-missing-field-initializers -march=native -MD -MQ -m32 -mssse3")

target_include_directories(mlx5-test PRIVATE . ${DPDK_INCLUDE_PATHS})
target_link_directories(mlx5-test PRIVATE ${DPDK_LIB_DIR} ${DPDK_DRIVERS_LIB_DIR})
target_link_libraries(mlx5-test -Wl,-export-dynamic -Wl,--whole-archive  z m rt -Wl,--start-group  rt m dl ibverbs mlx5 mtcr_ul -Wl,--end-group -Wl,--no-whole-archive -Wl,-Bstatic,--whole-archive,${LDDPDK},--no-whole-archive -Wl,-Bdynamic pcap pthread numa)
target_compile_definitions(mlx5-test PRIVATE ${DPDK_DEFS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 ${DPDK_FLAGS}" )
# add_definitions(-std=c++17)