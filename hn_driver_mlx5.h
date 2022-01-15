#ifndef HN_DRIVER_MLX5_H
#define HN_DRIVER_MLX5_H

#include <iostream>
#include <map>
#include <functional>
#include <rte_ethdev.h>
#include "hn_driver.h"

class hn_driver_mlx5: public hn_driver
{
public:
    hn_driver_mlx5() {}
    ~hn_driver_mlx5() {}

        /**
     * @brief
     *      creates an instance of this object
     */
    static hn_driver* create() { return new hn_driver_mlx5();}

    void set_fdir_global_config(u_int16_t port_id, rte_eth_conf &port_conf) override;
    void set_fdir_filter(u_int16_t port_id) override;

};

#endif // HN_DRIVER_MLX5_H