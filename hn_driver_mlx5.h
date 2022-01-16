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


};

#endif // HN_DRIVER_MLX5_H