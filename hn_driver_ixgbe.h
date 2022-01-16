#ifndef HN_DRIVER_IXGBE_H
#define HN_DRIVER_IXGBE_H

#include <iostream>
#include <map>
#include <functional>
#include <rte_ethdev.h>
#include "hn_driver.h"

class hn_driver_ixgbe: public hn_driver
{
public:
    hn_driver_ixgbe() {}
    ~hn_driver_ixgbe() {}

    /**
     * @brief
     *      creates an instance of this object
     */
    static hn_driver* create() { return new hn_driver_ixgbe();}


};

#endif // HN_DRIVER_IXGBE_H