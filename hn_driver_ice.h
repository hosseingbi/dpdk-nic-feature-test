#ifndef HN_DRIVER_ICE_H
#define HN_DRIVER_ICE_H

#include <iostream>
#include <map>
#include <functional>
#include <rte_ethdev.h>
#include "hn_driver.h"

class hn_driver_ice: public hn_driver
{
public:
    hn_driver_ice() {}
    ~hn_driver_ice() {}

        /**
     * @brief
     *      creates an instance of this object
     */
    static hn_driver* create() { return new hn_driver_ice();}


};

#endif // HN_DRIVER_ICE_H