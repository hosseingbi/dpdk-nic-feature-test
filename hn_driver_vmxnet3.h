#ifndef HN_DRIVER_VMXNET3_H
#define HN_DRIVER_VMXNET3_H

#include <iostream>
#include <map>
#include <functional>
#include <rte_ethdev.h>
#include "hn_driver.h"

class hn_driver_vmxnet3: public hn_driver
{
public:
    hn_driver_vmxnet3() {}
    ~hn_driver_vmxnet3() {}

        /**
     * @brief
     *      creates an instance of this object
     */
    static hn_driver* create() { return new hn_driver_vmxnet3();}


};

#endif // HN_DRIVER_VMXNET3_H