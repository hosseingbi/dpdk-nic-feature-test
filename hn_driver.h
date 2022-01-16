#ifndef HN_DRIVER_H
#define HN_DRIVER_H

#include <iostream>
#include <map>
#include <functional>
#include <rte_ethdev.h>

#define MAX_PATTERN_NUM         3
#define MAX_ACTION_NUM          2

class hn_driver
{
protected:
    int flow_dir_filter_config(u_int32_t portid, u_int32_t queue_id, uint8_t *flexbytes);
public:
    hn_driver() {}
    ~hn_driver() {}

    virtual void set_rss_config(u_int16_t port_id, rte_eth_conf &port_conf);
    virtual void set_fdir_global_config(u_int16_t port_id, rte_eth_conf &port_conf);
    virtual void set_fdir_filter(u_int16_t port_id);

};

class hn_driver_extend
{
private:
    /**
     * @brief it keeps a mapping between the name of the driver and a function to create an instance of the driver.
     */
    std::map<std::string, std::function<hn_driver*()>> driver_map;

public:

    /**
     * @brief 
     *      it registers a driver
     * @param driver_name 
     * @param driver_creator_handler 
     */
    void register_driver(std::string driver_name, std::function<hn_driver*()> driver_creator_handler)
    {
        driver_map[driver_name] = driver_creator_handler;
    }

    std::function<hn_driver*()> get_creator_handler(std::string driver_name) 
    {
        auto it = driver_map.find(driver_name);
        if(it == driver_map.end())
        {
            std::cerr<<"The driver \""<<driver_name<<"\" is not supported by this app"<<std::endl;
            return nullptr;
        }
        
        return it->second;
    }
};

#endif