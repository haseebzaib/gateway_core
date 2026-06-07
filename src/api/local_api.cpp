#include "gateway/api/local_api.hpp"

#include <chrono>
#include <iostream>

namespace gateway::api
{

LocalApi::LocalApi(const config::ConfigStore& config_store)
    : config_store_(config_store)
{
}

LocalApi::~LocalApi()
{
    stop();
}

void LocalApi::start()
{
    if (running_.exchange(true))
    {
        return;
    }

    thread_ = std::jthread([this] {
        run();
    });
}

void LocalApi::stop()
{
    running_ = false;
    if (thread_.joinable())
    {
        thread_.request_stop();
    }
}

void LocalApi::run()
{
    std::cout << "local API placeholder started, config="
              << config_store_.interface_config_path() << '\n';

    while (running_)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

} // namespace gateway::api

