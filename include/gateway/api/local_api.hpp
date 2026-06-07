#pragma once

#include "gateway/config/config_store.hpp"

#include <atomic>
#include <thread>

namespace gateway::api
{

class LocalApi
{
public:
    explicit LocalApi(const config::ConfigStore& config_store);
    ~LocalApi();

    LocalApi(const LocalApi&) = delete;
    LocalApi& operator=(const LocalApi&) = delete;

    void start();
    void stop();

private:
    void run();

private:
    const config::ConfigStore& config_store_;
    std::atomic_bool running_ {false};
    std::jthread thread_ {};
};

} // namespace gateway::api

