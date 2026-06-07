#pragma once

#include "gateway/api/local_api.hpp"
#include "gateway/config/config_store.hpp"

#include <atomic>

namespace gateway::core
{

class Application
{
public:
    Application();

    int run();
    void request_stop();

private:
    config::ConfigStore config_store_;
    api::LocalApi local_api_;
    std::atomic_bool running_ {false};
};

} // namespace gateway::core

