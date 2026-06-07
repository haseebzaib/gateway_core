#include "gateway/core/application.hpp"

#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

namespace gateway::core
{

namespace
{
Application* active_application = nullptr;

void handle_signal(int)
{
    if (active_application)
    {
        active_application->request_stop();
    }
}
}

Application::Application()
    : config_store_(config::RuntimePaths{})
    , local_api_(config_store_)
{
}

int Application::run()
{
    active_application = this;
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    running_ = true;
    std::cout << "gatewayd starting\n";
    local_api_.start();

    while (running_)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    local_api_.stop();
    std::cout << "gatewayd stopped\n";
    active_application = nullptr;
    return 0;
}

void Application::request_stop()
{
    running_ = false;
}

} // namespace gateway::core

