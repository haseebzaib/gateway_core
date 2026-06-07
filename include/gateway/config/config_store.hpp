#pragma once

#include <filesystem>
#include <string>

namespace gateway::config
{

struct RuntimePaths
{
    std::filesystem::path gateway_root {"/opt/gateway"};
    std::filesystem::path storage_root {"/opt/gateway/software_storage"};
};

class ConfigStore
{
public:
    explicit ConfigStore(RuntimePaths paths);

    [[nodiscard]] const RuntimePaths& paths() const noexcept;
    [[nodiscard]] std::filesystem::path interface_config_path() const;

private:
    RuntimePaths paths_;
};

} // namespace gateway::config

