#include "gateway/config/config_store.hpp"

namespace gateway::config
{

ConfigStore::ConfigStore(RuntimePaths paths)
    : paths_(std::move(paths))
{
}

const RuntimePaths& ConfigStore::paths() const noexcept
{
    return paths_;
}

std::filesystem::path ConfigStore::interface_config_path() const
{
    return paths_.storage_root / "engine" / "interfaces.json";
}

} // namespace gateway::config

