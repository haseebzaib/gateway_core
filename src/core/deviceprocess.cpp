#include "gateway/core/deviceprocess.hpp"
#include "gateway/core/interprocess.hpp"
#include "gateway/modules/message_protocol/message_protocol.hpp"

#include "thread"
#include "chrono"
#include "spdlog/spdlog.h"
#include "spdlog/fmt/fmt.h"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/statvfs.h>

namespace core::deviceprocess
{
    namespace
    {
        using deviceMetrics = module::message_protocol::messageProtocol::deviceMetrics;

        constexpr int kSampleIntervalMs = 1000; // how often we sample + send
        constexpr int kEmmcLifeEveryN   = 2500; // refresh slow eMMC-life read every N cycles

        // One CPU's accumulated jiffies, split into busy vs idle.
        struct CpuTime
        {
            std::uint64_t total = 0;
            std::uint64_t idle  = 0;
        };

        // index 0 = aggregate ("cpu"), 1..N = per core ("cpu0".."cpuN-1")
        std::vector<CpuTime> read_cpu_times()
        {
            std::vector<CpuTime> out;
            std::ifstream f("/proc/stat");
            std::string line;
            while (std::getline(f, line))
            {
                if (line.rfind("cpu", 0) != 0)
                    break; // cpu lines are first; stop once they end

                std::istringstream ss(line);
                std::string label; // "cpu" or "cpuN"
                ss >> label;

                // user nice system idle iowait irq softirq steal guest guest_nice
                std::uint64_t v = 0, sum = 0, idle = 0;
                int col = 0;
                while (ss >> v)
                {
                    sum += v;
                    if (col == 3 || col == 4) // idle + iowait
                        idle += v;
                    ++col;
                }
                out.push_back({sum, idle});
            }
            return out;
        }

        float cpu_usage_pct(const CpuTime &prev, const CpuTime &cur)
        {
            const std::uint64_t dt = cur.total - prev.total;
            const std::uint64_t di = cur.idle - prev.idle;
            if (dt == 0)
                return 0.0f;
            return 100.0f * static_cast<float>(dt - di) / static_cast<float>(dt);
        }

        // read a whole small sysfs/proc file into a string
        std::string read_file(const char *path)
        {
            std::ifstream f(path);
            std::stringstream ss;
            ss << f.rdbuf();
            return ss.str();
        }

        float read_temp_c()
        {
            const std::string s = read_file("/sys/class/thermal/thermal_zone0/temp");
            if (s.empty())
                return 0.0f;
            return static_cast<float>(std::strtol(s.c_str(), nullptr, 10)) / 1000.0f;
        }

        std::uint32_t read_freq_mhz()
        {
            const std::string s = read_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq");
            if (s.empty())
                return 0;
            return static_cast<std::uint32_t>(std::strtoul(s.c_str(), nullptr, 10) / 1000); // kHz -> MHz
        }

        std::uint64_t read_uptime_sec()
        {
            const std::string s = read_file("/proc/uptime");
            if (s.empty())
                return 0;
            return static_cast<std::uint64_t>(std::strtod(s.c_str(), nullptr));
        }

        // /proc/meminfo values are in kB; we fill MB.
        void read_mem(deviceMetrics &m)
        {
            std::ifstream f("/proc/meminfo");
            std::string key;
            std::uint64_t val = 0;
            std::string unit;
            std::uint64_t memTotal = 0, memAvail = 0, swapTotal = 0, swapFree = 0;
            while (f >> key >> val >> unit)
            {
                if (key == "MemTotal:")       memTotal  = val;
                else if (key == "MemAvailable:") memAvail = val;
                else if (key == "SwapTotal:")  swapTotal = val;
                else if (key == "SwapFree:")   swapFree  = val;
            }
            m.ramTotalMb = static_cast<float>(memTotal) / 1024.0f;
            m.ramUsedMb  = static_cast<float>(memTotal - memAvail) / 1024.0f;
            m.swapUsedMb = static_cast<float>(swapTotal - swapFree) / 1024.0f;
        }

        // Storage is reported at two scopes:
        //  - diskUsedPct: fullness of the ROOT partition (the operational alarm:
        //    root filling up breaks logging/redis, regardless of chip size).
        //  - emmcTotalMb/emmcUsedMb: the whole physical eMMC/SD device, so you
        //    can see total chip capacity (e.g. 29.7 GB) vs how much is consumed
        //    across all of its partitions.
        void read_storage(deviceMetrics &m)
        {
            // root partition fullness (percent)
            struct statvfs root{};
            if (statvfs("/", &root) == 0)
            {
                const std::uint64_t total = static_cast<std::uint64_t>(root.f_blocks) * root.f_frsize;
                const std::uint64_t freeB = static_cast<std::uint64_t>(root.f_bfree) * root.f_frsize;
                m.diskUsedPct = total ? 100.0f * static_cast<float>(total - freeB) / static_cast<float>(total) : 0.0f;
            }

            // whole physical device size from sysfs (value is in 512-byte sectors)
            const std::string sz = read_file("/sys/block/mmcblk0/size");
            const std::uint64_t devBytes = sz.empty() ? 0 : std::strtoull(sz.c_str(), nullptr, 10) * 512ULL;
            m.emmcTotalMb = static_cast<float>(devBytes) / (1024.0f * 1024.0f);

            // sum used space across every mounted partition on mmcblk0
            std::uint64_t usedBytes = 0;
            std::ifstream mounts("/proc/mounts");
            std::string dev, mnt, rest;
            while (mounts >> dev >> mnt)
            {
                std::getline(mounts, rest); // discard the rest of the line
                if (dev.rfind("/dev/mmcblk0", 0) != 0)
                    continue;
                struct statvfs v{};
                if (statvfs(mnt.c_str(), &v) == 0)
                    usedBytes += (static_cast<std::uint64_t>(v.f_blocks) - v.f_bfree) * v.f_frsize;
            }
            m.emmcUsedMb = static_cast<float>(usedBytes) / (1024.0f * 1024.0f);
        }

        // vcgencmd get_throttled -> "throttled=0x...". Low 4 bits are the live
        // flags. Best effort: returns 0 if vcgencmd is missing or unreadable
        // (e.g. the process is not in the 'video' group / lacks /dev/vcio).
        std::uint8_t read_throttle_flags()
        {
            FILE *p = popen("vcgencmd get_throttled 2>/dev/null", "r");
            if (!p)
                return 0;
            char buf[128] = {0};
            std::uint8_t flags = 0;
            if (fgets(buf, sizeof(buf), p))
            {
                const char *eq = std::strchr(buf, '=');
                if (eq)
                    flags = static_cast<std::uint8_t>(std::strtoul(eq + 1, nullptr, 0) & 0xF);
            }
            pclose(p);
            return flags;
        }

        // /sys/block/mmcblk0/device/life_time -> "0x02 0x01" (typ A / typ B).
        // Each step = 10% of rated write life used. We report the worse of the
        // two as 0-100%. Returns 0 when the node is absent (SD cards, etc.).
        std::uint8_t read_emmc_life()
        {
            const std::string s = read_file("/sys/block/mmcblk0/device/life_time");
            if (s.empty())
                return 0;
            std::istringstream ss(s);
            unsigned a = 0, b = 0;
            ss >> std::hex >> a >> b;
            const unsigned worse = (a > b) ? a : b;
            return static_cast<std::uint8_t>(worse * 10); // step -> percent
        }
    } // namespace

    void main()
    {
        SPDLOG_INFO("deviceprocess thread running");

        // prime the CPU counters so the first computed usage is a real delta.
        std::vector<CpuTime> prev = read_cpu_times();
        std::uint8_t cachedEmmcLife = read_emmc_life();
        int cycle = 0;

        while (1)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(kSampleIntervalMs));

            std::vector<CpuTime> cur = read_cpu_times();

            deviceMetrics m{};
            m.timestamp_ms = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());

            // --- cpu usage: aggregate (index 0) + per core (1..N) ---
            if (!cur.empty() && cur.size() == prev.size())
            {
                m.cpuUsage = cpu_usage_pct(prev[0], cur[0]);
                m.coreCount = static_cast<std::uint8_t>(cur.size() - 1);
                m.perCoreUsage.reserve(m.coreCount);
                for (std::size_t i = 1; i < cur.size(); ++i)
                    m.perCoreUsage.push_back(cpu_usage_pct(prev[i], cur[i]));
            }
            prev = std::move(cur);

            m.cpuTemp    = read_temp_c();
            m.cpuFreqMhz = read_freq_mhz();

            double load[3] = {0, 0, 0};
            if (getloadavg(load, 3) == 3)
            {
                m.loadAvg1m  = static_cast<float>(load[0]);
                m.loadAvg5m  = static_cast<float>(load[1]);
                m.loadAvg15m = static_cast<float>(load[2]);
            }

            m.throttleFlags = read_throttle_flags();

            read_mem(m);
            read_storage(m);

            // eMMC life barely moves (months); refresh it occasionally only.
            if (++cycle >= kEmmcLifeEveryN)
            {
                cachedEmmcLife = read_emmc_life();
                cycle = 0;
            }
            m.emmcLifeUsed = cachedEmmcLife;

            m.uptimeSec = read_uptime_sec();

            // build "c0=12.3 c1=5.0 ..." for the per-core column
            std::string perCore;
            for (std::size_t i = 0; i < m.perCoreUsage.size(); ++i)
                perCore += fmt::format("c{}={:.1f} ", i, m.perCoreUsage[i]);

            SPDLOG_INFO(
                "deviceMetrics ts={} cpu={:.1f}% cores={} [{}] temp={:.1f}C "
                "freq={}MHz load={:.2f}/{:.2f}/{:.2f} throttle=0x{:X} "
                "ram={:.0f}/{:.0f}MB swap={:.0f}MB disk={:.1f}% "
                "emmc={:.0f}/{:.0f}MB life={}% up={}s",
                m.timestamp_ms, m.cpuUsage, static_cast<unsigned>(m.coreCount), perCore,
                m.cpuTemp, m.cpuFreqMhz, m.loadAvg1m, m.loadAvg5m, m.loadAvg15m,
                static_cast<unsigned>(m.throttleFlags), m.ramUsedMb, m.ramTotalMb, m.swapUsedMb,
                m.diskUsedPct, m.emmcUsedMb, m.emmcTotalMb, static_cast<unsigned>(m.emmcLifeUsed),
                m.uptimeSec);

            core::interprocess::messageProtocol_.send_device_data(m);
        }
    }

} // namespace core::deviceprocess
