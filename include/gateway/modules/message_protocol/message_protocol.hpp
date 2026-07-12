#pragma once
#include "cstdint"
#include "string"
#include "string_view"
#include "array"
#include "stdint.h"
#include <type_traits>
#include <span>
#include <optional>
#include <atomic>
#include <cstdint>
#include <random>

#include <queue>
#include <mutex>
#include <optional>
#include <vector>
#include <deque>
#include <unordered_set>
#include <cstdint>
#include "gateway/modules/anomaly_detection/event.hpp"
#include "gateway/modules/modbus/modbus_client.hpp"
#include "gateway/utils/thirdparty/json.hpp"

/**
 * vision behind current message structure is that we send data in json like following
 * {"rs232Config" { "serial" {"bauderate":  , so on serial setting}, "Dustrak" { here comes dustrak setting}  }},
 * now if we have m,ultiple other configs as well they all get combined like following
 * {"rs485ModbusConfig" {}} and so on  , {"ack_required": true} at the end of message
 * each appl;ication if wanting ack wait for 2seconds and if not recived or 5seconds send same message again untill ack recived
 * {
 *  "message_id": "msg-001",
  "rs232Config": {
    laos add enabled with each because configuration can be there but port wont be enabled better to have it
    "serial": {
      "baudrate": 9600,
      "dataBits": 8,
      "parity": "none",
      "stopBits": 1
    },
    "Dustrak": {
      "enabled": true,
      "sampleRate": 1
    }
  },
  "rs485ModbusConfig": {
    "baudrate": 19200,
    "parity": "none",
    "slaveId": 1
  },
  "ack_required": true
}
 * **/

namespace module::message_protocol
{

  class messageProtocol
  {
  public:
    struct configMessage
    {
      std::string messageId {};
      std::string messageType {};
      nlohmann::json payload {};
    };

    struct deviceMetrics
    {
      std::uint64_t timestamp_ms;

      // --- cpu ---
      std::uint8_t coreCount;            // online cores now (4 today, may change)
      float cpuUsage;                    // overall busy %, 0-100
      std::vector<float> perCoreUsage;   // per-core %, size == coreCount
      float cpuTemp;                     // SoC temp °C (single sensor on Pi)
      std::vector<std::uint32_t> perCoreFreqMhz; // current clock per core, size == coreCount
      float loadAvg1m;
      float loadAvg5m;
      float loadAvg15m;
      std::uint8_t throttleFlags;        // vcgencmd low bits; 0 if unavailable

      // --- memory ---
      float ramUsedMb;
      float ramTotalMb;
      float swapUsedMb;

      // --- storage (root fs / eMMC) ---
      float diskUsedPct;
      float emmcUsedMb;
      float emmcTotalMb;
      std::uint8_t emmcLifeUsed;         // 0-100 %, 0 if unavailable

      // --- misc ---
      std::uint64_t uptimeSec;
    };

    // public so the JSON serializer (NLOHMANN_JSON_SERIALIZE_ENUM below the
    // class) can name the type. Values pinned so the wire format stays stable
    // even if entries are reordered later.
    enum class messageType
    {
      unKnown       = 0,
      deviceData    = 1,
      deviceAnamoly = 2,
      ack           = 3,
      nAck          = 4,
      status        = 5,
      heartBeat     = 6,
    };

    messageProtocol();
    ~messageProtocol();

    void send_device_data(deviceMetrics deviceData);
    void send_device_anomaly_data(const std::vector<anomaly_detection::anomalyEvent>& anomalyEvents);
    void send_rs232_sniffer_frame(const nlohmann::json& data);
    void send_modbus_samples(
        std::string_view sourceType,
        std::string_view sourceId,
        const std::vector<module::modbus::sample>& samples,
        const std::vector<module::modbus::readError>& errors,
        bool success);
    void send_modbus_status(
        std::string_view sourceType,
        std::string_view sourceId,
        std::string_view status,
        std::string_view error = {});
    void send_sensor_payload(
        std::string_view sourceType,
        std::string_view sourceId,
        const nlohmann::json& payload,
        bool success = true);

    // Accepts arbitrary TCP chunks and extracts complete newline-delimited JSON
    // frames. Configuration frames are validated, queued, and ACKed/NACKed.
    void receive(std::span<const std::uint8_t> bytes);
    std::optional<configMessage> get_next_config();

    std::optional<std::vector<std::uint8_t>> get_next_tx();

  private:
    std::uint64_t next_message_id();

    std::mutex tx_mutex_;
    std::mutex config_mutex_;
    std::deque<std::vector<std::uint8_t>> tx_queue_;
    std::queue<std::vector<std::uint8_t>> rx_queue_;
    std::queue<std::vector<std::uint8_t>> ack_required_queue_;
    std::queue<configMessage> config_queue_;
    std::deque<std::string> recent_message_ids_;
    std::unordered_set<std::string> recent_message_id_set_;

    std::string rx_buffer_;

    std::uint64_t startupRandom_{0};
    std::atomic<std::uint64_t> counter_{1};
  };

  // Serializes messageType to/from its name string, e.g. "deviceData".
  // Must live at namespace scope (not inside the class) and after the enum
  // is fully defined. Found via ADL when assigning into an nlohmann::json.
  NLOHMANN_JSON_SERIALIZE_ENUM(messageProtocol::messageType, {
      {messageProtocol::messageType::unKnown,       "unknown"},
      {messageProtocol::messageType::deviceData,    "deviceData"},
      {messageProtocol::messageType::deviceAnamoly, "deviceAnamoly"},
      {messageProtocol::messageType::ack,           "ack"},
      {messageProtocol::messageType::nAck,          "nAck"},
      {messageProtocol::messageType::status,        "status"},
      {messageProtocol::messageType::heartBeat,     "heartBeat"},
  })

}
