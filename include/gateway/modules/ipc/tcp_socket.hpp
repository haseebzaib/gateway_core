#pragma
#include "cstdint"
#include "string"
#include "string_view"
#include "array"
#include "stdint.h"
#include <type_traits>
#include <span>

namespace module
{

    namespace ipc
    {

        class tcpSocket
        {

        public:
            enum class state
            {
                idle,
                listening,
                connecting,
                connected,
                closed,
                error

            };
            tcpSocket() = default;
            ~tcpSocket();

            tcpSocket(const tcpSocket &) = delete;
            tcpSocket &operator=(const tcpSocket &) = delete;

            tcpSocket(tcpSocket &&other) noexcept;
            tcpSocket &operator=(tcpSocket &&other) noexcept;

            bool start_server(std::uint16_t port);
            bool connect_to(std::string_view ip, std::uint16_t port);
            state get_state();
            int poll_once(int timeout_ms);

            std::size_t send_data(std::span<const std::byte> data);
            std::size_t send_data(std::string_view text);

            template <typename T>
                requires std::is_trivially_copyable_v<T>
            std::size_t send_data(const T &value)
            {
                return send_data(std::as_bytes(std::span<const T, 1>{&value, 1}));
            }

            bool is_connected();
            void close();

        private:
            bool create_socket();
            bool set_non_blocking(int fd);
            void handle_accept();
            void handle_receive();
            void handle_send();
            int listen_fd_ = -1;
            int socket_fd_ = -1;

            state state_ = state::idle;
            std::array<std::uint8_t, 1024> tx_buffer_;
            std::array<std::uint8_t, 1024> rx_buffer_;
            std::size_t tx_size_ = 0;
            std::size_t tx_offset_ = 0;
        };

    }

}
