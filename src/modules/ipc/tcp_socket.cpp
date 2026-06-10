#include "gateway/modules/ipc/tcp_socket.hpp"
#include "arpa/inet.h"
#include "fcntl.h"
#include "netinet/in.h"
#include "poll.h"
#include "sys/socket.h"
#include "unistd.h"
#include "cstring"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <cerrno>

namespace module
{

    namespace ipc
    {

        tcpSocket::~tcpSocket()
        {
            close();
        }

        bool tcpSocket::start_server(std::uint16_t port)
        {
             SPDLOG_INFO("Starting Server ");
            close();

            listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);

            if (listen_fd_ < 0)
            {
                SPDLOG_INFO("IPC socket create failed: {}", std::strerror(errno));
                return false;
            }

            int opt = 1;
            setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(port);

            if (bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
            {
                SPDLOG_INFO("IPC bind failed on port {}: {}", port, std::strerror(errno));
                close();
                return false;
            }

            if (listen(listen_fd_, 1) < 0)
            {
                SPDLOG_INFO("IPC listen failed on port {}: {}", port, std::strerror(errno));
                close();
                return false;
            }

            if (!set_non_blocking(listen_fd_))
            {
                SPDLOG_INFO("IPC set listen socket non-blocking failed: {}", std::strerror(errno));
                close();
                return false;
            }

            state_ = state::listening;
            SPDLOG_INFO("IPC server listening on 0.0.0.0:{}", port);

            return true;
        }

        bool tcpSocket::connect_to(std::string_view ip, std::uint16_t port)
        {
            close();
            socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
            if (socket_fd_ < 0)
            {
                close();
                return false;
            }

            if (!set_non_blocking(socket_fd_))
            {
                SPDLOG_INFO("IPC set client socket non-blocking failed: {}", std::strerror(errno));
                close();
                return false;
            }
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);

            std::string ip_str(ip);

            if (inet_pton(AF_INET, ip_str.c_str(), &addr.sin_addr) <= 0)
            {
                close();
                return false;
            }

            int ret = connect(socket_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));

            if (ret == 0)
            {
                state_ = state::connected;
                return true;
            }

            if (errno == EINPROGRESS)
            {
                state_ = state::connecting;
                return true;
            }

            close();
            return false;
        }
        tcpSocket::state tcpSocket::get_state()
        {
            return state_;
        }
        int tcpSocket::poll_once(int timeout_ms)
        {

            if (state_ == state::listening)
            {

                pollfd pfd{};
                pfd.fd = listen_fd_;
                pfd.events = POLLIN;
                int ret = poll(&pfd, 1, timeout_ms);
                if (ret > 0 && (pfd.revents & POLLIN))
                {
                    handle_accept();
                }
            }

            if (state_ == state::connecting || state_ == state::connected)
            {
                pollfd pfd{};
                pfd.fd = socket_fd_;
                pfd.events = POLLIN;

                if (tx_offset_ < tx_size_ || state_ == state::connecting)
                {
                    pfd.events |= POLLOUT;
                }

                int ret = poll(&pfd, 1, timeout_ms);

                if (ret == 0)
                {
                    return 0;
                }

                if (ret < 0)
                {
                    return -1;
                }

                if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
                {
                    close();
                    state_ = state::error;
                    SPDLOG_INFO("Client disconnected ");
                    return -1;
                }

                if (state_ == state::connecting && (pfd.revents & POLLOUT))
                {
                    int error = 0;
                    socklen_t len = sizeof(error);

                    if (getsockopt(socket_fd_, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0)
                    {
                        close();
                        state_ = state::error;
                        return -1;
                    }

                    state_ = state::connected;
                }

                if (pfd.revents & POLLIN)
                {
                    handle_receive();
                }

                if (pfd.revents & POLLOUT)
                {
                    handle_send();
                }
            }

            return 0;
        }

        bool tcpSocket::is_connected()
        {
            if(state_ == state::connected)
            {
                   return true;
            }
            return false;
        }
        void tcpSocket::close()
        {
            SPDLOG_INFO("Closing connection ");
            if (socket_fd_ >= 0)
            {
                ::close(socket_fd_);
                socket_fd_ = -1;
            }

            if (listen_fd_ >= 0)
            {
                ::close(listen_fd_);
                listen_fd_ = -1;
            }
            rx_buffer_.fill(0);
            tx_buffer_.fill(0);
            tx_size_ = 0;
            tx_offset_ = 0;

            state_ = state::closed;
        }

        std::size_t tcpSocket::send_data(std::span<const std::byte> data)
        {
            if (state_ != state::connected)
            {
                return 0;
            }

            if (tx_offset_ < tx_size_)
            {
                return 0;
            }

            if (data.size() > tx_buffer_.size())
            {
                return 0;
            }
            std::memcpy(tx_buffer_.data(), data.data(), data.size());
            tx_size_ = data.size();
            tx_offset_ = 0;

            return data.size();
        }

        std::size_t tcpSocket::send_data(std::string_view text)
        {

            return send_data(std::as_bytes(std::span{text.data(), text.size()}));
        }


            std::optional<std::span<const std::uint8_t>> tcpSocket::get_received() {

                if(rx_size == 0)
                {
                    return std::nullopt;
                }
                int size = rx_size;
                rx_size = 0;

                return std::span<const std::uint8_t>{rx_buffer_.data(),size};
                
            }



        bool tcpSocket::create_socket()
        {

            return false;
        }
        bool tcpSocket::set_non_blocking(int fd)
        {
            int flags = fcntl(fd, F_GETFL, 0);

            if (flags < 0)
            {
                return false;
            }

            return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
        }
        void tcpSocket::handle_accept()
        {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);

            int client_fd = accept(listen_fd_, reinterpret_cast<sockaddr *>(&client_addr), &client_len);

            if (client_fd < 0)
                return;

            set_non_blocking(client_fd);

            socket_fd_ = client_fd;
            state_ = state::connected;

            ::close(listen_fd_);
            listen_fd_ = -1;

            char client_ip[INET_ADDRSTRLEN] = {};
            const char *ip = inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            SPDLOG_INFO("Client connected {}:{}", ip != nullptr ? ip : "unknown", ntohs(client_addr.sin_port));
        }
        void tcpSocket::handle_receive()
        {
            std::uint8_t buffer[1024];

            while (true)
            {
                ssize_t n = recv(socket_fd_, buffer, sizeof(buffer), 0);

                if (n > 0)
                {
                    std::copy(buffer, buffer + n, rx_buffer_.begin());
                    rx_size = n;

                    SPDLOG_INFO("Rx recived {}", std::string_view(reinterpret_cast<char*>(buffer), n));
                }
                else if (n == 0)
                {
                    SPDLOG_INFO("Peer connection closed");
                    close();
                    return;
                }
                else
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;

                    close();
                    return;
                }
            }
        }
        void tcpSocket::handle_send()
        {
            while (tx_offset_ < tx_size_)
            {
                ssize_t n = send(socket_fd_, tx_buffer_.data() + tx_offset_, tx_size_ - tx_offset_, 0);

                if (n > 0)
                {
                    tx_offset_ += static_cast<std::size_t>(n);
                    SPDLOG_INFO("tx sent {} bytes", n);
                    if (tx_offset_ == tx_size_)
                    {
                        tx_buffer_.fill(0);
                        tx_size_ = 0;
                        tx_offset_ = 0;
                    }
                }
                else if (n < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;

                    close();
                    return;
                }
                else
                {
                    break;
                }
            }
        }
    }

}
