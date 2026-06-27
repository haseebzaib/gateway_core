#include "gateway/core/interprocess.hpp"
#include "thread"
#include "chrono"
#include "spdlog/spdlog.h"
#include "gateway/modules/ipc/tcp_socket.hpp"

namespace core
{
    namespace interprocess
    {
        void main()
        {
            module::ipc::tcpSocket socket;

            if (!socket.start_server(8765))
            {
                SPDLOG_ERROR("IPC server failed to start");
                return;
            }

            SPDLOG_INFO("IPC thread running");

            while (1)
            {

                socket.poll_once(50);
                static int counter = 0;

                if (socket.is_connected())
                {
                    //  socket.send_data("hello from server " + std::to_string(counter++) + "\n");

                    std::optional<std::span<const std::uint8_t>> data = socket.get_received();

                    if (data.has_value())
                    {

                        SPDLOG_INFO("Rx recived on wire {}", std::string_view(reinterpret_cast<const char *>(data->data()), data->size()));
                    }

                    //  message_protocol.loop(*data);

                    while (auto tx = messageProtocol_.get_next_tx())
                    {
                        socket.send_data(std::as_bytes(std::span{tx->data(), tx->size()}));
                    }
                }

                if (socket.get_state() == module::ipc::tcpSocket::state::closed || socket.get_state() == module::ipc::tcpSocket::state::error)
                {
                    socket.start_server(8765);
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }
}
