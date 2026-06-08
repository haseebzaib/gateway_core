#include "gateway/core/interprocess.hpp"
#include "thread"
#include "chrono"
#include "spdlog/spdlog.h"
#include "gateway/modules/ipc/tcp_socket.hpp"



namespace core 
{
    namespace interprocess {
        void main()
        {
            module::ipc::tcpSocket socket;

            if (!socket.start_server(8765))
            {
                SPDLOG_ERROR("IPC server failed to start");
                return;
            }

               SPDLOG_INFO("IPC thread running");

            while(1)
            {

         

            socket.poll_once(50);
             static int counter = 0;

            if(socket.is_connected())
            {
        socket.send_data("hello from server " + std::to_string(counter++) + "\n");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        
            }

            //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        }
    }
}
