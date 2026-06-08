#include "spdlog/spdlog.h"
#include "gateway/core/application.hpp"
#include "gateway/core/interprocess.hpp"
#include "thread"
#include "chrono"



namespace core{

    namespace application {



        void run()
        {
          SPDLOG_INFO("Application started");
          std::jthread threadIpc(core::interprocess::main);
        }



    }




}