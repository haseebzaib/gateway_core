#include "spdlog/spdlog.h"
#include "gateway/core/application.hpp"
#include "gateway/core/interprocess.hpp"
#include "gateway/core/sensorprocess.hpp"
#include "gateway/core/deviceprocess.hpp"
#include "thread"
#include "chrono"



namespace core{

    namespace application {



        void run()
        {
          SPDLOG_INFO("Application started");
          std::jthread threadIpc(core::interprocess::main);
          std::jthread threadSensorProcess(core::sensorprocess::main);
          std::jthread threadDeviceProcess(core::deviceprocess::main);
        }



    }




}