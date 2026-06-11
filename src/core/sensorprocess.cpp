#include "gateway/core/sensorprocess.hpp"
#include "gateway/modules/serial/serial.hpp"
#include "gateway/modules/dustrak/drx_85xx.hpp"
#include "gateway/modules/modbus/modbus_client.hpp"
#include "thread"
#include "chrono"
#include <array>
#include <string_view>




namespace core::sensorprocess 
{

    constexpr std::array<rs232PortMapping,2> rs232PortMapping_ = {
      {
        {"port_0",rs232Ch0Path,0},
        {"port_1",rs232Ch1Path,1},
      } 
    };

    constexpr std::array<rs485PortMapping,2> rs485PortMapping_ = {
      {
        {"port_0",rs485Ch2Path,0},
        {"port_1",rs485Ch3Path,1},
      } 
    };





    void main()
    {


        while(1)
        {

          std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }



}