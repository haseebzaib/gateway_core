#pragma
#include "cstdint"
#include "string"
#include "string_view"
#include "array"
#include "stdint.h"
#include <type_traits>
#include <span>
#include <optional>


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

            
            
            private:
            enum class messageType {
                unKnown,
                rs232Config,
                rs485ModbusConfig,
                tcpModbusConfig,
                sensorDustrakDataPort0,
                sensorDustrakDataPort1,
                sensorRs485ModbusPort0,
                sensorRs485ModbusPort1,
                sensorTcpModbusCon0,
                sensorTcpModbusCon1,
                sensorTcpModbusCon2,
                sensorTcpModbusCon3,
                sensorTcpModbusCon4,
                sensorTcpModbusCon5,
                sensorTcpModbusCon6,
                sensorTcpModbusCon7,
                sensorTcpModbusCon8,
                sensorTcpModbusCon9,
                sensorTcpModbusCon10,

                ack,
                nAck,
                status,
                heartBeat,

            };


        };




    
    
}