#pragma once

#include "gateway/modules/message_protocol/message_protocol.hpp"


namespace core::interprocess 
{


         // inline: one shared definition across all TUs that include this
         // header (interprocess.cpp, application.cpp, ...). Without it each
         // TU defines its own copy -> "multiple definition" at link.
         inline module::message_protocol::messageProtocol messageProtocol_;

        void main();
    
}

