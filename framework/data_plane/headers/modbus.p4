/* -*- P4_16 -*- */
#ifndef __PROTOCOL_MODBUS__
#define __PROTOCOL_MODBUS__

header modbus_h {
    bit<16> transaction_id;

    // Protocol ID always zero for mudbus
    bit<16> protocol_id;
    
    // Number of following bytes = 1 (Unit ID) + 1 (Function Code) + N (Payload)
    bit<8> length_1;
    bit<8> length_2;

    bit<8> unit_id;
    bit<8> function_code;
}

header modbus_exception_h {
    bit<8> exception_type;
}

#endif