/* -*- P4_16 -*- */
#ifndef __CONTROLS_MODBUS_VALIDATOR__
#define __CONTROLS_MODBUS_VALIDATOR__

#include <core.p4>
#include <tna.p4>

#include "../../types.p4"

const bit<8> MODBUS_FLAG_NONE = 0x00;
const bit<8> MODBUS_FLAG_DISABLE_EXTENSIONS = 0x01;
const bit<8> MODBUS_FLAG_DISABLE_COILS = 0x02;
const bit<8> MODBUS_FLAG_DISABLE_DISCRETE_INPUTS = 0x04;
const bit<8> MODBUS_FLAG_DISABLE_HOLDING_REGISTERS = 0x08;
const bit<8> MODBUS_FLAG_DISABLE_INPUT_REGISTERS = 0x10;
const bit<8> MODBUS_FLAG_DISABLE_FILE_RECORD = 0x20;
const bit<8> MODBUS_FLAG_DISABLE_FIFO = 0x40;
const bit<8> MODBUS_FLAG_DISABLE_DEVICE_IDENTIFICATION = 0x80;

control ModBusValidatorControl(
    inout egress_headers_t headers,
    inout egress_metadata_t meta,
    in egress_intrinsic_metadata_t intr_meta,
    in egress_intrinsic_metadata_from_parser_t parser_meta,
    inout egress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout egress_intrinsic_metadata_for_output_port_t output_port_meta) {
    
    action set_flags(bit<8> validator_mask, bit<8> protocol_validator_mask) {
        meta.validator_mask = meta.validator_mask | validator_mask;
        meta.protocol_validator_mask = meta.protocol_validator_mask | protocol_validator_mask;
    }

    action drop() {
        deparser_meta.drop_ctl = 1;
        exit;
    }

    table modbus_function_codes {
        key = {
            headers.modbus.function_code: exact @name("value");
        }
        actions = {
            set_flags;
            @defaultonly drop;
        }
        size = 64;
        default_action = drop();
        // const entries = {
        //     0x01: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_DISABLE_COILS                 ); // Read Coils
        //     0x02: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_DISABLE_DISCRETE_INPUTS       ); // Read Discrete Inputs
        //     0x03: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_DISABLE_HOLDING_REGISTERS     ); // Read Multiple Holding Registers
        //     0x04: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_DISABLE_INPUT_REGISTERS       ); // Read Input Registers
        //     0x05: set_flags(VALIDATOR_FLAG_DISABLE_WRITE, MODBUS_FLAG_DISABLE_COILS                 ); // Write Single Coil
        //     0x06: set_flags(VALIDATOR_FLAG_DISABLE_WRITE, MODBUS_FLAG_DISABLE_HOLDING_REGISTERS     ); // Write Single Holding Register
        //  // 0x07: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_NONE                          ); // Read Exception Status (Serial Only)
        //  // 0x08: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_NONE                          ); // Diagnostic (Serial Only)
        //  // 0x0B: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_NONE                          ); // Get Com Event Counter (Serial Only)
        //  // 0x0C: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_NONE                          ); // Get Com Event (Serial Only)
        //     0x0F: set_flags(VALIDATOR_FLAG_DISABLE_WRITE, MODBUS_FLAG_DISABLE_COILS                 ); // Write Multiple Coils
        //     0x10: set_flags(VALIDATOR_FLAG_DISABLE_WRITE, MODBUS_FLAG_DISABLE_HOLDING_REGISTERS     ); // Write Multiple Holding Registers
        //  // 0x11: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_NONE                          ); // Report Server ID (Serial Only)
        //     0x14: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_DISABLE_FILE_RECORD           ); // Read File Record
        //     0x15: set_flags(VALIDATOR_FLAG_DISABLE_WRITE, MODBUS_FLAG_DISABLE_FILE_RECORD           ); // Write File Record
        //     0x16: set_flags(VALIDATOR_FLAG_DISABLE_WRITE, MODBUS_FLAG_DISABLE_HOLDING_REGISTERS     ); // Mask Write Register
        //     0x17: set_flags(VALIDATOR_FLAG_DISABLE_WRITE, MODBUS_FLAG_DISABLE_HOLDING_REGISTERS     ); // Read / Write Multiple Registers
        //     0x18: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_DISABLE_FIFO                  ); // Read FIFO Queue
        //     0x2B: set_flags(VALIDATOR_FLAG_NONE         , MODBUS_FLAG_DISABLE_DEVICE_IDENTIFICATION ); // Read Device Identification
        // }
    }

    table modbus_exceptions {
        key = {
            headers.modbus_exception.exception_type: exact @name("value");
        }
        actions = {
            NoAction;
            @defaultonly drop;
        }
        size = 16;
        default_action = drop();
        // const entries = {
        //     0x01: NoAction(); // ILLEGAL FUNCTION
        //     0x02: NoAction(); // ILLEGAL DATA ADDRESS
        //     0x03: NoAction(); // ILLEGAL DATA VALUE
        //     0x04: NoAction(); // SERVER DEVICE FAILURE
        //     0x05: NoAction(); // ACKNOWLEDGE
        //     0x06: NoAction(); // SERVER DEVICE BUSY
        //     0x08: NoAction(); // MEMORY PARITY ERROR 
        //     0x0A: NoAction(); // GATEWAY PATH UNAVAILABLE
        //     0x0B: NoAction(); // GATEWAY TARGET DEVICE FAILED TO RESPOND
        // }
    }

    apply {
        // 1: Drop packets with invalid payload lengths
        bit<16> modbus_payload_length = headers.modbus.length_1 ++ headers.modbus.length_2; // Workaround
        modbus_payload_length = modbus_payload_length + 6; // 2 /* Transaction ID */ + 2 /* Protocol ID */ + 2 /* Length */ (see modbus header)
        if (modbus_payload_length != headers.egress_meta.payload_length) {
            drop();
        }
        
        // 2: Drop packets with invalid function codes
        modbus_function_codes.apply();

        // 3: Drop packets with invalid exception codes
        if (headers.modbus_exception.isValid()) {
            meta.validator_mask = meta.validator_mask | VALIDATOR_FLAG_IS_NOT_SERVER;
            modbus_exceptions.apply();
        }
    }

}

#endif