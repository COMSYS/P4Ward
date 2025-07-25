/* -*- P4_16 -*- */
#ifndef __PROTOCOL_OPCUA__
#define __PROTOCOL_OPCUA__

#include "helper.p4"

enum bit<24> opcua_message_type_t {
    MSG = 0x4d5347,
    OPN = 0x4f504e,
    ERR = 0x455252,
    CLO = 0x434c4f,
    HEL = 0x48454c,
    ACK = 0x41434b,
    RHE = 0x524845
}

header opcua_h {
    opcua_message_type_t message_type;
    bit<8> reserved;
    le_32b_t message_size;
}

header opcua_error_h {
    bit<32> error_id;
}

header opcua_asymmetric_algorithm_h {
    le_32b_t secure_channel_id;
    le_32b_t security_policy_uri_length;
    // http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
    // http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss
    // http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15
    // http://opcfoundation.org/UA/SecurityPolicy#Basic256
    // http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
    // http://opcfoundation.org/UA/SecurityPolicy#None
}

header opcua_security_policy_uri_1_h {
    bit<344> security_policy_uri; // 43 bytes -> http://opcfoundation.org/UA/SecurityPolicy#
}

header opcua_security_policy_uri_2_h {
    bit<32> security_policy_uri; // 4 bytes -> Aes1, Aes2, Basi, None
}

header opcua_security_policy_uri_3_h {
    bit<32> security_policy_uri; // 4 bytes -> 28_S, 56_S, c128, c256, c256
}

header opcua_security_policy_uri_4_h {
    bit<40> security_policy_uri; // 5 bytes -> ha256, ha256, Rsa15, Sha25
}

header opcua_security_policy_uri_5_h {
    bit<8> security_policy_uri; // 1 bytes -> _, 6
}

header opcua_security_policy_uri_6_h {
    bit<48> security_policy_uri; // 6 bytes -> RsaOae, RsaPss
}

header opcua_security_policy_uri_7_h {
    bit<8> security_policy_uri; // 1 bytes -> p
}

// header opcua_symmetric_algorithm_h {
//     bit<32> secure_channel_id;
//     bit<32> token_id;
// }

#endif