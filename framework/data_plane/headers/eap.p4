/* -*- P4_16 -*- */
#ifndef __PROTOCOL_EAP__
#define __PROTOCOL_EAP__

enum bit<8> eapol_version_t {
    VERSION_1 = 0x01
}

enum bit<8> eapol_type_t {
    EAP_PACKET = 0x00,
    START = 0x01,
    LOGOFF = 0x02,
    KEY = 0x03,
    ASF = 0x04
}

header eapol_h {
    eapol_version_t version;
    eapol_type_t type;
    bit<16> len;
}

enum bit<8> eap_code_t {
    REQUEST = 0x01,
    RESPONSE = 0x02,
    SUCCESS = 0x03,
    FAILURE = 0x04
}

header eap_h {
    eap_code_t code;
    bit<8> id;
    bit<16> len;
}

const bit<16> EAP_SIZE = 4;

enum bit<8> eap_msg_type_t {
    IDENTITY = 0x01,
    MD5 = 0x04, // MD5 Challenge
    OTP = 0x05 // One Time Password
}

header eap_msg_h {
    eap_msg_type_t type;
}

const bit<16> EAP_MSG_SIZE = EAP_SIZE + 1;

const bit<16> MD5_SIZE = 16;

header eap_md5_h {
    bit<8> value_size;
}

// Size of the OTP extension header
const bit<16> EAP_MD5_SIZE = EAP_MSG_SIZE + 1;

typedef bit<32> eap_sequence_id_t;
typedef bit<32> eap_seed_t;

header eap_otp_h {
    bit<8> value_size;
    bit<32> value_first;
    bit<32> value_second;
    bit<8> space_1;
    eap_sequence_id_t sequence_id;
    bit<8> space_2;
    eap_seed_t seed;
    bit<8> space_3;
}

const bit<32> EAP_OTP_ID_1 = 0x6f74702d; // 'otp-'
const bit<32> EAP_OTP_MD5_ID_2 = 0x6d643520; // 'md5 '
const bit<32> EAP_OTP_SHA1_ID_2 = 0x73686131; // 'sha1'
const bit<32> EAP_OTP_SHA2_ID_2 = 0x73686132; // 'sha2'
const bit<32> EAP_OTP_SHA3_ID_2 = 0x73686133; // 'sha3'

const bit<8> EAP_OTP_CHALLENGE_SIZE = 19;

const bit<16> EAP_OTP_SIZE = EAP_MSG_SIZE + 1;

/* EAP Authentication Metadata */
enum bit<8> eap_metadata_type_t {
    MESSAGE = 0x01,
    SUCCESS = 0x02,
    FAILURE = 0x03,
    ERROR = 0x04
}

header eap_metadata_h {
    eap_metadata_type_t type;
    bit<16> port;
}

#endif