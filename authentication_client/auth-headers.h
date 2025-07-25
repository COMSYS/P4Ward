#ifndef AUTH_HEADERS_H
#define AUTH_HEADERS_H

#include <arpa/inet.h>
#include <memory.h>
#include <stdint.h>

typedef uint8_t mac_address_t[6];

typedef enum ether_type {
  ETHER_TYPE_EAPOL = 0x888e,
} ether_type_t;

#pragma pack(push, 1)
typedef struct ethernet_header {
  mac_address_t dst_address;
  mac_address_t src_address;
  uint16_t ether_type;
} ethernet_header_t;
#pragma pack(pop)

void write_ethernet(uint8_t **packet, const mac_address_t src,
                    const mac_address_t dst, uint16_t ether_type);
void read_ethernet(uint8_t **packet, ethernet_header_t *header);

typedef enum eapol_type {
  EAPOL_TYPE_EAP_PACKET = 0x00,
  EAPOL_TYPE_START = 0x01,
  EAPOL_TYPE_LOGOFF = 0x02,
  EAPOL_TYPE_KEY = 0x03,
  EAPOL_TYPE_ASF = 0x04
} eapol_type_t;

#pragma pack(push, 1)
typedef struct eapol_header {
  uint8_t version;
  uint8_t type;
  uint16_t length;
} eapol_header_t;
#pragma pack(pop)

void write_eapol(uint8_t **packet, eapol_type_t type, uint16_t payload_length);
void read_eapol(uint8_t **packet, eapol_header_t *header);

typedef enum eap_code {
  EAP_CODE_REQUEST = 0x01,
  EAP_CODE_RESPONSE = 0x02,
  EAP_CODE_SUCCESS = 0x03,
  EAP_CODE_FAILURE = 0x04
} eap_code_t;

typedef enum eap_type {
  EAP_TYPE_IDENTITY = 0x01,
  EAP_TYPE_MD5 = 0x04,  // MD5 Challenge
  EAP_TYPE_OTP = 0x05   // One Time Password
} eap_type_t;

#pragma pack(push, 1)
typedef struct eap_header {
  uint8_t code;
  uint8_t id;
  uint16_t length;
} eap_header_t;
#pragma pack(pop)

void write_eap(uint8_t **packet, eap_code_t code, uint8_t id,
               uint16_t payload_length);
void read_eap(uint8_t **packet, eap_header_t *header);

void write_eap_type(uint8_t **packet, eap_type_t type);
void read_eap_type(uint8_t **packet, eap_type_t *type);

void write_eap_identity(uint8_t **packet, const char *identity,
                        size_t identity_length);

#pragma pack(push, 1)
typedef struct eap_md5_header {
  uint8_t value_size;
} eap_md5_header_t;
#pragma pack(pop)

void write_eap_md5(uint8_t **packet, uint8_t value_size, const uint8_t *value);
void read_eap_md5(uint8_t **packet, eap_md5_header_t *header, uint8_t *value);

#endif