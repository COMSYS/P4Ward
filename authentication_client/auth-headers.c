#include "auth-headers.h"

void write_ethernet(uint8_t **packet, const mac_address_t src,
                    const mac_address_t dst, uint16_t ether_type) {
  ethernet_header_t header = {
      .ether_type = htons(ether_type),
  };

  memcpy(header.src_address, src, sizeof(mac_address_t));
  memcpy(header.dst_address, dst, sizeof(mac_address_t));

  memcpy((void *)*packet, &header, sizeof(ethernet_header_t));
  *packet += sizeof(ethernet_header_t);
}

void read_ethernet(uint8_t **packet, ethernet_header_t *header) {
  memcpy(header, (void *)*packet, sizeof(ethernet_header_t));
  *packet += sizeof(ethernet_header_t);

  header->ether_type = ntohs(header->ether_type);
}

void write_eapol(uint8_t **packet, eapol_type_t type, uint16_t payload_length) {
  eapol_header_t header = {
      .version = 1,
      .type = (uint8_t)type,
      .length = htons(payload_length),
  };

  memcpy((void *)*packet, &header, sizeof(eapol_header_t));
  *packet += sizeof(eapol_header_t);
}

void read_eapol(uint8_t **packet, eapol_header_t *header) {
  memcpy(header, (void *)*packet, sizeof(eapol_header_t));
  *packet += sizeof(eapol_header_t);

  header->length = ntohs(header->length);
}

void write_eap(uint8_t **packet, eap_code_t code, uint8_t id,
               uint16_t payload_length) {
  eap_header_t header = {
      .code = (uint8_t)code,
      .id = id,
      .length = htons(payload_length),
  };

  memcpy((void *)*packet, &header, sizeof(eap_header_t));
  *packet += sizeof(eap_header_t);
}

void read_eap(uint8_t **packet, eap_header_t *header) {
  memcpy(header, (void *)*packet, sizeof(eap_header_t));
  *packet += sizeof(eap_header_t);

  header->length = ntohs(header->length);
}

void write_eap_type(uint8_t **packet, eap_type_t type) {
  uint8_t raw_type = type;

  memcpy((void *)*packet, &raw_type, sizeof(uint8_t));
  *packet += sizeof(uint8_t);
}

void read_eap_type(uint8_t **packet, eap_type_t *type) {
  uint8_t raw_type;
  memcpy(&raw_type, (void *)*packet, sizeof(uint8_t));
  *packet += sizeof(uint8_t);

  *type = (eap_type_t)raw_type;
}

void write_eap_identity(uint8_t **packet, const char *identity,
                        size_t identity_length) {
  memcpy((void *)*packet, identity, identity_length);
  *packet += identity_length;
}

void write_eap_md5(uint8_t **packet, uint8_t value_size, const uint8_t *value) {
  eap_md5_header_t header = {
      .value_size = value_size,
  };

  memcpy((void *)*packet, &header, sizeof(eap_md5_header_t));
  *packet += sizeof(eap_md5_header_t);

  memcpy((void *)*packet, value, value_size);
  *packet += value_size;
}

void read_eap_md5(uint8_t **packet, eap_md5_header_t *header, uint8_t *value) {
  memcpy(header, (void *)*packet, sizeof(eap_md5_header_t));
  *packet += sizeof(eap_md5_header_t);

  memcpy(value, (void *)*packet, header->value_size);
  *packet += header->value_size;
}