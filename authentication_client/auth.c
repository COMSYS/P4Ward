#include <arpa/inet.h>
#include <features.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <memory.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "SHA3IUF/sha3.h"
#include "auth-headers.h"
#include "crypto-algorithms/md5.h"
#include "crypto-algorithms/sha1.h"
#include "crypto-algorithms/sha256.h"

#define BUFFER_SIZE (4096)
#define SMALL_BUFFER_SIZE (1024)

const char *interface = "";
mac_address_t src = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
mac_address_t dst = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const char *name = "";
const char *password = "";
size_t cutoff = -1;

bool is_authenticated = false;

int sock;

#define OTP_SEED_SIZE (20)
char otp_seed[OTP_SEED_SIZE + 1] = {};
#define OTP_STORE_CAPACITY (2048)
uint64_t otp_store[OTP_STORE_CAPACITY] = {};
size_t otp_size = 0;

long long start_time = 0;
long long get_us() {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000 - start_time;
}

void log_message(const char *message) {
  printf("%s timestamp=%lld\n", message, get_us());
}

int initialize_socket() {
  sock = socket(AF_PACKET, SOCK_RAW, htons(3));
  if (sock == -1) {
    fprintf(stderr, "Failed to open socket: ");
    perror("socket");

    exit(-1);
  }

  // Find interface index
  struct ifreq interface_request;
  memset(&interface_request, 0, sizeof(struct ifreq));
  strncpy((char *)interface_request.ifr_name, interface, IFNAMSIZ);

  if ((ioctl(sock, SIOCGIFINDEX, &interface_request)) == -1) {
    fprintf(stderr, "Failed to get interface: ");
    perror("SIOCGIFINDEX");

    exit(-1);
  }

  // Bind to interface
  struct sockaddr_ll socket_address;
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_ifindex = interface_request.ifr_ifindex;
  socket_address.sll_protocol = htons(3);

  if ((bind(sock, (struct sockaddr *)&socket_address,
            sizeof(socket_address))) == -1) {
    fprintf(stderr, "Failed to bind socket to interface.\n");
    perror("bind");
    exit(-1);
  }

  return 0;
}

void send_eapol_start(const mac_address_t src, const mac_address_t dst) {
  uint8_t packet[BUFFER_SIZE];
  uint8_t *raw_packet = packet;

  write_ethernet(&raw_packet, src, dst, ETHER_TYPE_EAPOL);
  write_eapol(&raw_packet, EAPOL_TYPE_START, 0);

  log_message("Sending start request");
  size_t packet_length = raw_packet - (uint8_t *)packet;
  if (write(sock, (void *)packet, packet_length) != packet_length) {
    fprintf(stderr, "Failed to send packet: ");
    perror("write");
    exit(-1);
  }
}

void send_eapol_logoff(const mac_address_t src, const mac_address_t dst) {
  uint8_t packet[BUFFER_SIZE];
  uint8_t *raw_packet = packet;

  write_ethernet(&raw_packet, src, dst, ETHER_TYPE_EAPOL);
  write_eapol(&raw_packet, EAPOL_TYPE_LOGOFF, 0);

  log_message("Sending logoff request");
  size_t packet_length = raw_packet - (uint8_t *)packet;
  if (write(sock, (void *)packet, packet_length) != packet_length) {
    fprintf(stderr, "Failed to send packet: ");
    perror("write");
    exit(-1);
  }
}

void send_eap_identity_response(const mac_address_t src,
                                const mac_address_t dst, uint8_t id,
                                const char *name, size_t name_length) {
  uint8_t packet[BUFFER_SIZE];
  uint8_t *raw_packet = packet;

  write_ethernet(&raw_packet, src, dst, ETHER_TYPE_EAPOL);
  write_eapol(&raw_packet, EAPOL_TYPE_EAP_PACKET,
              sizeof(eap_header_t) + sizeof(uint8_t) + name_length);
  write_eap(&raw_packet, EAP_CODE_RESPONSE, id,
            sizeof(eap_header_t) + sizeof(uint8_t) + name_length);
  write_eap_type(&raw_packet, EAP_TYPE_IDENTITY);
  write_eap_identity(&raw_packet, name, name_length);

  log_message("Sending identity response");
  size_t packet_length = raw_packet - (uint8_t *)packet;
  if (write(sock, (void *)packet, packet_length) != packet_length) {
    fprintf(stderr, "Failed to send packet: ");
    perror("write");
    exit(-1);
  }
}

void recv_eap_identity_request(ethernet_header_t *ethernet_header,
                               eapol_header_t *eapol_header_t,
                               eap_header_t *eap_header, uint8_t *raw_packet) {
  send_eap_identity_response(src, dst, eap_header->id, name, strlen(name));
}

void send_eap_md5_response(const mac_address_t src, const mac_address_t dst,
                           uint8_t id, const uint8_t *md5, size_t md5_length) {
  uint8_t packet[BUFFER_SIZE];
  uint8_t *raw_packet = packet;

  write_ethernet(&raw_packet, src, dst, ETHER_TYPE_EAPOL);
  write_eapol(&raw_packet, EAPOL_TYPE_EAP_PACKET,
              sizeof(eap_header_t) + sizeof(uint8_t) +
                  sizeof(eap_md5_header_t) + md5_length);
  write_eap(&raw_packet, EAP_CODE_RESPONSE, id,
            sizeof(eap_header_t) + sizeof(uint8_t) + sizeof(eap_md5_header_t) +
                md5_length);
  write_eap_type(&raw_packet, EAP_TYPE_MD5);
  write_eap_md5(&raw_packet, md5_length, md5);

  log_message("Sending md5 response");
  size_t packet_length = raw_packet - (uint8_t *)packet;
  if (write(sock, (void *)packet, packet_length) != packet_length) {
    fprintf(stderr, "Failed to send packet: ");
    perror("write");
    exit(-1);
  }
}

void recv_eap_md5_request(ethernet_header_t *ethernet_header,
                          eapol_header_t *eapol_header_t,
                          eap_header_t *eap_header, uint8_t *raw_packet) {
  uint8_t challenge[SMALL_BUFFER_SIZE] = {};
  uint8_t *raw_challenge = challenge;

  size_t name_length = strlen(name);
  memcpy(raw_challenge, name, name_length);
  raw_challenge += name_length;

  size_t password_length = strlen(password);
  memcpy(raw_challenge, password, password_length);
  raw_challenge += password_length;

  eap_md5_header_t eap_md5_header;
  read_eap_md5(&raw_packet, &eap_md5_header, raw_challenge);
  raw_challenge += eap_md5_header.value_size;

  MD5_CTX ctx;
  BYTE digest[16];

  md5_init(&ctx);
  md5_update(&ctx, (uint8_t *)challenge, raw_challenge - (uint8_t *)challenge);
  md5_final(&ctx, (uint8_t *)digest);

  send_eap_md5_response(src, dst, eap_header->id, digest, 16);
}

uint64_t otp_md5_hash_primer(const char *password, size_t password_length,
                             const char *seed, size_t seed_length) {
  MD5_CTX ctx;
  BYTE digest[16];

  md5_init(&ctx);
  md5_update(&ctx, (uint8_t *)password, password_length);
  md5_update(&ctx, (uint8_t *)seed, seed_length);
  md5_final(&ctx, (uint8_t *)digest);

  uint64_t *parts = (uint64_t *)digest;  // 16 * 1byte <=> 2 * 8bytes
  return parts[0] ^ parts[1];
}

uint64_t otp_md5_hash_step(uint8_t *value, size_t value_size) {
  MD5_CTX ctx;
  BYTE digest[16];

  md5_init(&ctx);
  md5_update(&ctx, value, value_size);
  md5_final(&ctx, (uint8_t *)digest);

  uint64_t *parts = (uint64_t *)digest;  // 16 * 1byte <=> 2 * 8bytes
  return parts[0] ^ parts[1];
}

uint64_t otp_sha1_hash_primer(const char *password, size_t password_length,
                              const char *seed, size_t seed_length) {
  SHA1_CTX ctx;
  BYTE digest[24] = {};

  sha1_init(&ctx);
  sha1_update(&ctx, (uint8_t *)password, password_length);
  sha1_update(&ctx, (uint8_t *)seed, seed_length);
  sha1_final(&ctx, (uint8_t *)digest);

  uint64_t *parts = (uint64_t *)
      digest;  // 20 * 1byte + 4bytes(zero) <=> 2.5 * 8bytes + 4bytes(zero)
  return parts[0] ^ parts[1] ^ parts[2];
}

uint64_t otp_sha1_hash_step(uint8_t *value, size_t value_size) {
  SHA1_CTX ctx;
  BYTE digest[24] = {};

  sha1_init(&ctx);
  sha1_update(&ctx, value, value_size);
  sha1_final(&ctx, (uint8_t *)digest);

  uint64_t *parts = (uint64_t *)
      digest;  // 20 * 1byte + 4bytes(zero) <=> 2.5 * 8bytes + 4bytes(zero)
  return parts[0] ^ parts[1] ^ parts[2];
}

uint64_t otp_sha2_hash_primer(const char *password, size_t password_length,
                              const char *seed, size_t seed_length) {
  SHA256_CTX ctx;
  BYTE digest[24] = {};

  sha256_init(&ctx);
  sha256_update(&ctx, (uint8_t *)password, password_length);
  sha256_update(&ctx, (uint8_t *)seed, seed_length);
  sha256_final(&ctx, (uint8_t *)digest);

  uint64_t *parts = (uint64_t *)digest;  // 32 * 1byte <=> 4 * 8bytes
  return parts[0] ^ parts[1] ^ parts[2] ^ parts[3];
}

uint64_t otp_sha2_hash_step(uint8_t *value, size_t value_size) {
  SHA256_CTX ctx;
  BYTE digest[24] = {};

  sha256_init(&ctx);
  sha256_update(&ctx, value, value_size);
  sha256_final(&ctx, (uint8_t *)digest);

  uint64_t *parts = (uint64_t *)digest;  // 20 * 1byte <=> 4 * 8bytes
  return parts[0] ^ parts[1] ^ parts[2] ^ parts[3];
}

uint64_t otp_sha3_hash_primer(const char *password, size_t password_length,
                              const char *seed, size_t seed_length) {
  sha3_context ctx;
  const void *digest;

  sha3_Init256(&ctx);
  sha3_Update(&ctx, (uint8_t *)password, password_length);
  sha3_Update(&ctx, (uint8_t *)seed, seed_length);
  digest = sha3_Finalize(&ctx);

  uint64_t *parts = (uint64_t *)digest;  // 32 * 1byte <=> 4 * 8bytes
  return parts[0] ^ parts[1] ^ parts[2] ^ parts[3];
}

uint64_t otp_sha3_hash_step(uint8_t *value, size_t value_size) {
  sha3_context ctx;
  const void *digest;

  sha3_Init256(&ctx);
  sha3_Update(&ctx, (uint8_t *)value, value_size);
  digest = sha3_Finalize(&ctx);

  uint64_t *parts = (uint64_t *)digest;  // 32 * 1byte <=> 4 * 8bytes
  return parts[0] ^ parts[1] ^ parts[2] ^ parts[3];
}

void send_eap_otp_response(const mac_address_t src, const mac_address_t dst,
                           uint8_t id, const uint8_t *challenge_response,
                           size_t challenge_response_length) {
  uint8_t packet[BUFFER_SIZE];
  uint8_t *raw_packet = packet;

  write_ethernet(&raw_packet, src, dst, ETHER_TYPE_EAPOL);
  write_eapol(&raw_packet, EAPOL_TYPE_EAP_PACKET,
              sizeof(eap_header_t) + sizeof(uint8_t) +
                  sizeof(eap_md5_header_t) + challenge_response_length);
  write_eap(&raw_packet, EAP_CODE_RESPONSE, id,
            sizeof(eap_header_t) + sizeof(uint8_t) + sizeof(eap_md5_header_t) +
                challenge_response_length);
  write_eap_type(&raw_packet, EAP_TYPE_OTP);
  write_eap_md5(&raw_packet, challenge_response_length, challenge_response);

  log_message("Sending otp response");
  size_t packet_length = raw_packet - (uint8_t *)packet;
  if (write(sock, (void *)packet, packet_length) != packet_length) {
    fprintf(stderr, "Failed to send packet: ");
    perror("write");
    exit(-1);
  }
}

void recv_eap_otp_request(ethernet_header_t *ethernet_header,
                          eapol_header_t *eapol_header_t,
                          eap_header_t *eap_header, uint8_t *raw_packet) {
  char challenge[SMALL_BUFFER_SIZE] = {};
  char *raw_challenge = challenge;
  const char *challenge_end = challenge + SMALL_BUFFER_SIZE;

  // Read challenge
  eap_md5_header_t eap_md5_header;
  read_eap_md5(&raw_packet, &eap_md5_header, (uint8_t *)challenge);

  // Test challenge prefix otp-
  if (strncmp(raw_challenge, "otp-", 4) != 0) {
    return;
  }
  raw_challenge += 4;

  // Read algorithm
  const char *algorithm;
  size_t algorithm_length;
  {
    algorithm = raw_challenge;
    for (; raw_challenge < challenge_end; raw_challenge++) {
      if (*raw_challenge == ' ') {
        *raw_challenge = '\0';
        break;
      }
    }
    algorithm_length = raw_challenge - algorithm;
    raw_challenge++;
  }

  // Skip whitespace
  for (; raw_challenge < challenge_end; raw_challenge++)
    if (*raw_challenge != ' ') break;

  // Read sequence id
  const char *raw_sequence_id;
  size_t sequence_id_length;
  size_t sequence_id;
  {
    raw_sequence_id = raw_challenge;
    for (; raw_challenge < challenge_end; raw_challenge++) {
      if (*raw_challenge == ' ') {
        *raw_challenge = '\0';
        break;
      }
    }
    sequence_id_length = raw_challenge - raw_sequence_id;
    raw_challenge++;

    sequence_id = atoll(raw_sequence_id);
  }

  // Skip whitespace
  for (; raw_challenge < challenge_end; raw_challenge++)
    if (*raw_challenge != ' ') break;

  // Read seed
  const char *seed;
  size_t seed_length;
  {
    seed = raw_challenge;
    for (; raw_challenge < challenge_end; raw_challenge++) {
      if (*raw_challenge == ' ') {
        *raw_challenge = '\0';
        break;
      }
    }
    seed_length = raw_challenge - seed;
    raw_challenge++;
  }

  if (seed_length > OTP_SEED_SIZE) return;  // Invalid seed size

  if (strcmp(otp_seed, seed) != 0) {
    otp_size = 0;
    strcpy(otp_seed, seed);
  }

  if (sequence_id >= otp_size) {
    if (algorithm_length == 3 && strncmp(algorithm, "md5", 3) == 0) {
      if (otp_size == 0) {
        otp_store[0] =
            otp_md5_hash_primer(password, strlen(password), seed, seed_length);
        otp_size = 1;
      }

      size_t end = sequence_id;
      for (; otp_size < sequence_id; otp_size++) {
        otp_store[otp_size] = otp_md5_hash_step(
            (uint8_t *)&otp_store[otp_size - 1], sizeof(uint64_t));
      }
    } else if (algorithm_length == 4 && strncmp(algorithm, "sha1", 4) == 0) {
      if (otp_size == 0) {
        otp_store[0] =
            otp_sha1_hash_primer(password, strlen(password), seed, seed_length);
        otp_size = 1;
      }

      size_t end = sequence_id;
      for (; otp_size < sequence_id; otp_size++) {
        otp_store[otp_size] = otp_sha1_hash_step(
            (uint8_t *)&otp_store[otp_size - 1], sizeof(uint64_t));
      }
    } else if (algorithm_length == 4 && strncmp(algorithm, "sha2", 4) == 0) {
      if (otp_size == 0) {
        otp_store[0] =
            otp_sha2_hash_primer(password, strlen(password), seed, seed_length);
        otp_size = 1;
      }

      size_t end = sequence_id;
      for (; otp_size < sequence_id; otp_size++) {
        otp_store[otp_size] = otp_sha2_hash_step(
            (uint8_t *)&otp_store[otp_size - 1], sizeof(uint64_t));
      }
    } else if (algorithm_length == 4 && strncmp(algorithm, "sha3", 4) == 0) {
      if (otp_size == 0) {
        otp_store[0] =
            otp_sha3_hash_primer(password, strlen(password), seed, seed_length);
        otp_size = 1;
      }

      size_t end = sequence_id;
      for (; otp_size < sequence_id; otp_size++) {
        otp_store[otp_size] = otp_sha3_hash_step(
            (uint8_t *)&otp_store[otp_size - 1], sizeof(uint64_t));
      }
    } else {
      return;
    }
  }

  // Build challenge response
  char challenge_response[SMALL_BUFFER_SIZE] = {};
  size_t challenge_response_length;
  {
    char *raw_challenge_response = challenge_response;

    uint64_t otp = otp_store[sequence_id - 1];
    for (size_t i = 0; i < sizeof(uint64_t); i++)
      raw_challenge_response[i] = (uint8_t)(otp >> (i * 8));
    raw_challenge_response += sizeof(uint64_t);

    *raw_challenge_response = ' ';
    raw_challenge_response += sizeof(char);

    for (ssize_t i = 0; i < (3 - (ssize_t)sequence_id_length); i++)
      *(raw_challenge_response++) = ' ';
    memcpy(raw_challenge_response, raw_sequence_id, sequence_id_length);
    raw_challenge_response += sequence_id_length;

    *raw_challenge_response = ' ';
    raw_challenge_response += sizeof(char);

    memcpy(raw_challenge_response, seed, seed_length);
    raw_challenge_response += seed_length;

    *raw_challenge_response = ' ';
    raw_challenge_response += sizeof(char);

    challenge_response_length = raw_challenge_response - challenge_response;
    for (ssize_t i = 0; i < (19 - (ssize_t)challenge_response_length); i++)
      *(raw_challenge_response++) = ' ';

    challenge_response_length = raw_challenge_response - challenge_response;
  }

  send_eap_otp_response(src, dst, eap_header->id, (uint8_t *)challenge_response,
                        challenge_response_length);
}

void recv_eap(ethernet_header_t *ethernet_header,
              eapol_header_t *eapol_header_t, uint8_t *raw_packet) {
  eap_header_t eap_header;
  read_eap(&raw_packet, &eap_header);

  switch (eap_header.code) {
    case EAP_CODE_REQUEST: {
      eap_type_t eap_type;
      read_eap_type(&raw_packet, &eap_type);

      switch (eap_type) {
        case EAP_TYPE_IDENTITY: {
          log_message("Receiving identity request");
          recv_eap_identity_request(ethernet_header, eapol_header_t,
                                    &eap_header, raw_packet);
          break;
        }
        case EAP_TYPE_MD5: {
          log_message("Receiving md5 request");
          recv_eap_md5_request(ethernet_header, eapol_header_t, &eap_header,
                               raw_packet);
          break;
        }
        case EAP_TYPE_OTP: {
          log_message("Receiving otp request");
          recv_eap_otp_request(ethernet_header, eapol_header_t, &eap_header,
                               raw_packet);
          break;
        }
        default:
          fprintf(stderr, "Invalid eap request type %i.\n", eap_type);
          break;
      }

      break;
    }
    case EAP_CODE_SUCCESS:
      log_message("Authentication succeeded");
      is_authenticated = true;
      if (cutoff > 0) cutoff -= 1;
      break;
    case EAP_CODE_FAILURE:
      log_message("Authentication failed");
      is_authenticated = false;
      break;
    default:
      fprintf(stderr, "Invalid eap code %i.\n", eap_header.code);
      break;
  }
}

int main(int argc, char **argv) {
  for (size_t i = 1; i < argc; i++) {
    if (strncmp(argv[i], "--disable-reauth", 16) == 0) {
      cutoff = 1;
    } else if (i + 1 < argc) {
      if (strncmp(argv[i], "--interface", 11) == 0) {
        interface = argv[i + 1];
      } else if (strncmp(argv[i], "--src", 5) == 0) {
        sscanf(argv[i + 1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src[0], &src[1],
               &src[2], &src[3], &src[4], &src[5]);
      } else if (strncmp(argv[i], "--dst", 5) == 0) {
        sscanf(argv[i + 1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst[0], &dst[1],
               &dst[2], &dst[3], &dst[4], &dst[5]);
      } else if (strncmp(argv[i], "--name", 6) == 0) {
        name = argv[i + 1];
      } else if (strncmp(argv[i], "--password", 10) == 0) {
        password = argv[i + 1];
      } else if (strncmp(argv[i], "--cut-off", 9) == 0) {
        sscanf(argv[i + 1], "%zi", &cutoff);
      }
      i++;  // Skip argument
    }
  }

  // Set relative start time
  start_time = get_us();

  initialize_socket();

  send_eapol_start(src, dst);

  uint8_t packet[BUFFER_SIZE];
  size_t packet_length = 0;

  do {
    int result = recv(sock, (void *)packet, BUFFER_SIZE, 0);
    if (result == -1) {
      fprintf(stderr, "Failed to send packet: ");
      perror("read");
      exit(-1);
    }
    uint8_t *raw_packet = packet;

    ethernet_header_t ethernet_header;
    read_ethernet(&raw_packet, &ethernet_header);

    if (ethernet_header.ether_type == ETHER_TYPE_EAPOL) {
      eapol_header_t eapol_header;
      read_eapol(&raw_packet, &eapol_header);

      if (eapol_header.type == EAPOL_TYPE_EAP_PACKET) {
        recv_eap(&ethernet_header, &eapol_header, raw_packet);
      }
    } else if (ethernet_header.ether_type == 0xFFFF) {
      if (memcmp(ethernet_header.dst_address, src, 6) == 0) {
        send_eapol_start(src, dst);
      }
    }
  } while (!(cutoff == 0 && is_authenticated));

  send_eapol_logoff(src, dst);

  return 0;
}