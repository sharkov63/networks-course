#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ECHO_CONTENT "ABCD"
#define PING_OK 0
#define PING_ERR_UNKNOWN (-1)
#define PING_ERR_PRINTED 1

#define LOG(...)                                                               \
  do {                                                                         \
    printf("ping: " __VA_ARGS__);                                              \
    putchar('\n');                                                             \
  } while (0)

#define SWAP16(x) (((x) >> 8) | ((x) << 8))

typedef struct __attribute__((packed)) {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_no;
  char data[0];
} ICMP_EchoMessage;

static uint16_t calculate_icmp_checksum(const void *message, size_t datalen) {
  uint16_t sum = 0;
  const uint16_t *data = (const uint16_t *)message;
  size_t len = sizeof(ICMP_EchoMessage) + datalen;
  for (; len >= 2; ++data, len -= 2)
    sum += *data;
  if (len == 1)
    sum += *(const uint8_t *)(data);
  return sum;
}

static ICMP_EchoMessage *create_icmp_echo_request(const char *data,
                                                  size_t datalen) {
  ICMP_EchoMessage *message =
      (ICMP_EchoMessage *)malloc(sizeof(ICMP_EchoMessage) + datalen);
  if (!message)
    return message;
  message->type = 8;
  message->code = 0;
  message->checksum = 0;
  message->identifier = 0;
  message->sequence_no = 0;
  memcpy(message->data, data, datalen);
  message->checksum = ~calculate_icmp_checksum(message, datalen);
  return message;
}

static int resolve_address(const char *hostname, struct addrinfo **res) {
  int ret = getaddrinfo(hostname, NULL, NULL, res);
  if (ret) {
    LOG("Failed to resolve '%s': %d %s", hostname, ret, gai_strerror(ret));
    return PING_ERR_PRINTED;
  }

  char text_ipaddr[INET_ADDRSTRLEN];
  struct sockaddr_in *sockaddress = (struct sockaddr_in *)(*res)->ai_addr;
  if (inet_ntop(AF_INET, &sockaddress->sin_addr, text_ipaddr,
                INET_ADDRSTRLEN)) {
    LOG("Successfully resolved '%s' to %s", hostname, text_ipaddr);
  }
  return PING_OK;
}

static int receive_response(ICMP_EchoMessage **response, int raw_socket,
                            size_t message_len) {
  size_t expected_length = sizeof(struct iphdr) + message_len;
  void *buf = malloc(expected_length);
  if (!buf)
    return PING_ERR_UNKNOWN;
  int received = recv(raw_socket, buf, expected_length, 0);
  if (received == -1) {
    LOG("Failed to receive ICMP echo response: %d %s", errno, strerror(errno));
    goto free_buf;
  }
  if (received < expected_length) {
    LOG("Received only %d bytes; expected %d", received, (int)expected_length);
    goto free_buf;
  }
  const struct iphdr *ip_header = (const struct iphdr *)buf;
  uint16_t ip_datagram_length = SWAP16(ip_header->tot_len);
  if (ip_datagram_length != expected_length) {
    LOG("Received IP datagram of total length %d bytes; expected %d",
        ip_datagram_length, (int)expected_length);
    goto free_buf;
  }
  LOG("Successfully received an IP datagram with correct size");
  *response = (ICMP_EchoMessage *)(ip_header + 1);
  return PING_OK;

free_buf:
  free(buf);
  return PING_ERR_PRINTED;
}

static void free_response(void *response) {
  free((struct iphdr *)response - 1);
}

static int ping(const char *hostname) {
  int ret = PING_OK;

  // Open a raw socket
  int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (raw_socket == -1) {
    LOG("Failed to open a raw socket: %d %s", errno, strerror(errno));
    if (errno == EPERM)
      LOG("Perhaps you forgot to run ping with sudo?");
    return PING_ERR_PRINTED;
  }
  LOG("Successfully opened a raw socket.");

  // Resolve address
  struct addrinfo *address;
  if ((ret = resolve_address(hostname, &address)))
    goto close_socket;

  // Create ICMP message
  size_t datalen = sizeof(ECHO_CONTENT) - 1;
  ICMP_EchoMessage *message = create_icmp_echo_request(ECHO_CONTENT, datalen);
  if (!message) {
    LOG("Failed to create ICMP echo request");
    ret = PING_ERR_UNKNOWN;
    goto free_address;
  }
  size_t message_len = sizeof(ICMP_EchoMessage) + datalen;

  // Send the message
  if (sendto(raw_socket, message, message_len, 0, address->ai_addr,
             address->ai_addrlen) == -1) {
    LOG("Failed to send ICMP echo message: %d %s", errno, strerror(errno));
    ret = PING_ERR_PRINTED;
    goto free_message;
  }
  LOG("Successfully sent echo message");

  // Receive response
  ICMP_EchoMessage *response;
  ret = receive_response(&response, raw_socket, message_len);
  if (ret)
    goto free_address;

  // Verify response
  uint16_t checksum = calculate_icmp_checksum(response, message_len);
  if (checksum != (uint16_t)(-1)) {
    LOG("Received corrupted ICMP response with checksum %x", checksum);
    ret = PING_ERR_PRINTED;
    goto free_response;
  }
  if (response->type != 0) {
    LOG("Received ICMP response with wrong type %d, expected 0",
        response->type);
    ret = PING_ERR_PRINTED;
    goto free_response;
  }
  if (response->code != 0) {
    LOG("Received ICMP response with wrong code %d, expected 0",
        response->type);
    ret = PING_ERR_PRINTED;
    goto free_response;
  }
  if (memcmp(response->data, message->data, datalen) != 0) {
    LOG("Received ICMP response with different content");
    ret = PING_ERR_PRINTED;
    goto free_response;
  }

  LOG("Successfully received a valid echo response!");

free_response:
  free_response(response);
free_message:
  free(message);
free_address:
  freeaddrinfo(address);
close_socket:
  LOG("Closing the raw socket...");
  close(raw_socket);
  return ret;
}

int main(int argc, const char **argv) {
  if (argc <= 1) {
    LOG("Please provide <hostname> command-line argument.");
    return 1;
  }
  int err = ping(argv[1]);
  if (err) {
    if (err == PING_ERR_UNKNOWN) {
      LOG("Some error happened. Exiting...");
    }
    return err;
  }
  return 0;
}
