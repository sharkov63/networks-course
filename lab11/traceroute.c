#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

#define TRACEROUTE_OK 0
#define TRACEROUTE_ERR_UNKNOWN (-1)
#define TRACEROUTE_ERR_PRINTED 1
#define TRACEROUTE_TIMEOUT 2

#define ECHO_CONTENT "ABCD"
#define MAX_HOPS 64
#define ITERATIONS 3
#define RESPONSE_LEN 256
#define TIMEOUT_S 1

#define LOG(...)                                                               \
  do {                                                                         \
    fprintf(stderr, "traceroute: " __VA_ARGS__);                               \
    fprintf(stderr, "\n");                                                     \
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
  size_t sum = 0;
  const uint16_t *data = (const uint16_t *)message;
  size_t len = sizeof(ICMP_EchoMessage) + datalen;
  for (; len >= 2; ++data, len -= 2)
    sum += *data;
  if (len == 1)
    sum += *(const uint8_t *)(data);
  while (sum > 0xffff)
    sum = (sum & 0xffff) + (sum >> 16);
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
    return TRACEROUTE_ERR_PRINTED;
  }

  char text_ipaddr[INET_ADDRSTRLEN];
  struct sockaddr_in *sockaddress = (struct sockaddr_in *)(*res)->ai_addr;
  if (inet_ntop(AF_INET, &sockaddress->sin_addr, text_ipaddr,
                INET_ADDRSTRLEN)) {
    LOG("Successfully resolved '%s' to %s", hostname, text_ipaddr);
  }
  return TRACEROUTE_OK;
}

static int receive_response(struct iphdr **response, size_t *ip_datagram_length,
                            int raw_socket) {
  int ret = TRACEROUTE_OK;
  void *buf = malloc(RESPONSE_LEN);
  if (!buf)
    return TRACEROUTE_ERR_UNKNOWN;

  int received = recv(raw_socket, buf, RESPONSE_LEN, 0);
  if (received == -1) {
    if (errno == EWOULDBLOCK) {
      ret = TRACEROUTE_TIMEOUT;
      goto free_buf;
    }
    LOG("Failed to receive ICMP echo response: %d %s", errno, strerror(errno));
    ret = TRACEROUTE_ERR_PRINTED;
    goto free_buf;
  }

  *response = (struct iphdr *)buf;
  *ip_datagram_length = (uint16_t)SWAP16((*response)->tot_len);
  if (*ip_datagram_length > RESPONSE_LEN) {
    LOG("Received IP datagram of length %d bytes, but only %d is supported",
        (int)*ip_datagram_length, RESPONSE_LEN);
    ret = TRACEROUTE_ERR_PRINTED;
    goto free_buf;
  }
  LOG("Successfully received an IP datagram of length %d",
      (int)*ip_datagram_length);
  return TRACEROUTE_OK;

free_buf:
  free(buf);
  return ret;
}

typedef struct {
  int socket;
  struct addrinfo *address;
  ICMP_EchoMessage *echo_message;
  size_t echo_message_len;
  int ttl;
} traceroute_context;

typedef struct {
  double rtt_s;
  struct in_addr ip_addr; // 0 if unknown
  int finished;
} traceroute_attempt_res;

static double get_time() {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  return now.tv_sec + now.tv_nsec * 1e-9;
}

static int attempt(const traceroute_context *context,
                   traceroute_attempt_res *result) {
  int ret = TRACEROUTE_OK;

  // Send the message

  double start_time = get_time();
  if (sendto(context->socket, context->echo_message, context->echo_message_len,
             0, context->address->ai_addr,
             context->address->ai_addrlen) == -1) {
    LOG("Failed to send ICMP echo message: %d %s", errno, strerror(errno));
    return TRACEROUTE_ERR_PRINTED;
  }
  LOG("Successfully sent echo message");

  // Receive response
  struct iphdr *ip_header;
  size_t ip_datagram_length;
  ret = receive_response(&ip_header, &ip_datagram_length, context->socket);
  result->rtt_s = get_time() - start_time;
  result->finished = 0;
  if (ret == TRACEROUTE_TIMEOUT) {
    LOG("timeout for TTL %d", context->ttl);
    result->ip_addr.s_addr = 0;
    return TRACEROUTE_OK;
  }
  if (ret) {
    return TRACEROUTE_ERR_UNKNOWN;
  }
  result->ip_addr.s_addr = ip_header->saddr;
  ICMP_EchoMessage *response = (ICMP_EchoMessage *)(ip_header + 1);

  // Verify response
  LOG("response type = %d", response->type);
  LOG("response code = %d", response->code);
  uint16_t checksum = calculate_icmp_checksum(
      response,
      ip_datagram_length - sizeof(struct iphdr) - sizeof(ICMP_EchoMessage));
  if (checksum != (uint16_t)(-1)) {
    LOG("Received corrupted ICMP response with checksum %x", checksum);
    ret = TRACEROUTE_ERR_PRINTED;
    goto free_response;
  }

  if (response->type == 0 && response->code == 0) {
    result->finished = 1;
  }

free_response:
  free(ip_header);
  return ret;
}

static int traceroute(const char *hostname) {
  int ret = TRACEROUTE_OK;

  traceroute_context context;

  // Open a raw socket
  context.socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (context.socket == -1) {
    LOG("Failed to open a raw socket: %d %s", errno, strerror(errno));
    if (errno == EPERM)
      LOG("Perhaps you forgot to run traceroute with sudo?");
    return TRACEROUTE_ERR_PRINTED;
  }
  LOG("Successfully opened a raw socket.");

  // Set timeout for the socket
  struct timeval timeout;
  timeout.tv_sec = TIMEOUT_S;
  timeout.tv_usec = 0;
  if (setsockopt(context.socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                 sizeof timeout) == -1) {
    LOG("Failed to set receive timeout for the raw socket");
    ret = TRACEROUTE_ERR_PRINTED;
    goto close_socket;
  }

  // Resolve address
  if ((ret = resolve_address(hostname, &context.address))) {
    goto close_socket;
  }

  // Create ICMP echo message
  size_t datalen = sizeof(ECHO_CONTENT) - 1;
  context.echo_message = create_icmp_echo_request(ECHO_CONTENT, datalen);
  if (!context.echo_message) {
    LOG("Failed to create ICMP echo request");
    ret = TRACEROUTE_ERR_UNKNOWN;
    goto free_address;
  }
  context.echo_message_len = sizeof(ICMP_EchoMessage) + datalen;

  for (context.ttl = 1; context.ttl <= MAX_HOPS; ++context.ttl) {
    // Set TTL for the socket
    if (setsockopt(context.socket, SOL_IP, IP_TTL, &context.ttl,
                   sizeof context.ttl) == -1) {
      LOG("Failed to set TTL for the raw socket");
      ret = TRACEROUTE_ERR_PRINTED;
      goto free_message;
    }
    LOG("Set TTL = %d", context.ttl);

    traceroute_attempt_res results[ITERATIONS];
    for (int iteration = 0; iteration < ITERATIONS; ++iteration) {
      if ((ret = attempt(&context, &results[iteration])))
        goto free_message;
    }

    printf("%d ", context.ttl);
    struct in_addr ip_addr = results[0].ip_addr;
    char text_ipaddr[INET_ADDRSTRLEN] = "*";
    if (ip_addr.s_addr != 0)
      inet_ntop(AF_INET, &ip_addr, text_ipaddr, INET_ADDRSTRLEN);
    struct sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr = ip_addr;
    printf("IP %s ", text_ipaddr);
    char host[256];
    if (ip_addr.s_addr != 0 &&
        getnameinfo((const struct sockaddr *)&sockaddr, sizeof sockaddr, host,
                    sizeof host, NULL, 0, 0) == 0) {
      printf("%s ", host);
    }
    for (int iteration = 0; iteration < ITERATIONS; ++iteration)
      printf(" %lf s", results[iteration].rtt_s);
    printf("\n");
    if (results[0].finished)
      break;
  }

free_message:
  free(context.echo_message);
free_address:
  freeaddrinfo(context.address);
close_socket:
  LOG("Closing the raw socket...");
  close(context.socket);
  return ret;
}

int main(int argc, const char **argv) {
  if (argc <= 1) {
    LOG("Please provide <hostname> command-line argument.");
    return 1;
  }
  int err = traceroute(argv[1]);
  if (err) {
    if (err == TRACEROUTE_ERR_UNKNOWN) {
      LOG("Some error happened. Exiting...");
    }
    return err;
  }
  return 0;
}
