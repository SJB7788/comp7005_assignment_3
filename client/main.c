#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void parse_arguments(int argc, char *argv[], char **message, char **key,
                            char **ip_address, char **port);
static in_port_t parse_port(const char *binary_name, const char *port_str);
_Noreturn static void usage(const char *program_name, int exit_code,
                            const char *message);
static void convert_address(const char *address, struct sockaddr_storage *addr);
static int create_socket(int domain, int type, int protocol);
static void connect_socket(int sockfd, struct sockaddr_storage *addr,
                           in_port_t port);
static void send_message(int sockfd, const struct sockaddr_storage *addr,
                         const char *message);
static char shift_char(char curr_char, int shift);
static int decrypt_vigenere_cipher(char *message, const char *key,
                                   char buffer[], size_t buffer_size);
static void close_socket(int client_fd);

enum {
  BASE_TEN = 10,
  BACKLOG = 5,
  BUFFER_SIZE = 256,
  MAX_DELAY = 5,
  MIN_DELAY = 1,
  ALPHANUM = 26,
  ARG_LIMIT = 5
};

int main(int argc, char *argv[]) {
  char *message;
  char *key;
  char *address;
  char *port_str;

  int sockfd;
  in_port_t port;
  struct sockaddr_storage addr;
  ssize_t nread;
  char buffer[BUFFER_SIZE];
  char msg_buffer[BUFFER_SIZE];
  int delay;
  unsigned int seed;

  address = NULL;
  port_str = NULL;
  parse_arguments(argc, argv, &message, &key, &address, &port_str);
  convert_address(address, &addr);
  port = parse_port(argv[0], port_str);
  sockfd = create_socket(addr.ss_family, SOCK_STREAM, 0);
  connect_socket(sockfd, &addr, port);

  seed = (unsigned int)(time(NULL) ^ getpid());
  srand(seed);

  strlcpy(msg_buffer, message, BUFFER_SIZE);
  strlcat(msg_buffer, " ", BUFFER_SIZE);
  strlcat(msg_buffer, key, BUFFER_SIZE);
  strlcat(msg_buffer, "\0", BUFFER_SIZE);

  delay = (rand() % (MAX_DELAY - MIN_DELAY + 1)) + MIN_DELAY;
  printf("Simulating work for %d seconds on client\n", delay);
  sleep((unsigned int)delay);

  send_message(sockfd, &addr, msg_buffer);

  nread = read(sockfd, buffer, sizeof(buffer));

  if (nread == -1) {
    perror("read");
    return EXIT_FAILURE;
  }

  printf("encrypted message: %s\n", buffer);
  decrypt_vigenere_cipher(buffer, key, buffer, BUFFER_SIZE);
  printf("decrypted message: %s\n", buffer);

  close_socket(sockfd);

  return EXIT_SUCCESS;
}

static void parse_arguments(int argc, char *argv[], char **message, char **key,
                            char **ip_address, char **port) {
  if (argc < ARG_LIMIT) {
    usage(argv[0], EXIT_FAILURE, "Too few arguments");
  }

  if (argc > ARG_LIMIT) {
    usage(argv[0], EXIT_FAILURE, "Too many arguments");
  }

  *message = argv[1];
  *key = argv[2];
  *ip_address = argv[3];
  *port = argv[4];
}

static in_port_t parse_port(const char *binary_name, const char *str) {
  char *endptr;
  uintmax_t parsed_value;

  errno = 0;
  parsed_value = strtoumax(str, &endptr, BASE_TEN);

  if (errno != 0) {
    perror("Error parsing in_port_t");
    exit(EXIT_FAILURE);
  }

  if (*endptr != '\0') {
    usage(binary_name, EXIT_FAILURE, "Invalid characters in input.");
  }

  if (parsed_value > UINT16_MAX) {
    usage(binary_name, EXIT_FAILURE, "in_port_t value out of range.");
  }

  return (in_port_t)parsed_value;
}

_Noreturn static void usage(const char *program_name, int exit_code,
                            const char *message) {
  if (message) {
    fprintf(stderr, "%s\n", message);
  }

  fprintf(stderr, "Usage: %s <message> <key> <ip address> <port>\n",
          program_name);
  exit(exit_code);
}

static void convert_address(const char *address,
                            struct sockaddr_storage *addr) {
  memset(addr, 0, sizeof(*addr));

  if (inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) ==
      1) {
    addr->ss_family = AF_INET;
  } else if (inet_pton(AF_INET6, address,
                       &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1) {
    addr->ss_family = AF_INET6;
  } else {
    fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
    exit(EXIT_FAILURE);
  }
}

static int create_socket(int domain, int type, int protocol) {
  int sockfd;

  sockfd = socket(domain, type, protocol);

  if (sockfd == -1) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

static void connect_socket(int sockfd, struct sockaddr_storage *addr,
                           in_port_t port) {
  char addr_str[INET6_ADDRSTRLEN];
  in_port_t net_port;
  socklen_t addr_len;

  if (inet_ntop(addr->ss_family,
                addr->ss_family == AF_INET
                    ? (void *)&(((struct sockaddr_in *)addr)->sin_addr)
                    : (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr),
                addr_str, sizeof(addr_str)) == NULL) {
    perror("inet_ntop");
    exit(EXIT_FAILURE);
  }

  printf("Connecting to: %s:%u\n", addr_str, port);
  net_port = htons(port);

  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *ipv4_addr;

    ipv4_addr = (struct sockaddr_in *)addr;
    ipv4_addr->sin_port = net_port;
    addr_len = sizeof(struct sockaddr_in);
  } else if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *ipv6_addr;

    ipv6_addr = (struct sockaddr_in6 *)addr;
    ipv6_addr->sin6_port = net_port;
    addr_len = sizeof(struct sockaddr_in6);
  } else {
    fprintf(stderr, "Invalid address family: %d\n", addr->ss_family);
    exit(EXIT_FAILURE);
  }

  if (connect(sockfd, (struct sockaddr *)addr, addr_len) == -1) {
    const char *msg;

    msg = strerror(errno);
    fprintf(stderr, "Error: connect (%d): %s\n", errno, msg);
    exit(EXIT_FAILURE);
  }

  printf("Connected to: %s:%u\n", addr_str, port);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void send_message(int sockfd, const struct sockaddr_storage *addr,
                         const char *message) {
  size_t len;
  ssize_t nwritten;

  printf("Sending server a message...\n");

  len = strlen(message);

  nwritten = write(sockfd, message, len);

  if (nwritten == -1) {
    perror("write");
    exit(EXIT_FAILURE);
  }

  printf("Message Sent\n");
}

static char shift_char(char curr_char, int shift) {
  char base;
  int shift_res;

  if (isalpha((unsigned char)curr_char) == 0) {
    return curr_char;
  }

  if (isupper(curr_char)) {
    base = 'A';
  } else {
    base = 'a';
  }

  shift_res = (curr_char - base + shift) % ALPHANUM;
  if (shift_res < 0) {
    shift_res += ALPHANUM;
  }

  return (char)(base + shift_res);
}

static int decrypt_vigenere_cipher(char *message, const char *key,
                                   char buffer[], size_t buffer_size) {
  size_t key_i;
  size_t message_len = strlen(message);
  size_t key_len = strlen(key);

  if (key_len == 0) {
    fprintf(stderr, "Key length is 0");
    return -1;
  }

  if (buffer_size < message_len + 1) {
    fprintf(stderr, "buffer must be one byte bigger than the message");
    return -1;
  }

  key_i = 0;
  for (size_t i = 0; i < message_len; i++) {
    unsigned char curr_char = (unsigned char)message[i];
    char curr_key = key[key_i];

    if (isalpha(curr_char)) {
      int shift_val = (int)curr_key - 'A';
      buffer[i] = shift_char((char)curr_char, -shift_val);
      key_i = (key_i + 1) % key_len;
    } else {
      buffer[i] = (char)curr_char;
    }
  }

  buffer[message_len] = '\0';
  return 1;
}

static void close_socket(int client_fd) {
  if (close(client_fd) == -1) {
    perror("Error closing socket");
    exit(EXIT_FAILURE);
  }
}
