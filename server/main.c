#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>

static void parse_arguments(int argc, char *argv[], char **ip_address, char **port);
static in_port_t parse_port(const char *binary_name, const char *port_str);
static void convert_address(const char *address, struct sockaddr_storage *addr);
static int create_socket(int domain, int type, int protocol);
static void bind_socket(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static struct pollfd* initialize_poll(int sockfd, struct sockaddr_storage **client_socket);
static void handle_connection(int sockfd, struct pollfd **fd_set, struct sockaddr_storage **client_sockets, int *client_count);
static void start_listening(int server_fd, int backlog);
static int accept_connection(int server_fd, struct sockaddr_storage *client_addr, socklen_t *client_addr_len);
static void send_message(int client_sockfd, const struct sockaddr_storage *client_addr, const char *message);
static void close_socket(int sockfd);
static int parse_client_message(char *input, char **message, char **key);
static char shift_char(char curr_char, int shift);
static int encrypt_vigenere_cipher(char *message, char *key, char buffer[], size_t buffer_size);
_Noreturn static void usage(const char *program_name, int exit_code, const char *message);
static void setup_signal_handler(void);
static void sigint_handler(int signum);

#define BASE_TEN 10
#define BACKLOG 5
#define BUFFER_SIZE 256

static volatile sig_atomic_t exit_flag = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

int main(int argc, char *argv[])
{
    char *address;
    char *port_str;
    char *message;
    char *key;

    int sockfd;
    in_port_t port;
    struct sockaddr_storage addr;
    
    struct sockaddr_storage *client_socket;
    struct pollfd *fd_set;
    int client_count;

    ssize_t nread;
    char buffer[BUFFER_SIZE];

    address = NULL;
    port_str = NULL;

    parse_arguments(argc, argv, &address, &port_str);
    convert_address(address, &addr);
    port = parse_port(argv[0], port_str);
    sockfd = create_socket(addr.ss_family, SOCK_STREAM, 0);

    int one = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
    {
        perror("setsockopt(SO_REUSEADDR)");
        exit(EXIT_FAILURE);
    }

    bind_socket(sockfd, &addr, port);
    fd_set = initialize_poll(sockfd, &client_socket);
    start_listening(sockfd, BACKLOG);
    setup_signal_handler();

    while (!exit_flag)
    {
        int poll_val;
        
        poll_val = poll(fd_set, client_count + 1, -1);
        
        if (poll_val < 0) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        handle_connection(sockfd, &fd_set, &client_socket, &client_count);

        int client_sockfd;
        struct sockaddr_storage client_addr;
        socklen_t client_addr_len;

        client_addr_len = sizeof(client_addr);
        client_sockfd = accept_connection(sockfd, &client_addr, &client_addr_len);

        if (client_sockfd == -1)
        {
            if (exit_flag)
            {
                break;
            }

            continue;
        }

        nread = read(client_sockfd, buffer, sizeof(buffer));

        if (nread == -1)
        {
            perror("read");

            close_socket(sockfd);
            break;
        }

        buffer[nread] = '\0';

        if (parse_client_message(buffer, &message, &key) == -1)
        {
            continue;
        };

        if (encrypt_vigenere_cipher(buffer, key, buffer, BUFFER_SIZE) == -1)
        {
            continue;
        }

        send_message(client_sockfd, &client_addr, buffer);
        close_socket(client_sockfd);
    }

    close_socket(sockfd);

    return EXIT_SUCCESS;
}

static void parse_arguments(int argc, char *argv[], char **ip_address, char **port)
{
    if (argc <= 1)
    {
        usage(argv[0], EXIT_FAILURE, "Too few arguments");
    }

    if (argc == 2)
    {
        usage(argv[0], EXIT_FAILURE, "Port is required");
    }

    if (argc > 3)
    {
        usage(argv[0], EXIT_FAILURE, "Too many arguments");
    }

    *ip_address = argv[1];
    *port = argv[2];
}

in_port_t parse_port(const char *binary_name, const char *str)
{
    char *endptr;
    uintmax_t parsed_value;

    errno = 0;
    parsed_value = strtoumax(str, &endptr, BASE_TEN);

    if (errno != 0)
    {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    if (*endptr != '\0')
    {
        usage(binary_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    if (parsed_value > UINT16_MAX)
    {
        usage(binary_name, EXIT_FAILURE, "in_port_t value out of range.");
    }

    return (in_port_t)parsed_value;
}

_Noreturn static void usage(const char *program_name, int exit_code, const char *message)
{
    if (message)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s <ip address> <port>\n", program_name);
    exit(exit_code);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void sigint_handler(int signum)
{
    exit_flag = 1;
}

#pragma GCC diagnostic pop

static void convert_address(const char *address, struct sockaddr_storage *addr)
{
    memset(addr, 0, sizeof(*addr));

    if (inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        addr->ss_family = AF_INET;
    }
    else if (inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        addr->ss_family = AF_INET6;
    }
    else
    {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
        exit(EXIT_FAILURE);
    }
}

static int create_socket(int domain, int type, int protocol)
{
    int sockfd;

    sockfd = socket(domain, type, protocol);

    if (sockfd == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

static void bind_socket(int sockfd, struct sockaddr_storage *addr, in_port_t port)
{
    char addr_str[INET6_ADDRSTRLEN];
    socklen_t addr_len;
    void *vaddr;
    in_port_t net_port;

    net_port = htons(port);

    if (addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr = (struct sockaddr_in *)addr;
        addr_len = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        vaddr = (void *)&(((struct sockaddr_in *)addr)->sin_addr);
    }
    else if (addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr = (struct sockaddr_in6 *)addr;
        addr_len = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        vaddr = (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr);
    }
    else
    {
        fprintf(stderr, "Internal error: addr->ss_family must be AF_INET or AF_INET6, was: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if (inet_ntop(addr->ss_family, vaddr, addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Binding to: %s:%u\n", addr_str, port);

    if (bind(sockfd, (struct sockaddr *)addr, addr_len) == -1)
    {
        perror("Binding failed");
        fprintf(stderr, "Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("Bound to socket: %s:%u\n", addr_str, port);
}

static struct pollfd* initialize_poll(int sockfd, struct sockaddr_storage **client_socket) {
    struct pollfd *fd_set;

    *client_socket = NULL;

    fd_set = (struct pollfd*)malloc(sizeof(struct pollfd));

    if (fd_set == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    fd_set[0].fd = sockfd;
    fd_set[0].events = POLLIN;
    
    return fd_set; 
}

static void handle_connection(int sockfd, struct pollfd **fd_set, struct sockaddr_storage **client_sockets, int *client_count) {
    if (fd_set[0]->revents & POLLIN) {
        int client_fd;
        struct sockaddr_storage client_addr;
        socklen_t client_addr_len;
        struct sockaddr_storage *new_client_sockets;
        struct pollfd *new_fd_set;

        client_fd = accept_connection(sockfd, &client_addr, &client_addr_len);

        if (client_fd == -1) {
            perror("accept failed");
            return;
        }

        *client_count++;

        new_client_sockets = (struct sockaddr_storage*)realloc(*client_sockets, sizeof(struct sockaddr_storage) * (*client_count));
        new_fd_set = (struct pollfd*)realloc(*fd_set, sizeof(struct pollfd) * (*client_count));

        if (new_client_sockets == NULL || new_fd_set == NULL) {
            perror("realloc");
            free(*client_sockets);
            free(*fd_set);
            exit(EXIT_FAILURE);
        }

        *client_sockets = new_client_sockets;
        (*client_sockets)[(*client_count) - 1] = client_addr;

        *fd_set = new_fd_set;
        (*fd_set)[*client_count].fd = client_fd;
        (*fd_set)[*client_count].events = POLLIN;
    }
}

static void start_listening(int server_fd, int backlog)
{
    if (listen(server_fd, backlog) == -1)
    {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Listening for incoming connections...\n");
}

static int accept_connection(int server_fd, struct sockaddr_storage *client_addr, socklen_t *client_addr_len)
{
    int client_fd;

    errno = 0;
    client_fd = accept(server_fd, (struct sockaddr *)client_addr, client_addr_len);

    if (client_fd == -1)
    {
        if (errno != EINTR)
        {
            perror("accept failed");
        }

        return -1;
    }

    return client_fd;
}

static int parse_client_message(char *input, char **message, char **key)
{
    char *last_space = strrchr(input, ' '); // find last space

    if (last_space == NULL)
    {
        printf("Invalid format, no space found.\n");
        return -1;
    }

    *last_space = '\0';
    *message = input;
    *key = last_space + 1;

    return 1;
}

static char shift_char(char curr_char, int shift)
{
    if (isalpha((unsigned char)curr_char) == 0)
    {
        return curr_char;
    }

    char base;
    if (isupper(curr_char))
    {
        base = 'A';
    }
    else
    {
        base = 'a';
    }

    int shift_res = (curr_char - base + shift) % 26;
    if (shift_res < 0)
    {
        shift_res += 26;
    }

    return (char)(base + shift_res);
}

static int encrypt_vigenere_cipher(char *message, char *key, char buffer[], size_t buffer_size)
{
    size_t message_len = strlen(message);
    size_t key_len = strlen(key);

    if (key_len == 0)
    {
        fprintf(stderr, "Key length is 0");
        return -1;
    }

    if (buffer_size < message_len + 1)
    {
        fprintf(stderr, "buffer must be one byte bigger than the message");
        return -1;
    }

    size_t key_i = 0;
    for (size_t i = 0; i < message_len; i++)
    {
        unsigned char curr_char = (unsigned char)message[i];
        char curr_key = key[key_i];

        if (isalpha(curr_char))
        {
            int shift_val = (int)curr_key - (int)'A';
            buffer[i] = shift_char((char)curr_char, shift_val);
            key_i = (key_i + 1) % key_len;
        }
        else
        {
            buffer[i] = curr_char;
        }
    }

    buffer[message_len] = '\0';
    return 1;
}

static void setup_signal_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    sa.sa_handler = sigint_handler;
#ifdef __clang__
#pragma clang diagnostic pop
#endif

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void send_message(int client_sockfd, const struct sockaddr_storage *client_addr, const char *message)
{
    size_t len;

    len = strlen(message);

    ssize_t nwritten;

    nwritten = write(client_sockfd, message, len);

    if (nwritten == -1)
    {
        perror("write");
        exit(EXIT_FAILURE);
    }
}

#pragma GCC diagnostic pop

static void close_socket(int sockfd)
{
    if (close(sockfd) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}
