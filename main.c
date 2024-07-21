#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <libnetfilter_log/libnetfilter_log.h>

#define BUFFER_SIZE 4096
#define DNS_PORT 53
#define NFLOG_GROUP 3

#define OUTGOING_IPTABLES_COMMAND "INPUT -p udp --dport " DNS_PORT " -j NFLOG --nflog-group " NFLOG_GROUP
#define OUTGOING_IP6TABLES_COMMAND "INPUT -p udp --dport " DNS_PORT " -j NFLOG --nflog-group " NFLOG_GROUP

#define MAX_PKT_SIZE 0xffff

#define IPV4_DNS_PAYLOAD_OFFSET 28
#define IPV6_DNS_PAYLOAD_OFFSET 48

#define LOG_FILE_PATH "./log"
#define LOG_FILE_MODE "a"

#define DOMAIN_MAX_SIZE 256
#define IP_MAX_SIZE 40 // using ipv6 size

typedef struct nflog_handle nflog_handle_t;
typedef struct nflog_g_handle nflog_g_handle_t;
typedef struct nfgenmsg nfgenmsg_t;
typedef struct nflog_data nflog_data_t;

typedef enum
{
    A = 1,
    AAAA = 28,
    CNAME = 5,
    OTHER = -1
} qtype_t;

typedef enum
{
    IPV4 = 4,
    IPV6 = 6
} ip_version_t;

typedef struct
{
    qtype_t query_type;
    ip_version_t ip_version;
    char dns_server[IP_MAX_SIZE];
    char domain[DOMAIN_MAX_SIZE];
} dns_response_t;

int add_rule(const char *iptables_path, const char *rule) {
    char cmd[100];

    snprintf(cmd, sizeof(cmd), "%s  -A %s", iptables_path, rule);

    pid_t pid = fork();
    if (pid < 0)
    {
        printf("failed running fork");
        return 1;
    }

    if (pid == 0) {
        execlp("sh", "sh", "-c", cmd, (char *)NULL);
        perror("Exec Failed: (add): %d\n");
        exit(1);
    } else {
        wait(NULL);
    }
}

void deleteIptablesRule(const char *iptables_path, const char *rule)
{
    char cmd[100];
    snprintf(cmd, sizeof(cmd), "%s -D %s", iptables_path, rule);

    pid_t pid = fork();
    if (pid < 0) {
        printf("failed running fork");
        return 1;
    }

    if (pid == 0) {
        execlp("sh", "sh", "-c", cmd, (char *)NULL);
        perror("Exec failed (del)");
        exit(1);
    } else {
        wait(NULL);
    }
}

void print_dns_response(dns_response_t response) {
    printf("DNS Server: %s, ", response.dns_server);
    printf("Domain: %s, ", response.domain);
    printf("IP Version: %d, ", response.ip_version);

    printf("Query type: ");
    switch (response.query_type)
    {
    case A:
        printf("A");
        break;
    case AAAA:
        printf("AAAA");
        break;

    case CNAME:
        printf("CNAME");
        break;
    default:
        printf("Unknown");
        break;
    }

    printf("\n");    
}

int parse_domain(char *dns_payload, int dns_payload_len, dns_response_t *response, int *seek)
{
    // to make sure were not going out of bounds in `data`,
    // if `data` is smaller or equal to the size of the dns header section
    // we simply return
    if (dns_payload_len <= 12)
        return 1;

    // starting after the dns header
    // at an offset of 12 bytes from the start
    int i = 12, char_index = 0;
    while (i < dns_payload_len)
    {
        int section_length = dns_payload[i];
        if (section_length == 0)
            break;

        // An example for the domain section in the dns payload
        //  03 'w' 'w' 'w' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00
        //  each section is prefix with each length, followed by a '.' character
        //  so, ill fetch the length of the current section, then loop for this length
        //  and print each char
        for (int j = 1; j <= section_length; j++)
        {
            response->domain[char_index++] = dns_payload[i + j];
        }

        // move to the next section in the domain
        i += section_length + 1;

        // only print '.' if the next section length is not 0 (the domain end)
        if (dns_payload[i] != 0)
            response->domain[char_index++] = '.';
    }

    // setting seek at the end of domain/start of the question section
    // (for query type parsing)
    *seek = i + 1;

    response->domain[char_index] = '\0';
    return 0;
}

void parse_query_type(char *dns_payload, int question_start, dns_response_t *response)
{
    // the qtype field is 16 bit long, so ill be using an `uint16_t` field to fetch its value
    // the field resides right
    uint16_t qtype;
    memcpy(&qtype, (char *)(dns_payload + question_start), sizeof(uint16_t));

    response->query_type = (qtype_t)ntohs(qtype);
}


void parse_dns_packet(char *payload, int payload_len, dns_response_t *response, FILE *log_fd)
{
    char src_ip[IP_MAX_SIZE] = {0};
    int dns_payload_len, seek = 0;
    char *dns_payload;

    // The DNS Header is the first 12 (and 8 for IPV6) bytes of the data
    // so according the structure of the DNS packet,
    // the src ip resides at an offset of 12/8 bytes after the start of the DNS packet
    if (response->ip_version == IPV4)
    {
        inet_ntop(AF_INET, (char *)(payload + 12), response->dns_server, INET_ADDRSTRLEN);

        if (payload_len < IPV4_DNS_PAYLOAD_OFFSET)
            return;

        dns_payload = (char *)(payload + IPV4_DNS_PAYLOAD_OFFSET);
        dns_payload_len = payload_len - IPV4_DNS_PAYLOAD_OFFSET;
    }
    else
    { // IPV6
        inet_ntop(AF_INET6, (char *)(payload + 8), response->dns_server, INET6_ADDRSTRLEN);

        if (payload_len < IPV6_DNS_PAYLOAD_OFFSET)
            return;

        dns_payload = (char *)(payload + IPV6_DNS_PAYLOAD_OFFSET);
        dns_payload_len = payload_len - IPV6_DNS_PAYLOAD_OFFSET;
    }

    parse_domain(dns_payload, dns_payload_len, response, &seek);
    parse_query_type(dns_payload, seek, response);
}

static int callback(nflog_g_handle_t *group_handle, nfgenmsg_t *nfmsg, nflog_data_t *nfa, void *data)
{
    FILE *log_fd = (FILE *)data;
    dns_response_t response;
    int offset = 0;

    char *payload;
    int payload_len = nflog_get_payload(nfa, &payload);
    if (payload_len < 0)
        return 0;

    // Extract the IP version from the first byte of the IP header
    char ip_version = (payload[0] >> 4) & 0x0f;

    if (ip_version == 4)
        response.ip_version = IPV4;
    else
        response.ip_version = IPV6;

    parse_dns_packet(payload, payload_len, &response, log_fd);
    print_dns_response(response);

    return 0;
}

void cleanup(nflog_handle_t *handle, nflog_g_handle_t *group_handle, FILE *log_fd) {
    printf("Cleanup\n");

    // deleteIptablesRule("iptables", OUTGOING_IPTABLES_COMMAND);
    // deleteIptablesRule("ip6tables", OUTGOING_IP6TABLES_COMMAND);

    if (log_fd) fclose(log_fd);
    if (group_handle) nflog_unbind_group(group_handle);
    if (handle) nflog_close(handle);
}

/*
NFLOG Flow:
 - open handle
 - bind handle to both ipv4 and ipv6
 - bind handle to group #
 - set copy pkt mode
 - register callback function
 - open a fd to receive messages
 - open a fd to log file
 - loop to proccess packets
 - cleanup
*/

int main(void)
{
    nflog_handle_t *handle;
    nflog_g_handle_t *group_handle;
    char buffer[BUFFER_SIZE];
    FILE *log_fd;
    int rv;

    printf("Opening a new handler\n");
    handle = nflog_open();
    if (!handle)
    {
        fprintf(stderr, "Error opening netlink handle\n");
        return -1;
    }

    printf("unbinding handle from ipv4 and ipv6\n");
    if (nflog_unbind_pf(handle, AF_INET) < 0 || nflog_unbind_pf(handle, AF_INET6) < 0)
    {
        fprintf(stderr, "Error unbinding to IPV4 or IPv6\n");
        cleanup(handle, group_handle, log_fd);
        return -1;
    }

    printf("binding handle to IPV4 & IPv6\n");
    if (nflog_bind_pf(handle, AF_INET) < 0 || nflog_bind_pf(handle, AF_INET6) < 0)
    {
        fprintf(stderr, "Error binding to IPV4 or IPv6\n");
        cleanup(handle, group_handle, log_fd);
        return -1;
    }

    printf("Binding to Group %d\n", NFLOG_GROUP);
    group_handle = nflog_bind_group(handle, NFLOG_GROUP);
    if (!group_handle)
    {
        fprintf(stderr, "Error binding to group %d\n", NFLOG_GROUP);
        cleanup(handle, group_handle, log_fd);
        return -1;
    }

    printf("Setting mode to copy packets\n");
    if (nflog_set_mode(group_handle, NFULNL_COPY_PACKET, MAX_PKT_SIZE) < 0)
    {
        fprintf(stderr, "Error setting mode\n");
        cleanup(handle, group_handle, log_fd);
        return -1;
    };

    log_fd = fopen(LOG_FILE_PATH, LOG_FILE_MODE);
    if (!log_fd)
    {
        fprintf(stderr, "Error opening log file\n");

        cleanup(handle, group_handle, log_fd);
        return -1;
    }

    // passing log_fd to the callback function, to later write to the log file
    // important note is that the callback function, should not manage this fd
    // it is being closed at the end of the main function
    printf("Subscribing callback to nflog packet recv event\n");
    int err = nflog_callback_register(group_handle, &callback, log_fd);
    if (err < 0)
    {
        printf("Error registering callback err: %d\n", err);
        cleanup(handle, group_handle, log_fd);

        return -1;
    }

    printf("creating a new fd for nflog handle\n");
    int fd = nflog_fd(handle);
    if (!fd)
    {
        fprintf(stderr, "Error creating fd\n");
        cleanup(handle, group_handle, log_fd);

        return -1;
    }

    printf("Sniffing.. fd = %d\n", fd);
    while ((rv = recv(fd, buffer, BUFFER_SIZE, 0)) && rv >= 0)
    {
        // if received data is 0, continue to next iteration
        if (rv < 0)
            continue;

        if (nflog_handle_packet(handle, buffer, rv) < 0)
            printf("error handling packet\n");
    }

    cleanup(handle, group_handle, log_fd);

    return 0;
}