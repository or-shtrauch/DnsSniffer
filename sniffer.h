#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <stdio.h>

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

#define MAX_LINE_SIZE 1024
#define DOMAIN_MAX_SIZE 256
#define IP_MAX_SIZE 40  // using ipv6 size

#define MAX_QTYPE_SIZE sizeof("Unknown")

typedef struct nflog_handle nflog_handle_t;
typedef struct nflog_g_handle nflog_g_handle_t;
typedef struct nfgenmsg nfgenmsg_t;
typedef struct nflog_data nflog_data_t;

typedef enum {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    OTHER = -1
} qtype_t;

typedef enum {
    IPV4 = 4,
    IPV6 = 6
} ip_version_t;

typedef struct {
    qtype_t query_type;
    ip_version_t ip_version;
    char dns_server[IP_MAX_SIZE];
    char domain[DOMAIN_MAX_SIZE];
} dns_response_t;

int add_rule(const char *iptables_path, const char *rule);

int delete_rule(const char *iptables_path, const char *rule);

int parse_domain(char *dns_payload, int dns_payload_len, dns_response_t *response, int *seek);
void parse_query_type(char *dns_payload, int question_start, dns_response_t *response);

void parse_dns_packet(char *payload, int payload_len, dns_response_t *response);

static int callback(nflog_g_handle_t *group_handle, nfgenmsg_t *nfmsg, nflog_data_t *nfa, void *data);

// TODO: Change to write dns response to log_fd
int write_dns_response(dns_response_t response, FILE *log_fd);

void signal_handler(int signum);

void cleanup(void);

int init_nflog(void);

#endif