#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <stdio.h>

#define BUFFER_SIZE 4096
#define DNS_PORT 53
#define DNS_PORT_STR "53"

#define NFLOG_GROUP 3
#define NFLOG_GROUP_STR "3"

#define IPTABLES "/usr/sbin/iptables"
#define IP6TABLES "/usr/sbin/ip6tables"

#define MAX_PKT_SIZE 0xffff

#define IPV4_DNS_PAYLOAD_OFFSET 28
#define IPV6_DNS_PAYLOAD_OFFSET 48

#define LOG_FILE_PATH "./log"
#define LOG_FILE_MODE "a"

#define MAX_LINE_SIZE 1024
#define DOMAIN_MAX_SIZE 256
#define IP_MAX_SIZE 40  // using ipv6 size

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

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

int iptables(const char *iptables_path, int delete, const char *nflog_group, const char *dport);
int parse_domain(const char *dns_payload, int dns_payload_len, dns_response_t *out, int *seek);

void parse_query_type(char *dns_payload, int question_start, dns_response_t *out);

void parse_dns_packet(char *payload, int payload_len, dns_response_t *out);

static int cb_handle_dns_packet(nflog_g_handle_t *group_handle, nfgenmsg_t *nfmsg, nflog_data_t *nfa, void *data);

int write_dns_response(dns_response_t response, FILE * log_fd);

void signal_handler(int signum);

void cleanup(void);

int init_nflog(void);

#endif