#ifndef __DNS_SNIFFER_H__
#define __DNS_SNIFFER_H__

#include <stdint.h>
#include <stdio.h>

#define BUFFER_SIZE 4096
#define DNS_PORT 53

#define IP_VERSION_MASK 0x0f
#define MAX_PKT_SIZE 0xffff

#define IPV4_DNS_PAYLOAD_OFFSET 28
#define IPV6_DNS_PAYLOAD_OFFSET 48

#define LOG_FILE_PATH "./log"
#define LOG_FILE_MODE "a"

#define MAX_LINE_SIZE 1024
#define DOMAIN_MAX_SIZE 256
#define IP_MAX_SIZE 40  // using ipv6 size

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

typedef enum {
    DS_NFLOG_OPEN_ERROR_EXIT_CODE,
    DS_NFLOG_UNBINDING_PF_ERROR_EXIT_CODE,
    DS_NFLOG_BINDING_PF_ERROR_EXIT_CODE,
    DS_NFLOG_BIND_GROUP_ERROR_EXIT_CODE,
    DS_NFLOG_SET_MODE_ERROR_EXIT_CODE,
    DS_NFLOG_REGISTER_CALLBACK_ERROR_EXIT_CODE,
    DS_NFLOG_OPEN_FD_ERROR_EXIT_CODE,
    DS_GENERAL_FAILURE_EXIT_CODE,
    DS_SUCCESS_EXIT_CODE = 0
} dns_sniffer_exit_status_t;

typedef struct {
    qtype_t query_type;
    ip_version_t ip_version;
    char dns_server[IP_MAX_SIZE];
    char domain[DOMAIN_MAX_SIZE];
} dns_response_t;

typedef struct {
    void (*callback)(dns_response_t *response, FILE *output_fd);
    FILE *output_fd;
} dns_callback_data_t;

typedef struct {
    nflog_handle_t *nflog_handle;
    nflog_g_handle_t *nflog_group_handle;
} dns_sniffer_t;


dns_sniffer_exit_status_t init_dns_sniffer(dns_sniffer_t *sniffer, uint16_t nflog_group);

void parse_domain(const char *dns_payload, int dns_payload_len, dns_response_t *out, int *seek);

void parse_query_type(char *dns_payload, int question_start, dns_response_t *out);

void parse_dns_packet(char *payload, int payload_len, dns_response_t *out);

int cb_handle_dns_packet(nflog_g_handle_t *group_handle, nfgenmsg_t *nfmsg, nflog_data_t *nfa, void *data);

dns_sniffer_exit_status_t register_packet_handler(dns_sniffer_t *sniffer, dns_callback_data_t *callback_data);

dns_sniffer_exit_status_t start_dns_sniffer(dns_sniffer_t *sniffer);

void close_dns_sniffer(dns_sniffer_t *sniffer);

#endif