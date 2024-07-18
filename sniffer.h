#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <stdio.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

#define BUFFER_SIZE 2048

#define DNS_PORT 53

#define NFLOG_GROUP 3
// #define OUTGOING_IPTABLES_COMMAND "sudo iptables -I INPUT -p udp --dport "DNS_PORT" -j NFLOG --nflog-group "NFLOG_GROUP
// #define INCOMING_IPTABLES_COMMAND "sudo iptables -I OUTPUT -p udp --sport "DNS_PORT" -j NFLOG --nflog-group "NFLOG_GROUP

// #define OUTGOING_IP6TABLES_COMMAND "sudo ip6tables -I INPUT -p udp --dport " DNS_PORT " -j NFLOG --nflog-group " NFLOG_GROUP
// #define INCOMING_IP6TABLES_COMMAND "sudo ip6tables -I OUTPUT -p udp --sport " DNS_PORT " -j NFLOG --nflog-group " NFLOG_GROUP

#define EXIT_OK 0
#define EXIT_ERROR 1

#define MAX_PKT_SIZE 0xffff

#define arr_size (arr) sizeof(arr) / sizeof(arr[0])

#define LOG_FILE_PATH "./log"
#define LOG_FILE_MODE "a"

typedef struct nflog_handle nflog_handle_t;
typedef struct nflog_g_handle nflog_g_handle_t;
typedef struct nfulnl_msg_packet_hdr nfulnl_msg_packet_hdr_t;
typedef struct iphdr iphdr_t;
typedef struct udphdr udphdr_t;

typedef enum cleanup_state {
    NO_CLEANUP = 0,
    HANDLE,
    GROUP_HANDLE,
} cleanup_state_e;

int init_sniffer(nflog_handle_t *handle, nflog_g_handle_t *group_handle, cleanup_state_e *state);

int get_nflog_fd(nflog_handle_t *handle, int *out_fd);

void subscribe_to_dns_pkts(int *nflog_fd, void(*dns_cb) (FILE *));

void close_sniffer(nflog_handle_t *handle, nflog_g_handle_t *group_handle, cleanup_state_e *state);

#endif