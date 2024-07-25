#include <signal.h>
#include <stdio.h>

#include "dns_sniffer.h"
#include "firewall.h"

#define IPV4 4
#define IPV6 6

#define NFLOG_GROUP 3

#define SUCCESS_EXIT 0
#define FAILURE_EXIT 1

dns_sniffer_t sniffer;

void cleanup() {
    delete_incoming_dns_nflog_rule(IPV4, NFLOG_GROUP);
    delete_incoming_dns_nflog_rule(IPV6, NFLOG_GROUP);

    close_dns_sniffer(&sniffer);
}

void cb_print_dns_packet(dns_response_t *response) {
    printf("Server: %s, Domain: %s, IP Version: %s, Query Type: %s\n",
           response->dns_server,
           response->domain,
           (response->ip_version == IPV4) ? "IPv4" : "IPv6",
           (response->query_type == A) ? "A" : (response->query_type == AAAA) ? "AAAA"
                                           : (response->query_type == CNAME)  ? "CNAME"
                                                                              : "Unknown");
}

void signal_handler(int signum) {
    printf("got signal %d\n", signum);
    cleanup();
    exit(0);
}

int main() {
    int exit_code;
    printf("Starting");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    add_incoming_dns_nflog_rule(IPV4, NFLOG_GROUP);
    add_incoming_dns_nflog_rule(IPV6, NFLOG_GROUP);

    exit_code = init_dns_sniffer(&sniffer, NFLOG_GROUP);
    if (exit_code != DS_SUCCESS_EXIT_CODE) {
        printf("Failed to initialize sniffer, exit code: %d\n", exit_code);
        cleanup();
        return FAILURE_EXIT;
    }

    exit_code = register_packet_handler(&sniffer, cb_print_dns_packet);
    if (exit_code != DS_SUCCESS_EXIT_CODE) {
        printf("Failed to register packet handler, exit code: %d\n", exit_code);
        cleanup();
        return FAILURE_EXIT;
    }

    exit_code = start_dns_sniffer(&sniffer);
    if (exit_code != DS_SUCCESS_EXIT_CODE) {
        printf("Failed to start sniffer, exit code: %d\n", exit_code);
        cleanup();
        return FAILURE_EXIT;
    }

    cleanup();
    return SUCCESS_EXIT;
}