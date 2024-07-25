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
dns_callback_data_t callback_data;

void cleanup() {
    printf("Cleaning up...\n");
    delete_incoming_dns_nflog_rule(IPV4, NFLOG_GROUP);
    delete_incoming_dns_nflog_rule(IPV6, NFLOG_GROUP);

    close_dns_sniffer(&sniffer);

    if (callback_data.output_fd) {
        fclose(callback_data.output_fd);
        callback_data.output_fd = NULL;
    }
}

void setup_iptables_rules() {
    /* removing any existing rules from previous runs */
    delete_incoming_dns_nflog_rule(IPV4, NFLOG_GROUP);
    delete_incoming_dns_nflog_rule(IPV6, NFLOG_GROUP);

    add_incoming_dns_nflog_rule(IPV4, NFLOG_GROUP);
    add_incoming_dns_nflog_rule(IPV6, NFLOG_GROUP);
}

void cb_print_dns_packet(dns_response_t *response, FILE *output_fd) {
    fprintf(output_fd, "Server: %s, Domain: %s, IP Version: %s, Query Type: %s\n",
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

    printf("Setting up signal handlers\n");
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("opening log file\n");
    callback_data.output_fd = fopen(LOG_FILE_PATH, LOG_FILE_MODE);
    if (!callback_data.output_fd) {
        printf("Error opening log file\n");
        return FAILURE_EXIT;
    }

    printf("Setting up iptables rules\n");
    setup_iptables_rules();

    printf("Initializing DNS sniffer\n");
    exit_code = init_dns_sniffer(&sniffer, NFLOG_GROUP);
    if (exit_code != DS_SUCCESS_EXIT_CODE) {
        printf("Failed to initialize sniffer, exit code: %d\n", exit_code);
        cleanup();
        return FAILURE_EXIT;
    }

    printf("Registering packet handler\n");
    callback_data.callback = cb_print_dns_packet;
    exit_code = register_packet_handler(&sniffer, &callback_data);
    if (exit_code != DS_SUCCESS_EXIT_CODE) {
        printf("Failed to register packet handler, exit code: %d\n", exit_code);
        cleanup();
        return FAILURE_EXIT;
    }

    printf("Starting DNS sniffer\n");
    exit_code = start_dns_sniffer(&sniffer);
    if (exit_code != DS_SUCCESS_EXIT_CODE) {
        printf("Failed to start sniffer, exit code: %d\n", exit_code);
        cleanup();
        return FAILURE_EXIT;
    }

    cleanup();
    return SUCCESS_EXIT;
}