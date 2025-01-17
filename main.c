#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "dns_sniffer.h"
#include "firewall.h"

#define IPV4 4
#define IPV6 6

#define NFLOG_GROUP 3

#define SUCCESS_EXIT 0
#define FAILURE_EXIT 1

static struct dns_sniffer_t g_sniffer = {0};
static struct dns_callback_data_t g_callback_data = {0};

void cleanup() {
    printf("Cleaning Up...\n");
    firewall_delete_output_dns_nflog_rule(IPV4, NFLOG_GROUP);
    firewall_delete_output_dns_nflog_rule(IPV6, NFLOG_GROUP);

    dns_sniffer_close(&g_sniffer);

    if (g_callback_data.output_fd) {
        fclose(g_callback_data.output_fd);
        g_callback_data.output_fd = NULL;
    }
}

void setup_iptables_rules() {
    /* removing any existing rules from previous runs */
    firewall_delete_output_dns_nflog_rule(IPV4, NFLOG_GROUP);
    firewall_delete_output_dns_nflog_rule(IPV6, NFLOG_GROUP);

    firewall_add_output_dns_nflog_rule(IPV4, NFLOG_GROUP);
    firewall_add_output_dns_nflog_rule(IPV6, NFLOG_GROUP);
}

void print_dns_packet_cb(struct dns_response_t *response, FILE *output_fd) {
    char timestamp[20];
    time_t now = time(NULL);
    struct tm *local = localtime(&now);

    strftime(timestamp, sizeof(timestamp), "%d-%m-%Y %H:%M:%S", local);
    printf("%s | Server: %s, Domain: %s, IP Version: %s, Query Type: %s\n",
           timestamp,
           response->dns_server,
           response->domain,
           (response->ip_version == IPV4) ? "IPv4" : "IPv6",
           (response->query_type == A) ? "A" : (response->query_type == AAAA) ? "AAAA"
                                           : (response->query_type == CNAME)  ? "CNAME"
                                                                              : "Unknown");
    fprintf(output_fd, "%s | Server: %s, Domain: %s, IP Version: %s, Query Type: %s\n",
            timestamp,
            response->dns_server,
            response->domain,
            (response->ip_version == IPV4) ? "IPv4" : "IPv6",
            (response->query_type == A) ? "A" : (response->query_type == AAAA) ? "AAAA"
                                            : (response->query_type == CNAME)  ? "CNAME"
                                                                               : "Unknown");
}

void signal_handler(int signum) {
    g_sniffer.should_exit = 1;
    printf("Got Signal %d\n", signum);
}

int main() {
    int return_code = SUCCESS_EXIT;

    printf("Setting Up Signal Handlers\n");
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Opening Log File\n");
    g_callback_data.output_fd = fopen(LOG_FILE_PATH, LOG_FILE_MODE);
    if (!g_callback_data.output_fd) {
        printf("Error Opening Log File\n");
        return_code = FAILURE_EXIT;
        goto cleanup;
    }

    printf("Setting Up Iptables Rules\n");
    setup_iptables_rules();

    printf("Initializing DNS Sniffer\n");
    g_callback_data.callback = print_dns_packet_cb;
    return_code = dns_sniffer_start(&g_sniffer, &g_callback_data, NFLOG_GROUP);
    if (return_code < DS_SIGNAL_INTERRUPT_EXIT_CODE) {
        printf("Failed To Initialize Sniffer, Exit Code: %d\n", return_code);
        goto cleanup;
    }

    if (return_code == DS_SIGNAL_INTERRUPT_EXIT_CODE) {
        printf("Received Interrupt Signal\n");
    }

cleanup:
    cleanup();
    printf("Exiting With Code: %d\n", return_code);
    return return_code;
}