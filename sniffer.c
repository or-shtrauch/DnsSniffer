#include "sniffer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// declaring those variables globally for use in cleanup method
static nflog_handle_t *handle;
static nflog_g_handle_t *group_handle;
static FILE *log_fd;

int iptables(const char *iptables_path, int delete, const char *nflog_group, const char *dport) {
    char *argv[] = {
        iptables_path,
        delete == 1 ? "-D" : "-A",
        "OUTPUT",
        "-p", "udp", "-m", "udp",
        "--dport", dport,
        "-j", "NFLOG",
        "--nflog-group", nflog_group,
        NULL
    };

    printf("running iptables command: ");
    for (int i = 0; argv[i]!= NULL; i++) {
        printf("%s ", argv[i]);
    }
    printf("\n");

    pid_t pid = fork();
    if (pid < 0) {
        perror("failed running fork");
        return EXIT_FAILURE;
    }
    
    if (pid == 0) {
        execv(iptables_path, argv);
        perror("Exec failed\n");
        exit(1);
    } else {
        wait(NULL);
    }

    return EXIT_SUCCESS;
}

int parse_domain(const char *dns_payload, int dns_payload_len, dns_response_t *out, int *seek) {
    /*
        to make sure were not going out of bounds in `data`,
        if `data` is smaller or equal to the size of the dns header section
        we simply return
    */
    if (dns_payload_len <= 12)
        return EXIT_FAILURE;

    // starting after the dns header
    // at an offset of 12 bytes from the start
    int i = 12, char_index = 0;
    while (i < dns_payload_len) {
        int section_length = dns_payload[i];
        if (section_length == 0)
            break;

        /*
            An example for the domain section in the dns payload
            03 'w' 'w' 'w' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00
            each section is prefix with each length, followed by a '.'
            character so, ill fetch the length of the current section, then
            loop for this length and print each char
        */
        for (int j = 1; j <= section_length; j++) {
            out->domain[char_index++] = dns_payload[i + j];
        }

        // move to the next section in the domain
        i += section_length + 1;

        // only print '.' if the next section length is not 0 (the domain
        // end)
        if (dns_payload[i] != 0)
            out->domain[char_index++] = '.';
    }

    // setting seek at the end of domain/start of the question section (for query type parsing)
    *seek = i + 1;

    out->domain[char_index] = '\0';
    return EXIT_SUCCESS;
}

void parse_query_type(char *dns_payload, int question_start, dns_response_t *out) {
    /*
        the qtype field is 16 bit long, so ill be using an `uint16_t` field to
        fetch its value the field resides right
    */
    uint16_t qtype;
    memcpy(&qtype, (char *)(dns_payload + question_start), sizeof(uint16_t));

    out->query_type = (qtype_t)ntohs(qtype);
}

void parse_dns_packet(char *payload, int payload_len, dns_response_t *out) {
    char src_ip[IP_MAX_SIZE] = {0};
    int dns_payload_len, seek = 0;
    char *dns_payload;

    /*
        The DNS Header is the first 12 (and 8 for IPV6) bytes of the data
        so according the structure of the DNS packet,
        the src ip resides at an offset of 12/8 bytes after the start of the DNS
        packet
    */
    if (out->ip_version == IPV4) {
        inet_ntop(AF_INET, (char *)(payload + 12), out->dns_server, INET_ADDRSTRLEN);

        if (payload_len < IPV4_DNS_PAYLOAD_OFFSET)
            return;

        dns_payload = (char *)(payload + IPV4_DNS_PAYLOAD_OFFSET);
        dns_payload_len = payload_len - IPV4_DNS_PAYLOAD_OFFSET;
    } else {  // IPV6
        inet_ntop(AF_INET6, (char *)(payload + 8), out->dns_server, INET6_ADDRSTRLEN);

        if (payload_len < IPV6_DNS_PAYLOAD_OFFSET)
            return;

        dns_payload = (char *)(payload + IPV6_DNS_PAYLOAD_OFFSET);
        dns_payload_len = payload_len - IPV6_DNS_PAYLOAD_OFFSET;
    }

    parse_domain(dns_payload, dns_payload_len, out, &seek);
    parse_query_type(dns_payload, seek, out);
}

static int cb_handle_dns_packet(nflog_g_handle_t *group_handle, nfgenmsg_t *nfmsg, nflog_data_t *nfa, void *data) {
    FILE *log_fd = (FILE *)data;
    dns_response_t dns_response;
    int offset = 0;

    char *payload;
    int payload_len = nflog_get_payload(nfa, &payload);
    if (payload_len < 0)
        return EXIT_SUCCESS;

    // Extract the IP version from the first byte of the IP header
    char ip_version = (payload[0] >> 4) & 0x0f;

    dns_response.ip_version = (ip_version_t)ip_version;

    parse_dns_packet(payload, payload_len, &dns_response);
    write_dns_response(dns_response, log_fd);

    return EXIT_SUCCESS;
}

int write_dns_response(dns_response_t response, FILE *log_fd) {
    if (!log_fd)
        return EXIT_FAILURE;

    fprintf(log_fd, "Server: %s, Domain: %s, IP Version: %s, Query Type: %s\n",
            response.dns_server,
            response.domain,
            (response.ip_version == IPV4) ? "IPv4" : "IPv6",
            (response.query_type == A) ? "A" : (response.query_type == AAAA) ? "AAAA"
                                           : (response.query_type == CNAME)  ? "CNAME"
                                                                             : "Unknown");
}

void signal_handler(int signum) {
    printf("got signal %d\n", signum);
    cleanup();
    exit(0);
}

int init_nflog(void) {
    printf("Opening a new handler\n");
    handle = nflog_open();
    if (!handle) {
        fprintf(stderr, "Error opening netlink handle\n");
        return EXIT_FAILURE;
    }

    printf("unbinding handle from ipv4 and ipv6\n");
    if (nflog_unbind_pf(handle, AF_INET) < 0 || nflog_unbind_pf(handle, AF_INET6) < 0) {
        fprintf(stderr, "Error unbinding to IPV4 or IPv6\n");
        cleanup();
        return EXIT_FAILURE;
    }

    printf("binding handle to IPV4 & IPv6\n");
    if (nflog_bind_pf(handle, AF_INET) < 0 || nflog_bind_pf(handle, AF_INET6) < 0) {
        fprintf(stderr, "Error binding to IPV4 or IPv6\n");
        cleanup();
        return EXIT_FAILURE;
    }

    printf("Binding to Group %d\n", NFLOG_GROUP);
    group_handle = nflog_bind_group(handle, NFLOG_GROUP);
    if (!group_handle) {
        fprintf(stderr, "Error binding to group %d\n", NFLOG_GROUP);
        cleanup();
        return EXIT_FAILURE;
    }

    printf("Setting mode to copy packets\n");
    if (nflog_set_mode(group_handle, NFULNL_COPY_PACKET, MAX_PKT_SIZE) < 0) {
        fprintf(stderr, "Error setting mode\n");
        cleanup();
        return EXIT_FAILURE;
    };

    log_fd = fopen(LOG_FILE_PATH, LOG_FILE_MODE);
    if (!log_fd) {
        fprintf(stderr, "Error opening log file\n");

        cleanup();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void cleanup(void) {
    printf("Cleanup\n");

    // i dont care if this fails, so no return value checking
    iptables(IPTABLES, 1, NFLOG_GROUP_STR, DNS_PORT_STR);
    iptables(IP6TABLES, 1, NFLOG_GROUP_STR, DNS_PORT_STR);

    if (log_fd)
        fclose(log_fd);
    if (group_handle)
        nflog_unbind_group(group_handle);
    if (handle)
        nflog_close(handle);
}

int init_iptables(void) {
    if (iptables(IPTABLES, 1, NFLOG_GROUP_STR, DNS_PORT_STR) > 0 || iptables(IP6TABLES, 1, NFLOG_GROUP_STR, DNS_PORT_STR) > 0) {
        printf("Failed To clear previous iptables/ip6tables rules\n");
        return EXIT_FAILURE;
    }

    if (iptables(IPTABLES, 0, NFLOG_GROUP_STR, DNS_PORT_STR) > 0 || iptables(IP6TABLES, 0, NFLOG_GROUP_STR, DNS_PORT_STR) > 0) {
        printf("Failed To Add iptables/ip6tables rules\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*
NFLOG Flow:
 - registering signal handlers
 - setting up firewall rules
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

int main(void) {
    handle = NULL;
    group_handle = NULL;
    log_fd = NULL;

    char buffer[BUFFER_SIZE];
    int rv;

    // setting signal handlers for graceful termination
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

   if (!init_iptables()) {
        printf("Failed to initialize iptables\n");
        return EXIT_FAILURE;
   }

    if (init_nflog() > 0) {
        printf("Failed To Initialize nflog\n");
        return EXIT_FAILURE;
    }

    /*
        passing log_fd to the callback function, to later write to the log file
        important note is that the callback function, should not manage this fd
        it is being closed at the end of the main function
    */
    printf("Subscribing callback to nflog packet recv event\n");
    int err = nflog_callback_register(group_handle, &cb_handle_dns_packet, log_fd);
    if (err < 0) {
        printf("Error registering callback err: %d\n", err);
        cleanup();

        return EXIT_FAILURE;
    }

    printf("creating a new fd for nflog handle\n");
    int fd = nflog_fd(handle);
    if (!fd) {
        fprintf(stderr, "Error creating fd\n");
        cleanup();

        return EXIT_FAILURE;
    }

    printf("Sniffing.. fd = %d\n", fd);
    while ((rv = recv(fd, buffer, BUFFER_SIZE, 0)) && rv >= 0) {
        // if received data is 0, continue to next iteration
        if (rv < 0)
            continue;

        if (nflog_handle_packet(handle, buffer, rv) < 0)
            printf("error handling packet..doing nothing\n");
    }

    cleanup();

    return EXIT_SUCCESS;
}