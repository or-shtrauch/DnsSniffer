
#include "sniffer.h"

int main()
{
    int exit_code = EXIT_OK;
    nflog_handle_t *handle;
    nflog_g_handle_t *group_handle;
    FILE *log_fd;
    cleanup_state_e state;
    int nflog_fd, rv;
    char buffer[BUFFER_SIZE];

    fprintf(stdout, "Starting...\n");

    // log_fd = fopen(LOG_FILE_PATH, LOG_FILE_MODE);
    // if (!log_fd)
    // {
    //     fprintf(stdout, "Error opening log file\n");
    //     return EXIT_ERROR;
    // }

    // fprintf(stdout, "Opening log file\n");

    fprintf(stdout, "calling init_sniffer\n");
    if ((init_sniffer(handle, group_handle, &state)) == EXIT_ERROR)
    {
        fprintf(stdout, "error while called init_sniffer\n");
        goto cleanup;
    }

    fprintf(stdout, "calling get_nflog_fd\n");
    if ((exit_code = get_nflog_fd(handle, &nflog_fd)) == EXIT_ERROR)
    {
        fprintf(stdout, "error while called get_nflog_fd:\n");
        goto cleanup;
    }

    fprintf(stdout, "sniffing\n");
    while ((rv = recv(nflog_fd, buffer, BUFFER_SIZE, 0) && rv >= 0))
    {
        nfulnl_msg_packet_hdr_t *pkt_header = (nfulnl_msg_packet_hdr_t *)buffer;
        iphdr_t *ip_header = (iphdr_t *)(buffer + sizeof(nfulnl_msg_packet_hdr_t));
        udphdr_t *udp_header = (udphdr_t *)(buffer + sizeof(nfulnl_msg_packet_hdr_t) + ip_header->ihl * 4);

        // even though the iptables rule is only for udp:53, im still checking the pkt headers for protocol and port
        if (ip_header->protocol == IPPROTO_UDP && ntohs(udp_header->dest) == DNS_PORT)
        {
            fprintf(stdout, "got dns\n");
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);
            fprintf(stdout, "DNS packet: %s -> %s\n", src_ip, dst_ip);
        }
    }

cleanup:
    fprintf(stdout, "cleanup\n");
    fclose(log_fd);
    close_sniffer(handle, group_handle, &state);
    return exit_code;
}

// while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
// {
//     // Process received packet (similar to kernel module)
//     struct nfulnl_msg_packet_hdr *ph = (struct nfulnl_msg_packet_hdr *)buf;
//     struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct nfulnl_msg_packet_hdr));
//     struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct nfulnl_msg_packet_hdr) + iph->ihl * 4);
//     if (iph->protocol == IPPROTO_UDP && ntohs(udph->dest) == 53)
//     {
//         // Log the packet data (use ph->hw_protocol, ph->payload etc.)
//         char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
//         inet_ntop(AF_INET, &iph->saddr, src_ip, INET_ADDRSTRLEN);
//         inet_ntop(AF_INET, &iph->daddr, dst_ip, INET_ADDRSTRLEN);
//         fprintf(logfile, "DNS packet: %s -> %s\n", src_ip, dst_ip); // Example log format
//         // You can add more detailed logging by parsing the DNS payload if needed
//     }
//     nflog_handle_packet(h, buf, rv);
// }
