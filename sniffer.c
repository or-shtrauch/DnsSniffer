#include <libnetfilter_log/libnetfilter_log.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "sniffer.h"

int init(nflog_handle_t *handle, nflog_g_handle_t *group_handle, FILE *log_fd, cleanup_state_e *state)
{
    int i;
    *state = NO_CLEANUP;

    // fetching a handle for nflog
    handle = nflog_open();
    if (!handle)
    {
        fprintf(stderr, "Error opening netfilter log handle\n");
        return EXIT_ERROR;
    }

    int protocols[] = {AF_INET, AF_INET6};

    for (i = 0; i < 2; i++)
    {
        // unbinding any leftovers
        if (nflog_unbind_pf(handle, protocols[i]) < 0)
        {
            fprintf(stderr, "Error unbinding from %d\n", protocols[i]);
            return EXIT_ERROR;
        }

        // binding to AF_INET/6
        if (nflog_bind_pf(handle, protocols[i]) < 0)
        {
            fprintf(stderr, "error during nflog_bind_pf() for %d\n", protocols[i]);
            return EXIT_ERROR;
        }

        if (!i)
        {
            *state = HANDLE;
        }
    }

    group_handle = nflog_bind_group(handle, NFLOG_GROUP);
    if (!group_handle)
    {
        fprintf(stderr, "Error, no handle for nflog group %d\n", NFLOG_GROUP);
        return EXIT_ERROR;
    }

    *state = GROUP_HANDLE;

    if (nflog_set_mode(group_handle, NFULNL_COPY_PACKET, MAX_PKT_SIZE) < 0)
    {
        fprintf(stderr, "Error setting nflog mode\n");
        return EXIT_ERROR;
    }

    FILE *fp = fopen(LOG_FILE_PATH, LOG_FILE_MODE);
    if (!fp)
    {
        fprintf(stderr, "Error opening log file\n");
        return EXIT_ERROR;
    }

    *state = LOG_FILE;

    return EXIT_OK;
}

int get_nflog_fd(nflog_handle_t *handle, int *out_fd) {
    *out_fd = nflog_fd(handle);

    if (nflog_fd < 0) {
        fprintf(stderr, "Error getting nflog file descriptor\n");
        return EXIT_ERROR;
    }
}

void close(nflog_handle_t *handle, nflog_g_handle_t *group_handle, FILE *log_fd, cleanup_state_e *state)
{
    if (state == NO_CLEANUP)
        return;

    if (state >= GROUP_HANDLE)
        nflog_unbind_group(group_handle);

    if (state >= HANDLE)
        nflog_close(handle);

    if (state == LOG_FILE)
        fclose(log_fd);
}
