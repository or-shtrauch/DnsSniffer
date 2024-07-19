
#include <errno.h>
#include "sniffer.h"

int init_sniffer(nflog_handle_t **handle, nflog_g_handle_t **group_handle, cleanup_state_e *state)
{
    int i;
    *state = NO_CLEANUP;

    // fetching a handle for nflog
    fprintf(stdout, "Opening handle\n");
    *handle = nflog_open();
    if (!handle)
    {
        fprintf(stdout, "Error opening netfilter log handle\n");
        return EXIT_ERROR;
    }

    int protocols[] = {AF_INET, AF_INET6};

    for (i = 0; i < 2; i++)
    {
        // unbinding any leftovers
        fprintf(stdout, "Unbinding %d\n", protocols[i]);
        if (nflog_unbind_pf(handle, protocols[i]) < 0)
        {
            fprintf(stdout, "Error unbinding from %d\n", protocols[i]);
            return EXIT_ERROR;
        }

        // binding to AF_INET/6
        fprintf(stdout, "Binding %d\n", protocols[i]);
        if (nflog_bind_pf(*handle, protocols[i]) < 0)
        {
            fprintf(stdout, "error during nflog_bind_pf() for %d\n", protocols[i]);
            return EXIT_ERROR;
        }

        if (!i)
        {
            *state = HANDLE;
        }
    }

    fprintf(stdout, "Binding Handle to group %d\n", NFLOG_GROUP);
    *group_handle = nflog_bind_group(handle, NFLOG_GROUP);
    if (!group_handle)
    {
        fprintf(stdout, "Error, no handle for nflog group %d\n", NFLOG_GROUP);
        return EXIT_ERROR;
    }

    *state = GROUP_HANDLE;

    fprintf(stdout, "Setting nflog mode to copy packets\n");
    if (nflog_set_mode(*group_handle, NFULNL_COPY_PACKET, MAX_PKT_SIZE) < 0)
    {
        fprintf(stdout, "Error setting nflog mode\n");
        return EXIT_ERROR;
    }

    fprintf(stdout, "Finished init_sniffer\n");
    return EXIT_OK;
}

int main(void) {
    int exit_code = EXIT_OK;
    nflog_handle_t *handle = NULL;
    nflog_g_handle_t *group_handle = NULL;
    // FILE *log_fd;
    cleanup_state_e state;
    int fd = 0, rv;
    char buffer[BUFFER_SIZE];

    fprintf(stdout, "Starting...\n");

    int i;
    *state = NO_CLEANUP;

    // fetching a handle for nflog
    fprintf(stdout, "Opening handle\n");
    *handle = nflog_open();
    if (!handle)
    {
        fprintf(stdout, "Error opening netfilter log handle\n");
        return EXIT_ERROR;
    }

    int protocols[] = {AF_INET, AF_INET6};

    for (i = 0; i < 2; i++)
    {
        // unbinding any leftovers
        fprintf(stdout, "Unbinding %d\n", protocols[i]);
        if (nflog_unbind_pf(handle, protocols[i]) < 0)
        {
            fprintf(stdout, "Error unbinding from %d\n", protocols[i]);
            return EXIT_ERROR;
        }

        // binding to AF_INET/6
        fprintf(stdout, "Binding %d\n", protocols[i]);
        if (nflog_bind_pf(*handle, protocols[i]) < 0)
        {
            fprintf(stdout, "error during nflog_bind_pf() for %d\n", protocols[i]);
            return EXIT_ERROR;
        }

        if (!i)
        {
            *state = HANDLE;
        }
    }

    fprintf(stdout, "Binding Handle to group %d\n", NFLOG_GROUP);
    *group_handle = nflog_bind_group(handle, NFLOG_GROUP);
    if (!group_handle)
    {
        fprintf(stdout, "Error, no handle for nflog group %d\n", NFLOG_GROUP);
        return EXIT_ERROR;
    }

    *state = GROUP_HANDLE;

    fprintf(stdout, "Setting nflog mode to copy packets\n");
    if (nflog_set_mode(*group_handle, NFULNL_COPY_PACKET, MAX_PKT_SIZE) < 0)
    {
        fprintf(stdout, "Error setting nflog mode\n");
        return EXIT_ERROR;
    }

    fprintf(stdout, "Finished init_sniffer\n");
    return EXIT_OK;
}

// int get_nflog_fd(nflog_handle_t *handle, int *out_fd)
// {
//     fprintf(stdout, "Opening fd to nflog\n");
//     *out_fd = nflog_fd(handle);
//     if (*out_fd < 0)
//     {
//         fprintf(stdout, "Error getting nflog file descriptor - %ls\n", out_fd);
//         return EXIT_ERROR;
//     }

//     return EXIT_OK;
// }

void close_sniffer(nflog_handle_t *handle, nflog_g_handle_t *group_handle, cleanup_state_e *state)
{
    if (*state == NO_CLEANUP)
        return;

    if (*state >= GROUP_HANDLE)
        nflog_unbind_group(group_handle);

    if (*state >= HANDLE)
        nflog_close(handle);
}
