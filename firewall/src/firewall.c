#include "firewall.h"

#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

    static firewall_exec_exit_status_t execute_incoming_dns_nflog_rule(iptables_rule_action_t rule_action, int ip_version, uint16_t nflog_group) {
    const char iptables_path[] = ip_version == 4 ? "/usr/sbin/iptables" : "/usr/sbin/ip6tables";
    char nflog_group_str[NFLOG_BINDINGS_MAX_GROUP_SIZE];

    snprintf(nflog_group_str, NFLOG_BINDINGS_MAX_GROUP_SIZE, "%u", nflog_group);

    char *argv[] = {
        iptables_path,
        (rule_action == DELETE_RULE) ? "-D" : "-A",
        "OUTPUT",
        "-p", "udp", "-m", "udp",
        "--dport", DNS_PORT_STR,
        "-j", "NFLOG",
        "--nflog-group", nflog_group_str,
        NULL};

    pid_t fork_pid = fork();
    if (fork_pid < 0)
        return FW_FORK_ERROR_EXIT_CODE;

    if (fork_pid == 0) {
        execv(iptables_path, argv);
        exit(FW_EXEC_ERROR_EXIT_CODE);
    } else {
        int child_process_status, child_exit_code;
        waitpid(fork_pid, &child_process_status, 0);

        child_exit_code = child_process_status & EXIT_CODE_MASK;

        if (child_exit_code == FW_EXEC_ERROR_EXIT_CODE)
            return child_exit_code;

        return FW_SUCCESS_EXIT_CODE;
    }
}

firewall_exec_exit_status_t add_incoming_dns_nflog_rule(int ip_version, const char *nflog_group) {
    return execute_incoming_dns_nflog_rule(ADD_RULE, ip_version, nflog_group);
}

firewall_exec_exit_status_t delete_incoming_dns_nflog_rule(int ip_version, const char *nflog_group) {
    return execute_incoming_dns_nflog_rule(DELETE_RULE, ip_version, nflog_group);
}