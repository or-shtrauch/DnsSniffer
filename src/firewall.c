#include "firewall.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static char *iptables_chain_str[] = {
    "INPUT",
    "OUTPUT",
    "FORWARD",
};

static int firewall_execute_dns_nflog_rule(enum iptables_rule_action_t rule_action, 
                                                enum firewall_iptables_chain_t chain, 
                                                int ip_version, 
                                                uint16_t nflog_group) {
    char rule_action_str[3];
    char iptables_path[20];
    char nflog_group_str[NFLOG_BINDINGS_MAX_GROUP_SIZE];

    if (chain < 0 || chain >= MAX_CHAIN) {
        return FW_INVALID_ERROR_EXIT_CODE;
    }

    snprintf(rule_action_str, sizeof(rule_action_str), "%s", (rule_action == DELETE_RULE) ? "-D" : "-A");
    snprintf(iptables_path, sizeof(iptables_path), "%s", ip_version == 4 ? "/usr/sbin/iptables" : "/usr/sbin/ip6tables");
    snprintf(nflog_group_str, NFLOG_BINDINGS_MAX_GROUP_SIZE, "%u", nflog_group);

    char *argv[] = {
        iptables_path,
        rule_action_str,
        iptables_chain_str[chain],
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

int firewall_add_output_dns_nflog_rule(int ip_version, uint16_t nflog_group) {
    return firewall_execute_dns_nflog_rule(ADD_RULE, OUTPUT_CHAIN, ip_version, nflog_group);
}

int firewall_delete_output_dns_nflog_rule(int ip_version, uint16_t nflog_group) {
    return firewall_execute_dns_nflog_rule(DELETE_RULE, OUTPUT_CHAIN, ip_version, nflog_group);
}