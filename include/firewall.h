#ifndef __FIREWALL_H__
#define __FIREWALL_H__

#include <stdint.h>

#define DNS_PORT_STR "53"
#define EXIT_CODE_MASK 0xFF
#define NFLOG_BINDINGS_MAX_GROUP_SIZE 6

enum iptables_rule_action_t {
    DELETE_RULE = 1,
    ADD_RULE = 0
};

enum firewall_iptables_chain_t {
    INPUT_CHAIN = 0,
    OUTPUT_CHAIN = 1,
    FORWARD_CHAIN = 2,
    MAX_CHAIN = 3,
};

enum firewall_exec_exit_status_t {
    FW_INVALID_ERROR_EXIT_CODE = -3,
    FW_EXEC_ERROR_EXIT_CODE = -2,
    FW_FORK_ERROR_EXIT_CODE = -1,
    FW_SUCCESS_EXIT_CODE = 0,
};

int firewall_add_output_dns_nflog_rule(int ip_version, uint16_t nflog_group);

int firewall_delete_output_dns_nflog_rule(int ip_version, uint16_t nflog_group);

#endif