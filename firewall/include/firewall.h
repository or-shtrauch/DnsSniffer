#ifndef __FIREWALL_H__
#define __FIREWALL_H__

#include <stdint.h>

#define DNS_PORT_STR "53"
#define EXIT_CODE_MASK 0xFF
#define NFLOG_BINDINGS_MAX_GROUP_SIZE 6

typedef enum {
    DELETE_RULE = 1,
    ADD_RULE = 0
} iptables_rule_action_t;

typedef enum {
    FW_EXEC_ERROR_EXIT_CODE = -2,
    FW_FORK_ERROR_EXIT_CODE = -1,
    FW_SUCCESS_EXIT_CODE = 0,
} firewall_exec_exit_status_t;

static firewall_exec_exit_status_t execute_incoming_dns_nflog_rule(iptables_rule_action_t rule_action, int ip_version, uint16_t nflog_group);

firewall_exec_exit_status_t add_incoming_dns_nflog_rule(int ip_version, const char *nflog_group);

firewall_exec_exit_status_t delete_incoming_dns_nflog_rule(int ip_version, const char *nflog_group);

#endif