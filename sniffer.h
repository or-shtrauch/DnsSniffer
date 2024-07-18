#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#define NFLOG_GROUP 3
#define OUTGOING_IPTABLES_COMMAND "sudo iptables -I INPUT -p udp --dport 53 -j NFLOG --nflog-group "NFLOG_GROUP
#define INCOMING_IPTABLES_COMMAND "sudo iptables -I OUTPUT -p udp --sport 53 -j NFLOG --nflog-group "NFLOG_GROUP

#endif