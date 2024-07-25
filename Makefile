CC = gcc
CFLAGS = -Wall -Wextra -g

# Main target (static binary)
MAIN_OBJS = main.c
MAIN_TARGET = main.out
MAIN_INCLUDES = -Idns_sniffer/include -Ifirewall/include -I/usr/include/libnetfilter_log
MAIN_LIBS = -L. -lnetfilter_log -ldns_sniffer -lfirewall

# Firewall
FW_CFLAGS = $(CFLAGS) -shared -fPIC
FW_OBJS = firewall/src/firewall.c
FW_TARGET = libfirewall.so
FW_INCLUDES = -Ifirewall/include

# DNS Sniffer 
DNS_SNIFFER_CFLAGS = $(CFLAGS) -shared -fPIC 
DNS_SNIFFER_OBJS = dns_sniffer/src/dns_sniffer.c
DNS_SNIFFER_TARGET = libdns_sniffer.so
DNS_SNIFFER_INCLUDES = -Idns_sniffer/include -I/usr/include/libnetfilter_log
DNS_SNIFFER_LIBS = -L/usr/lib -lnetfilter_log 

all: 
	$(MAIN_TARGET) $(FW_TARGET) $(DNS_SNIFFER_TARGET)

main: $(MAIN_TARGET)
$(MAIN_TARGET): $(MAIN_OBJS)
	$(CC) $(CFLAGS) $(MAIN_OBJS) $(MAIN_INCLUDES) $(MAIN_LIBS) -o $(MAIN_TARGET)

firewall: $(FW_TARGET)
$(FW_TARGET): $(FW_OBJS)
	$(CC) $(FW_CFLAGS) $(FW_OBJS) $(FW_INCLUDES) -o $(FW_TARGET)

dns_sniffer: $(DNS_SNIFFER_TARGET)
$(DNS_SNIFFER_TARGET): $(DNS_SNIFFER_OBJS)
	$(CC) $(DNS_SNIFFER_CFLAGS) $(DNS_SNIFFER_OBJS) $(DNS_SNIFFER_INCLUDES) $(DNS_SNIFFER_LIBS) -o $(DNS_SNIFFER_TARGET)

clean:
	rm -f $(MAIN_TARGET) $(FW_TARGET) $(DNS_SNIFFER_TARGET) *.o
