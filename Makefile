CC = gcc
CFLAGS = -Wall -Wextra -g 

OBJS = sniffer.c

TARGET = dns_sniffer

INCLUDES = -I/usr/include/libnetfilter_log 

LIBS = -lnetfilter_log

all: 
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) $(INCLUDES) -o $(TARGET) 

clean:
	rm -f $(TARGET)
