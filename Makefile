CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -O2 -D_DEFAULT_SOURCE
LDFLAGS = -lpcap

SRC = main.c capture.c dns_parser.c
OBJ = $(SRC:.c=.o)

TARGET = dns_capture

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
