CC       = gcc
CFLAGS   = -Wall -Werror -g -O0 -std=c99 -Iinclude
LDFLAGS  =
TARGETS  = lock lock_admin

COMMON_SRCS = src/readin.c src/crypto_engine.c src/hardware_ctrl.c
COMMON_OBJS = $(COMMON_SRCS:.c=.o)

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -framework PCSC
else ifeq ($(UNAME_S),Linux)
    CFLAGS  += $(shell pkg-config --cflags libpcsclite 2>/dev/null)
    LDFLAGS += $(shell pkg-config --libs   libpcsclite 2>/dev/null)
else
    LDFLAGS += -lwinscard
endif

.PHONY: all clean

all: $(TARGETS)

lock: src/main.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

lock_admin: src/admin.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGETS)
