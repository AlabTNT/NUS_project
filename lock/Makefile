CC       = gcc
CFLAGS   = -Wall -Werror -g -O0 -std=c99 -Iinclude
LDFLAGS  =
TARGET   = lock
SRCS     = src/main.c src/readin.c src/crypto_engine.c src/hardware_ctrl.c
OBJS     = $(SRCS:.c=.o)

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

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
