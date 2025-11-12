PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := ps5-self-pager.elf
SYSTEM_COMMON_LIB_ELF := ps5-self-pager-system-common-lib.elf
FULL_SYSTEM_ELF := ps5-self-pager-full-system.elf
SHELLCORE_ELF := ps5-self-pager-shellcore.elf
GAME_ELF := ps5-self-pager-game.elf

SOURCES := $(wildcard *.c)

CFLAGS := -O2 -lkernel_sys -Wall

all: $(ELF)
dist: $(SYSTEM_COMMON_LIB_ELF) $(FULL_SYSTEM_ELF) $(SHELLCORE_ELF) $(GAME_ELF)

$(ELF): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^

$(SYSTEM_COMMON_LIB_ELF): $(SOURCES)
	$(CC) $(CFLAGS) -DDUMP_SYSTEM_COMMON_LIB -o $@ $^

$(FULL_SYSTEM_ELF): $(SOURCES)
	$(CC) $(CFLAGS) -DDUMP_FULL_SYSTEM -o $@ $^

$(SHELLCORE_ELF): $(SOURCES)
	$(CC) $(CFLAGS) -DDUMP_SHELLCORE -o $@ $^

$(GAME_ELF): $(SOURCES)
	$(CC) $(CFLAGS) -DDUMP_GAME -o $@ $^

clean:
	rm -f *.elf

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

send: test

