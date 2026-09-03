# Build the ECDAT demo binary (SPEC.md §14 item 7).
#
# No -s and no strip: the binary collector reads .dynsym, and a stripped binary
# would still carry DT_NEEDED but lose the symbol evidence, which is half the
# point of the target.
#
# Build it against OpenSSL 1.1.x if you can. The DT_NEEDED entry is the input
# the advisor's feasibility check reads, and `libcrypto.so.1.1` is what makes
# the ML-KEM recommendation come back `blocked` rather than `recommended`.
# The container path in ../docker-compose.yml pins that for you; building on a
# host with OpenSSL 3.x gives libcrypto.so.3 and a different, also-correct
# answer from the advisor.

CC      ?= cc
CFLAGS  ?= -O0 -g -Wall -Wno-deprecated-declarations
LDLIBS  ?= -lcrypto
BUILD   ?= build

all: $(BUILD)/cryptodemo

$(BUILD)/cryptodemo: cryptodemo.c
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)
	@echo "built $@ — symbols intact, dynamically linked"

clean:
	rm -rf $(BUILD)

.PHONY: all clean
