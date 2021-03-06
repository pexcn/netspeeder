CC ?= gcc
DESTDIR ?= /usr/local
SRC ?= src/netspeeder.c
BIN ?= netspeeder

all: $(SRC)
	$(CC) -o $(BIN) $(SRC) -s -O3 -lpcap -lnet -Wl,--build-id=none

static: $(SRC)
	$(CC) -o $(BIN) $(SRC) -s -O3 -lpcap -lnet -Wl,--build-id=none -Wl,-static -static

install: $(BIN)
	install -d $(DESTDIR)/bin/
	install $(BIN) $(DESTDIR)/bin/

uninstall:
	rm -f $(DESTDIR)/bin/$(BIN)

clean:
	rm -f $(BIN)
