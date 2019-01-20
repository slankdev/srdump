
LIBSLANK := ./libslankdev
CXXFLAGS += -I$(LIBSLANK) -Wall -Wextra -std=c++11
LDFLAGS += -lpcap

SRC = main.cc
OBJ = $(SRC:.cc=.o)
TARGET = srdump

srdump: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) $(TARGET)

install: srdump
	install -m 0755 srdump /usr/local/bin

uninstall:
	rm /usr/local/bin/srdump

install_docker:
	for c in `docker ps --format "{{.Names}}"`; do\
		docker cp srdump $$c:/usr/bin/srdump ; done
