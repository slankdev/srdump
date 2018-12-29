
LIBSLANK := ./libslankdev
CXXFLAGS += -I$(LIBSLANK) -Wall -Wextra -std=c++11
LDFLAGS += -lpcap

SRC = main.cc
OBJ = $(SRC:.cc=.o)
TARGET = srdump

all: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) $(TARGET)

install: all
	mkdir -p /usr/local/bin
	cp srdump /usr/local/bin/srdump

run: all
	sudo ip netns exec ns ./srdump -i net0 -Q out

install_docker:
	for c in `docker ps --format "{{.Names}}"`; do\
		docker cp srdump $$c:/usr/bin/srdump ; done

