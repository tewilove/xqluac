
CFLAGS := -Wall
CFLAGS += -m32
#CFLAGS += -DDEBUG_PRINT_INSN
CPPFLAGS := $(CFLAGS)
CPPFLAGS +=
LDFLAGS := -static -m32

all: xqluac

xqluac_OBJS := main.o

xqluac: $(xqluac_OBJS)
	g++ -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	g++ -c -o $@ $^ $(CPPFLAGS)

clean:
	rm -f *.o
	rm -f xqluac

.phony: clean
