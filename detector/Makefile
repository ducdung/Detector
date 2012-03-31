include ../config-host.mak

DEFINES=-I. -I$(SRC_PATH) -I$(SRC_PATH)/i386-softmmu -I$(SRC_PATH)/target-i386 -I$(SRC_PATH)/fpu
DEFINES+=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE

CFLAGS=-Wall -g -fPIC -O4 -MMD
LDFLAGS=-g -Wl -shared 
LIBS=-lm

ifeq ($(ARCH), x86_64)
LIBS+=-L$(SRC_PATH)/shared/xed2/xed2-intel64/lib -lxed
DEFINES+= -I$(SRC_PATH)/shared/xed2/xed2-intel64/include
endif
ifeq ($(ARCH), i386)
LIBS+=-L$(SRC_PATH)/shared/xed2/xed2-ia32/lib -lxed
DEFINES+= -I$(SRC_PATH)/shared/xed2/xed2-ia32/include
endif

OBJS=../shared/procmod.o ../shared/read_linux.o ../shared/hookapi.o ../shared/hooks/function_map.o ../shared/reduce_taint.o
OBJS+=detector.o thread_info.o

PLUGIN = detector.so

all: $(PLUGIN)

%.o: %.c 
	gcc $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	g++ $(CFLAGS) $(DEFINES) -c -o $@ $<

$(PLUGIN): $(OBJS)
	g++ $(LDFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f *.o *.so *~ $(PLUGIN) ../shared/*.o 


