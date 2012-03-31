include ../config-host.mak

DEFINES=-I. -I$(SRC_PATH) -I$(SRC_PATH)/i386-softmmu 
#DEFINES+=-I$(VINE_PATH)/libasmir/src/include
DEFINES+=-I$(SRC_PATH)/shared/xed2/include
DEFINES+=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE
DEFINES+=-I$(SRC_PATH)/shared/llconf/install/include

CFLAGS=-Wall -g -fPIC -O4
LDFLAGS=-g -Wl -shared 
LIBS=-L/usr/local/lib -lbfd
# LIBS+=$(SRC_PATH)/shared/llconf/install/lib/libllconf.a

ifeq ($(ARCH), x86_64)
LIBS+=-L$(SRC_PATH)/shared/xed2/xed2-intel64/lib -lxed
DEFINES+= -I$(SRC_PATH)/shared/xed2/xed2-intel64/include
endif
ifeq ($(ARCH), i386)
LIBS+=-L$(SRC_PATH)/shared/xed2/xed2-ia32/lib -lxed
DEFINES+= -I$(SRC_PATH)/shared/xed2/xed2-ia32/include
endif

OBJS=../shared/procmod.o ../shared/read_linux.o ../shared/hookapi.o ../shared/hooks/function_map.o 
OBJS+=hookfinder.o tracing.o ../shared/reduce_taint.o thread_info.o

PLUGIN = hookfinder.so


all: $(PLUGIN) trace_reader

trace_reader.o: trace_reader.c
	gcc -O4 -g -Wall $(DEFINES) -c -o $@ $<
	
%.o: %.c 
	gcc $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	g++ $(CFLAGS) $(DEFINES) -c -o $@ $<

$(PLUGIN): $(OBJS)
	g++ $(LDFLAGS) $^ -o $@ $(LIBS)

trace_reader: trace_reader.o
	g++ -g -o $@ $< $(LIBS)

clean:
	rm -f *.o *.so *~ $(PLUGIN) ../shared/*.o 


