#ifndef TRACING_H_INCLUDED
#define TRACING_H_INCLUDED
//#include "hookfinder.h"

extern FILE *tracelog;

typedef struct {
  int   is_new;
  union {
    struct {
      int   is_move;
      uint32_t src_id[12];
      uint32_t dst_id[4];
    }prop;
    struct {
	  uint32_t dst_id[4];
    }define;
  };
  uint32_t eip;
  uint32_t esp;
  uint32_t caller;
  uint32_t callee;
  uint32_t address_id;
  uint32_t mem_addr;
  uint32_t mem_val;
  uint8_t raw_insn[16];
} trace_record_t;

void prepare_trace_record(trace_record_t *trec);
void start_trace(const char *filename);
void stop_trace();
void write_trace(trace_record_t *trec);
void write_new_trace_record();

#endif
