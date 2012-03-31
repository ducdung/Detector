#include "config.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/user.h>
#include <sys/time.h>
#include <unistd.h>
#include "TEMU_main.h"
#include "tracing.h"
#include "hookfinder.h"

FILE *tracelog = 0;

void term_printf(const char *fmt, ...);

void prepare_trace_record(trace_record_t *trec)
{
  bzero(trec, sizeof(trace_record_t));
  trec->is_new = 0;
  trec->eip = *TEMU_cpu_eip;
  TEMU_read_mem(*TEMU_cpu_eip, 16, trec->raw_insn);
  if (current_thread_node) {
    trec->caller = current_thread_node->eip;
    trec->callee = current_thread_node->entry_eip;
    trec->esp = current_thread_node->esp; //FIXME: this should be the esp on function entry
  }
}


void write_trace(trace_record_t *trec)
{
  fwrite(trec, 1, sizeof(trace_record_t), tracelog);
}

void write_new_trace_record(taint_record_t *records, int size, uint32_t val)
{
  int i;
  trace_record_t trace_rec;
  taint_record_t taint_rec;
  bzero(&trace_rec, sizeof(trace_rec));
  trace_rec.is_new = 1;
  for(i=0; i<size; i++) 
	trace_rec.define.dst_id[i] = records[i].depend_id;

  trace_rec.eip = *TEMU_cpu_eip;
  if(current_thread_node)
    trace_rec.esp = current_thread_node->esp;
  trace_rec.caller = records[0].caller;
  trace_rec.callee = records[0].callee;
  trace_rec.mem_addr = TEMU_cpu_regs[R_A0];
  trace_rec.mem_val = val;
 
  if(taintcheck_register_check(R_A0, 0, 1, (uint8_t*)(&taint_rec)))
	trace_rec.address_id = taint_rec.depend_id;
  TEMU_read_mem(*TEMU_cpu_eip, 16, trace_rec.raw_insn);
  write_trace(&trace_rec);
}

void start_trace(const char *filename)
{
  if (tracelog) {
	term_printf("Tracing is already started!\n");
	return;
  }

  tracelog = fopen(filename, "w");
  if (0 == tracelog) {
	term_printf("Failed to open %s! \n", filename);
    return;
  }

  term_printf("Tracing is started successfully!\n");
  return;
}


void stop_trace()
{
  if (tracelog) {
    fclose(tracelog);
    tracelog = 0;
    term_printf("tracing has been stopped!\n");
  }
}

