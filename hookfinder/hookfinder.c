#include "config.h"
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include "../list.h"
#include "TEMU_main.h"
#include "shared/hookapi.h"
#include "hookfinder.h"
#include "shared/procmod.h"
#include "shared/hooks/function_map.h"
#include "slirp/slirp.h"
#include "tracing.h"
#include "shared/reduce_taint.h"
#include "thread_info.h"

static plugin_interface_t hookfinder_interface;

static FILE *hookfinder_log = NULL;
static taint_record_t *possible_hook_record = NULL;
static char checked_module_name[256] = "";
static uint32_t last_insn_pc = 0;
uint32_t current_tid = 0;
thread_info_t *current_thread_node = NULL;
static uint32_t cur_depend_id = 1;
static uint32_t checked_module_base = 0;
static int taint_sendkey_id = 0;
static int taint_nic_state = 0;
static char current_proc[64];
static char current_mod[64];
int in_checked_module = 0; //1: in the module, 2: in the generated code, 3: in function call

extern int impact_propagate;

typedef struct {
  char buf[256];
  struct list_head link;
} logbuf_t;

static logbuf_t log_buffer[32];
static LIST_HEAD(log_stack);

static void log_init()
{
  int i;
  memset(log_buffer, 0, sizeof(log_buffer));
  for (i = 0; i < sizeof(log_buffer) / sizeof(logbuf_t); i++)
    list_add(&log_buffer[i].link, &log_stack);
}

static void writelog(FILE * fp, char *fmt, ...)
{
  va_list ap;
  char log[256];
  struct list_head *pos;
  logbuf_t *lbuf;

  memset(log, 0, sizeof(log));
  va_start(ap, fmt);
  vsnprintf(log, 255, fmt, ap);
  va_end(ap);

  list_for_each(pos, &log_stack) {
    lbuf = list_entry(pos, logbuf_t, link);
    if (!strcmp(log, lbuf->buf)) {
      list_del(pos);
      list_add(pos, &log_stack);
      return;
    }
  }
  pos = log_stack.prev;
  lbuf = list_entry(pos, logbuf_t, link);
  strcpy(lbuf->buf, log);
  list_del(pos);
  list_add(pos, &log_stack);
  fprintf(fp, "%s", log);
  fflush(fp);
}


static void do_check_module(const char *name)
{
  strcpy(checked_module_name, name);
  term_printf("module to check: %s\n", name);
}

static void do_stop_check(void)
{
  checked_module_name[0] = 0;
  term_printf("hookfinder is stopped!\n");
}

static void do_taint_nic(int state)
{
  taint_nic_state = state;
}

extern void do_send_key(const char *string);

void do_taint_sendkey(const char *string, int id)
{
  taint_sendkey_id = id;
  do_send_key(string);
}

static void hookfinder_send_keystroke(int reg)
{
  taint_record_t record;
  if (taint_sendkey_id) {
	bzero(&record, sizeof(record));
	record.depend_id = cur_depend_id++;
    taintcheck_taint_register(reg, 0, 1, 1, (unsigned char *) &record);
    taint_sendkey_id = 0;
  }
}


static term_cmd_t hookfinder_term_cmds[] = {
  {"check_module", "s", do_check_module,
   "module_name", "specify the name of module to be tested"},
  {"stop_check", "", do_stop_check,
   "", "stop finding hooks"},
  {"start_trace", "s", start_trace,
   "file_name", "start tracing"},
  {"stop_trace", "", stop_trace,
   "", "stop tracing"},
  {"guest_ps", "", list_procs,
   "", "list the processes on guest system"},
  {"taint_nic", "i", do_taint_nic,
   "state", "set the network input to be tainted or not"},
  {"taint_sendkey", "si", do_taint_sendkey,
   "key id", "send a tainted key to the guest system"},
  {NULL, NULL},
};

static term_cmd_t hookfinder_info_cmds[] = {
  {NULL, NULL},
};


static void hookfinder_guest_message(char *message)
{
  switch (message[0]) {
  case 'P':
    parse_process(message);
    break;
  case 'M':
    parse_module(message);
    break;
  }
}

static int hookfinder_block_begin()
{
  taint_record_t records[4];
  uint8_t taint;
  tmodinfo_t *mi;
//  char proc[32];
//  int resume_from_interrupt = 0;

  if (checked_module_name[0] == 0)
    goto _finished;

  current_tid = get_current_tid();
  current_thread_node =
      (current_tid != -1UL)? get_thread_info(current_tid) : NULL;

  mi = locate_module(*TEMU_cpu_eip, TEMU_cpu_cr[3], current_proc);
  strcpy(current_mod, mi? mi->name: "<unknown>");
  if (!strcasecmp(current_mod, checked_module_name)) {
    checked_module_base = mi->base;
    in_checked_module = 1;
    goto _handle_in_malware;
  }

  uint32_t phys_addr = TEMU_get_phys_addr(*TEMU_cpu_eip);
  taint = taintcheck_memory_check(phys_addr, 1, (uint8_t *)records);
  if (taint) {
    //this may be generated code
    in_checked_module = 2;
/*
    if (mi && mi->sys) {
      writelog(hookfinder_log,
                 "code patch: %s!%s eip=%08x depend_id=%08x\n", current_proc,
                 mi->name, *TEMU_cpu_eip, records[0].depend_id);
    }else */
    {
      writelog(hookfinder_log,
                 "tainted_code: %s!%s eip=%08x depend_id=%08x\n", current_proc,
                 mi? mi->name: "<unknown>", *TEMU_cpu_eip, records[0].depend_id);
    }

    goto _handle_in_malware;
  }

  //in system code

  if(current_thread_node) {
    if (current_thread_node->origin == 1 || current_thread_node->origin == 2) {
      //jump out of malicious code
      if ((current_thread_node->esp & 0x80000000) ==
          (TEMU_cpu_regs[R_ESP] & 0x80000000)
          && current_thread_node->esp < TEMU_cpu_regs[R_ESP]) {
        //return from malware
        delete_thread_info(current_tid);
        current_thread_node = NULL;
#if HOOKFINDER_DEBUG
        fprintf(taintlog, "delete tid=%d\n", current_tid);
#endif
        goto _finished;
      }

      if ((current_thread_node->esp & 0x80000000) ==
          (TEMU_cpu_regs[R_ESP] & 0x80000000)
          && current_thread_node->esp > TEMU_cpu_regs[R_ESP]) {
        //external call
        current_thread_node->entry_eip = *TEMU_cpu_eip; //callee
        //if(!resume_from_interrupt)
        //  current_thread_node->eip = last_insn_pc; //caller
        current_thread_node->origin = 3;
        goto _finished;
      }
    }
  }
  possible_hook_record = NULL;
  goto _finished;

_handle_in_malware:

  //to determine a hook:
  // 1. caller is far away from the current eip to exclude SEH
  if (possible_hook_record &&
      *TEMU_cpu_eip - possible_hook_record->caller > 0x20) {

    if (tracelog)
      writelog(hookfinder_log,
               "hook found: hook_proc=%08x eip=%08x callee=%08x caller=%08x depend_id=%08x\n",
               *TEMU_cpu_eip, possible_hook_record->eip,
               possible_hook_record->callee, possible_hook_record->caller,
               possible_hook_record->depend_id);
    else
      writelog(hookfinder_log,
               "hook found: hook_proc=%08x eip=%08x callee=%08x caller=%08x\n",
               *TEMU_cpu_eip, possible_hook_record->eip,
               possible_hook_record->callee, possible_hook_record->caller);
  }
  possible_hook_record = NULL;

  if(current_tid == -1UL) {
    goto _finished;
  }

  if(!current_thread_node) {
    thread_info_t info;
    bzero(&info, sizeof(info));
    info.cr3 = TEMU_cpu_cr[3];
    info.esp = TEMU_cpu_regs[R_ESP];
    info.eip = 0;
    info.origin = in_checked_module;
    write_thread_info(current_tid, &info);
    current_thread_node = get_thread_info(current_tid);
  }

  current_thread_node->out_eip = 0;
  current_thread_node->eip = 0;
  current_thread_node->entry_eip = 0;
  current_thread_node->origin = in_checked_module;

_finished:

  hookapi_check_call(in_checked_module != 0);
  in_checked_module = current_thread_node? current_thread_node->origin: 0;
  return 0;
}


static int hookfinder_init()
{
  function_map_init();
  init_hookapi();
  procmod_init();

  reduce_taint_init();

  log_init();
  if (!(hookfinder_log = fopen("hook.log", "w")))
    return -1;

  return 0;
}

static void hookfinder_cleanup()
{
  do_stop_check();
  if(tracelog)
    stop_trace();
  fclose(hookfinder_log);
  hookfinder_log = NULL;

  procmod_cleanup();
  hookapi_cleanup();
  function_map_cleanup();
}

static void hookfinder_mem_read(uint32_t virt_addr, uint32_t phys_addr,
                                   int size)
{
  taint_record_t records[4];
  int i;

  if(!current_thread_node) return;
  if(current_thread_node->origin != 1) return;

  bzero(records, sizeof(records));
  for (i = 0; i < size; i++) {
    records[i].eip = *TEMU_cpu_eip;
    records[i].depend_id = cur_depend_id++;
  }
  taintcheck_taint_memory(phys_addr, size, (1 << size) - 1,
                          (uint8_t *) records);
  if (tracelog) {
    uint32_t val;
    cpu_physical_memory_rw(phys_addr, (uint8_t *)&val, size, 0);
    write_new_trace_record(records, size, val);
  }
}

static void hookfinder_mem_write(uint32_t virt_addr, uint32_t phys_addr,
                                 int size)
{
  taint_record_t records[4];
  int i, should_taint = 0;
  uint8_t taint;

  if (impact_propagate == 0) return;
  if (!current_thread_node) return;
  if (current_thread_node->origin == 0) return;

  taint = taintcheck_memory_check(phys_addr, size, (uint8_t *) records);

  if (current_thread_node->origin != 3) { //in module or self-generated code
    if(taint) return;

    bzero(records, sizeof(records));
    for (i = 0; i < size; i++) {
      records[i].eip = *TEMU_cpu_eip;
      records[i].depend_id = cur_depend_id++;
    }
    taintcheck_taint_memory(phys_addr, size, (1 << size) - 1,
                            (uint8_t *) records);
    if (tracelog) {
      uint32_t val;
      cpu_physical_memory_rw(phys_addr, (uint8_t *)&val, size, 0);
      write_new_trace_record(records, size, val);
    }
    return;
  }

  //in function call
  if (taint) {
    //if the memory is tainted, update callee/caller
    for (i = 0; i < size; i++) {
      if (taint & (1 << i)) {
        if (records[i].caller == 0) {
          records[i].callee = current_thread_node->entry_eip;
          records[i].caller = current_thread_node->eip;
          should_taint = 1;
        }
      }
    }
    if(should_taint)
      taintcheck_taint_memory(phys_addr, size, taint, (uint8_t *) records);
    return;
  }

  //the memory is not tainted
//#define TAINT_FUNCTION_CALL
#ifdef TAINT_FUNCTION_CALL
  bzero(records, sizeof(records));
  for (i = 0; i < size; i++) {
    records[i].eip = *TEMU_cpu_eip;
    records[i].callee = current_thread_node->entry_eip;
    records[i].caller = current_thread_node->eip;
    records[i].depend_id = cur_depend_id++;
  }
  taintcheck_taint_memory(phys_addr, size, (1 << size) - 1,
                            (uint8_t *) records);
  if (tracelog) {
    uint32_t val = *(uint32_t *) (phys_ram_base + phys_addr);
    write_new_trace_record(records, size, val);
  }
#endif
}


static void hookfinder_tainted_eip(uint8_t * record)
{
  if (!current_thread_node || current_thread_node->origin != 1) {
    // in system code or patched code
    possible_hook_record = (taint_record_t *) record;
  }
}

static void hookfinder_taint_propagate(int nr_src,
                                       taint_operand_t * src_oprnds,
                                       taint_operand_t * dst_oprnd,
                                       int mode)
{
  int i, j;
  taint_record_t *taint_record = NULL; //, *saved_record = NULL;
  taint_record_t *dst_rec, *src_rec;
  taint_record_t *tmp_rec;
  trace_record_t trace_rec;
  int src_index = 0, dst_index = 0;

  if (tracelog)
    prepare_trace_record(&trace_rec);

  if (mode == PROP_MODE_MOVE) {
    trace_rec.prop.is_move = 1;
    if (nr_src == 1) {
      for (i = 0; i < src_oprnds[0].size; i++)
        if (src_oprnds[0].taint & (1 << i)) {
          dst_rec = (taint_record_t *) dst_oprnd->records + i;
          src_rec = (taint_record_t *) src_oprnds[0].records + i;
          memmove(dst_rec, src_rec, sizeof(taint_record_t));
          if (tracelog)
            trace_rec.prop.src_id[src_index++] = src_rec->depend_id;
          dst_rec->depend_id = cur_depend_id++;
          if (tracelog)
            trace_rec.prop.dst_id[dst_index++] = dst_rec->depend_id;
        }


      if (tracelog) {
        if (dst_oprnd->type == 1) {
          taint_record_t rec;
          trace_rec.mem_addr = TEMU_cpu_regs[R_A0];
          trace_rec.mem_val =
              TEMU_cpu_regs[src_oprnds[0].addr >> 2];
          if (taintcheck_register_check(R_A0, 0, 1, (uint8_t *) & rec))
            trace_rec.address_id = rec.depend_id;
        }
      }

      if (tracelog)
        write_trace(&trace_rec);

      return;
    }

  }

  /* deal with multiple sources */
  if (tracelog)
    trace_rec.prop.is_move = 0;

  for (i = 0; i < nr_src; i++) {
    if (src_oprnds[i].taint == 0)
      continue;

    for (j = 0; j < src_oprnds[i].size; j++)
      if (src_oprnds[i].taint & (1 << j)) {
        tmp_rec = (taint_record_t *) src_oprnds[i].records + j;
        if (!taint_record) {
          taint_record = tmp_rec;
          if (!tracelog)
            goto copy_taint_record;
        }

        if (tracelog)
          trace_rec.prop.src_id[src_index++] = tmp_rec->depend_id;
      }
  }

  if (!taint_record)
    return;

copy_taint_record:

  for (i = 0; i < dst_oprnd->size; i++) {
    dst_rec = (taint_record_t *) dst_oprnd->records + i;
    memmove(dst_rec, taint_record, sizeof(taint_record_t));
    dst_rec->depend_id = cur_depend_id++;
    if (tracelog) {
      trace_rec.prop.dst_id[dst_index++] = dst_rec->depend_id;
    }
  }

  if (tracelog) {
    /*if(dst_oprnd->type == 0) {
       trace_rec.prop.dst_reg = dst_oprnd->addr>>2;
       trace_rec.prop.dst_val = TEMU_cpu_regs[trace_rec.prop.dst_reg];
       } */
    write_trace(&trace_rec);
  }
}

static void hookfinder_insn_begin()
{
  static uint32_t cur_pc;
  last_insn_pc = cur_pc;
  cur_pc = *TEMU_cpu_eip;
}


static void hookfinder_do_interrupt(int intno, int is_int, uint32_t next_eip)
{
  if(in_checked_module && is_int == 0) {
   /*
     * an interrupt happens:
     * 1) save the return eip; 2) save the thread state; 3) save the pc before int
     * 4) set thread state to 0
     */
    current_thread_node->out_eip = is_int ? next_eip : *TEMU_cpu_eip;
    current_thread_node->origin_before_int = current_thread_node->origin;
    current_thread_node->origin = 0;
  }
}
static void hookfinder_after_iret_protected()
{
  current_tid = get_current_tid();
  current_thread_node = (current_tid != -1UL) ? get_thread_info(current_tid) : NULL;

  if (current_thread_node && current_thread_node->out_eip &&
      *TEMU_cpu_eip - current_thread_node->out_eip < 16) {
    /*
     * return from interrupt/exception:
     * restore the thread state before the interrupt/exeception
     */
    current_thread_node->out_eip = 0;
    current_thread_node->origin = current_thread_node->origin_before_int;
  }
}




typedef struct {
  uint16_t port;
  uint32_t init_seq;
  struct list_head link;
} tcpconn_record_t;

static LIST_HEAD(tcpconn_list);

static int hookfinder_add_tcpconn(uint16_t port, uint32_t seq)
{
  struct list_head *pos;
  tcpconn_record_t *tcp;
  list_for_each(pos, &tcpconn_list) {
    tcp = list_entry(pos, tcpconn_record_t, link);
    if (tcp->port == port) {
      tcp->init_seq = seq;
      return 0;
    }
  }

  if ((tcp = (tcpconn_record_t *) malloc(sizeof(tcpconn_record_t)))) {
    tcp->port = port;
    tcp->init_seq = seq;
    list_add(&tcp->link, &tcpconn_list);
  }
  return 0;
}


static uint32_t hookfinder_get_tcpseq(uint16_t port)
{
  struct list_head *pos;
  tcpconn_record_t *tcp;
  list_for_each(pos, &tcpconn_list) {
    tcp = list_entry(pos, tcpconn_record_t, link);
    if (tcp->port == port)
      return tcp->init_seq;
  }
  return 0;
}

static int hookfinder_del_tcpconn(uint16_t port)
{
  struct list_head *pos;
  tcpconn_record_t *tcp;
  list_for_each(pos, &tcpconn_list) {
    tcp = list_entry(pos, tcpconn_record_t, link);
    if (tcp->port == port) {
      list_del(pos);
      free(tcp);
      break;
    }
  }
  return 0;
}



static void hookfinder_nic_recv(uint8_t * buf, int size, int index,
                                 int start, int stop)
{
  struct ip *iph = (struct ip *) (buf + 14);
  struct tcphdr *tcph = (struct tcphdr *) (buf + 34);
  uint32_t seq = 0;
  int hlen = 0, tolen, len2 = 0, offset = 0, avail, len, i;
  taint_record_t record;

  if (!taint_nic_state || buf[12] != 0x08 || buf[13] != 0
      || iph->ip_p != 6)
    goto L1;

  if ((tcph->th_flags & (TH_ACK | TH_SYN)) == (TH_ACK | TH_SYN)) {
    hookfinder_add_tcpconn(ntohs(tcph->th_sport), ntohl(tcph->th_seq));
  }
  else if ((seq = hookfinder_get_tcpseq(ntohs(tcph->th_sport)))) {
    tolen = ntohs(iph->ip_len) + 14;
    hlen = 34 + tcph->th_off * 4;
    len2 = tolen - hlen;
  }
  if (len2) {
    bzero(&record, sizeof(record));
  }

L1:
  while (size > 0) {
    avail = stop - index;
    len = size;
    if (len > avail)
      len = avail;

    for (i = 0; i < len; i += 64)
      taintcheck_nic_writebuf(index + i, min(len - i, 64), 0, NULL);
    if (len2) {
      if (!offset) {
        if (len > hlen)
          for (; offset < len - hlen; offset++) {
            record.depend_id = cur_depend_id++;
            taintcheck_nic_writebuf(index + hlen + offset, 1, 1,
                                    (uint8_t *) & record);
            if(tracelog) write_new_trace_record(&record, 1, 0);
          }
      }
      else
        for (; offset < min(len2, offset + len); offset++) {
          record.depend_id = cur_depend_id++;
          taintcheck_nic_writebuf(index + offset, 1, 1,
                                  (uint8_t *) & record);
          if(tracelog) write_new_trace_record(&record, 1, 0);
        }
    }
    index += len;
    if (index == stop)
      index = start;
    size -= len;
  }
}

static void hookfinder_nic_send(uint32_t addr, int size, uint8_t * buf)
{
  struct ip *iph = (struct ip *) (buf + 14);
  struct tcphdr *tcph = (struct tcphdr *) (buf + 34);

  if (buf[12] != 0x08 || buf[13] != 0x0)
    return;

  if (iph->ip_p == 6) {
    if ((tcph->th_flags & (TH_ACK | TH_SYN)) == (TH_ACK | TH_SYN))
      hookfinder_add_tcpconn(ntohs(tcph->th_dport), ntohl(tcph->th_ack));
    else if (tcph->th_flags & TH_FIN)
      hookfinder_del_tcpconn(ntohs(tcph->th_dport));
  }
}

static void hookfinder_taint_disk(uint64_t addr, uint8_t * record,
                                void *opaque)
{
#if 0
  taint_record_t *rec = (taint_record_t *)record;
  term_printf("disk taint: addr=%Lx id=%08x\n", addr, rec->depend_id);
  vm_stop(0);
#endif
}


plugin_interface_t *init_plugin()
{
  hookfinder_interface.term_cmds = hookfinder_term_cmds;
  hookfinder_interface.info_cmds = hookfinder_info_cmds;
  hookfinder_interface.plugin_cleanup = hookfinder_cleanup;
  hookfinder_interface.taint_record_size = sizeof(taint_record_t);
  hookfinder_interface.taint_propagate = hookfinder_taint_propagate;
  hookfinder_interface.guest_message = hookfinder_guest_message;
  hookfinder_interface.send_keystroke = hookfinder_send_keystroke;
  hookfinder_interface.block_begin = hookfinder_block_begin;
  hookfinder_interface.insn_begin = hookfinder_insn_begin;

  hookfinder_interface.taint_disk = hookfinder_taint_disk;

  hookfinder_interface.nic_recv = hookfinder_nic_recv;
  hookfinder_interface.nic_send = hookfinder_nic_send;

  hookfinder_interface.eip_tainted = hookfinder_tainted_eip;

  hookfinder_interface.mem_write = hookfinder_mem_write;
  hookfinder_interface.mem_read = hookfinder_mem_read;

  hookfinder_interface.monitored_cr3 = 0;
  hookfinder_interface.do_interrupt = hookfinder_do_interrupt;
  hookfinder_interface.after_iret_protected = hookfinder_after_iret_protected;

  hookfinder_init();
  return &hookfinder_interface;
}
