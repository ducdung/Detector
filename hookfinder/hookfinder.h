#ifndef HOOKFINDER_H_INCLUDED
#define HOOKFINDER_H_INCLUDED

#include "thread_info.h"

typedef struct {
  uint32_t caller;
  uint32_t callee;
  uint32_t eip;
  uint32_t depend_id;
//  uint32_t last_tainted_eip; 
}taint_record_t;

extern thread_info_t *current_thread_node;

#endif
