#include <inttypes.h>
#include <string>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <map>
#include "thread_info.h"

using namespace std;

map<uint32_t, thread_info_t *> thread_info_map;

thread_info_t * get_thread_info(uint32_t tid)
{
  map<uint32_t, thread_info_t *>::iterator iter = thread_info_map.find(tid);

  if(iter != thread_info_map.end())
    return iter->second;

  return NULL;
}

void write_thread_info(uint32_t tid, thread_info_t *thread_info)
{
  thread_info_t *info = get_thread_info(tid);

  if(info == NULL) {
    thread_info_t *info = (thread_info_t *)malloc(sizeof(thread_info_t));
    *info = *thread_info;
    thread_info_map[tid] = info;
  } else {
    *info = *thread_info;
  }
}

void delete_thread_info(uint32_t tid)
{
  map<uint32_t, thread_info_t *>::iterator iter = thread_info_map.find(tid);
  if(iter != thread_info_map.end()) {
    thread_info_t *info = iter->second;
    thread_info_map.erase(iter);
    free(info);
  }
}
