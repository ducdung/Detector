#include <map>
#include <string>
#include <cassert>
#include <cstdlib>

#include <errno.h>
#include <inttypes.h>
// Local header
#include "thread_info.hpp"

std::map< uint32_t, thread_info_t * > thread_info_map;

thread_info_t * get_thread_info(uint32_t tid)
{
	std::map<uint32_t, thread_info_t *>::iterator iter = thread_info_map.find(tid);
	// Found it
	if(iter != thread_info_map.end()) { return iter->second; }
	// There is no such thread
	return NULL;
}

void write_thread_info(uint32_t tid, thread_info_t * thread_info)
{
	thread_info_t * info = get_thread_info(tid);

	if(info == NULL) {
		thread_info_t * info = (thread_info_t * ) malloc( sizeof(thread_info_t) );
		// Copy the thread information
		* info = * thread_info;
		// and store it in the map
		thread_info_map[ tid ] = info;
	} else {
		// There is already a thread with the same id, overwrite it
		* info = * thread_info;
	}
}

void delete_thread_info(uint32_t tid)
{
	std::map< uint32_t, thread_info_t * >::iterator iter = thread_info_map.find(tid);
	// Remove if exists
	if (iter != thread_info_map.end()) {
		thread_info_t * info = iter->second;
		thread_info_map.erase(iter);
		// Remember to clean up the malloc
		free(info);
	}
}

