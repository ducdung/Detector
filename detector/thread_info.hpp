#ifndef THREAD_INFO_H_INCLUDED
#define THREAD_INFO_H_INCLUDED

//! Everything about a thread
typedef struct {
	uint32_t cr3;
	uint32_t esp;
	uint32_t eip;
	uint32_t out_eip;
	uint32_t entry_eip;
	uint32_t origin;
	uint32_t origin_before_int;
} thread_info_t;

#ifdef __cplusplus
extern "C" {
#endif

/// @ingroup HookFinder
/// Given a thread id, it returns the associated thread_info_t structure.
thread_info_t * get_thread_info(uint32_t tid);

/// @ingroup HookFinder
/// Associate thread information with the thread id.
void write_thread_info(uint32_t tid, thread_info_t *thread_info);

/// @ingroup HookFinder
/// Delete thread information, given the thread id
void delete_thread_info(uint32_t tid);

#ifdef __cplusplus
};
#endif

#endif

