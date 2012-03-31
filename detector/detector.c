/*
 * =====================================================================================
 *
 *       Filename:  detector.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  03/31/2012 07:02:05 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Do Hoang Nhat Huy
 *        Company:
 *
 * =====================================================================================
 */

// Standard header
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

// Temu headers
#include <config.h>
#include <TEMU_lib.h>
#include <slirp/slirp.h>
#include <shared/procmod.h>
#include <shared/hookapi.h>
#include <shared/read_linux.h>
#include <shared/reduce_taint.h>
#include <shared/hooks/function_map.h>
#include <xed-interface.h>

// Local headers
#include "detector.h"
#include "thread_info.hpp"

//! Some pre-defined value
enum location_t {
	// Not in the monitored process
	LOC_NOWHERE = 0,
	// Directly reside in the monitored module
	LOC_INSIDE,
	// In the code generate by the monitored process.
	// This may be useful (copy from Hookfinder)
	LOC_GEN,
	// In the function called by the monitored process.
	// This may be useful (copy from Hookfinder);
	LOC_FUNCTION
};

//! Name of the current module
char current_mod[512]	 = "";
//! Name of the current process
char current_proc[512]	 = "";
//! Name of the monitored process, the one we care about
char monitored_proc[512] = "";

//! XED2 handle
xed_state_t xed_state;

//! Handle to the queue log
FILE * loghandle		= NULL;
//! Name of the queue log
char const * logfile	= "detector.log";

//! This is the main interface of a plugin
static plugin_interface_t interface;

//! Are we in the monitored process.  Check procmod.h
enum location_t in_checked_module = LOC_NOWHERE;
//! This is the starting address of the monitored module.  Check procmod.h
uint32_t checked_module_base = 0;
//! This is the size of the monitored module.  Check procmod.h
uint32_t checked_module_size = 0;

//! Multi-thread, get from Hookfinder
uint32_t current_thread_id = 0;
//! Multi-thread, get from Hookfinder
thread_info_t * current_thread_node = NULL;

//! Address of the next-to-last instruction, get from Hookfinder
uint32_t last_eip = 0;

//! ID of the tainted keystroke which is sent to the guest os
int taint_sendkey_id = 0;

//! Save the name of the requested module, prepare to monitor it
void do_start_check(char const * name)
{
	strcpy(monitored_proc, name);
	// Print the message to TEMU terminal
	term_printf("module to check: %s\n", name);
}

//! Stop monitor the current process
static void do_stop_check(void)
{
	monitored_proc[ 0 ] = 0x00;
	// Print the message to TEMU terminal
	term_printf("detector is stopped!\n");
}

//! Get a keystroke from TEMU terminal
void do_taint_sendkey(char const * string, int id)
{
	taint_sendkey_id = id;
	// TEMU api
	do_send_key(string);
}

//! User commands
static term_cmd_t detector_term_cmds[] = {
	{"check_module"	,	"s"	,	do_start_check	, "procname", "specify the name of module to be tested"		},
	{"stop_check"	,	""	,	do_stop_check	, ""		, "stop finding return-oriented rootkit"		},
	{"guest_ps"		,	""	,	list_procs		, ""		, "list the processes on guest system"			},
	//We don't need this yet
	//{"taint_nic"	,	"i"	,	do_taint_nic	, "state"	, "set the network input to be tainted or not"	},
	{"taint_sendkey",	"si",	do_taint_sendkey, "key&id"	, "send a tainted key to the guest system"		},
	// Terminator
	{NULL, NULL},
};

//! User manual
static term_cmd_t detector_info_cmds[] = {
	// Nothing, eh ?
	{NULL, NULL},
};

//! What will happen when TEMU send the keystroke to the guest os
static void detector_send_keystroke(int reg)
{
	taint_record_t record;
	// A tainted keystroke
	if (taint_sendkey_id) {
		bzero( &record, sizeof(record) );
		taintcheck_taint_register(reg, 0, 1, 1, (unsigned char *) &record);

		// Reset the tainted key
		taint_sendkey_id = 0;
	}
}

/*!
 * This is the main function which decide how to customize taint analysis.
 * The operand structure is defined in taintcheck.h.  This may be necessary
 * but we don't use it for now.
 */
void detector_taint_propagate(	int nr_src,
								taint_operand_t * src_oprnds,
								taint_operand_t * dst_oprnd,
								int mode	)
{
	// Do nothing, just use the default policy
	default_taint_propagate(nr_src, src_oprnds, dst_oprnd, mode);
}

/*!
 * Parse the message from guest system to extract OS-level semantics.
 * What the fuck does it actually do ?
 */
void detector_guest_message(char * message)
{
	switch (message[0]) {
		case 'P':
			// An internal function.  Don't know about it
			parse_process( message );
			break;
		case 'M':
			// Again
			parse_module( message );
			break;
		default:
			// Which message is it ?
			fprintf(loghandle, "Unknown message: %s\n", message);
			break;
	}
}

/*!
 * This is not clear how Temu define a block, however, both Hookfinder
 * & the sample plugin use this function to check if they are working
 * on the monitored process or not.
 */
int detector_block_begin()
{
	// We care for nothing
	if (monitored_proc[0] == 0) { goto _finished; }

	uint32_t eip, esp, cr3;
	// Get the value of EIP register
	TEMU_read_register(eip_reg, &eip);
	// Get the value of CR3 register
	TEMU_read_register(cr3_reg, &cr3);
	// Get the value of ESP register
	TEMU_read_register(esp_reg, &esp);

	// Get the current process using the above registers
	tmodinfo_t * mi = locate_module(eip, cr3, current_proc);
	// Get the current working module inside the current process
	strcpy(current_mod, mi ? mi->name : "<unknown>");

	if (0x00 == strcasecmp(current_mod, monitored_proc)) {
		// Save the base address
		checked_module_base = mi->base;
		// Save the size
		checked_module_size = mi->size;

		// We are inside the monitored module
		in_checked_module = LOC_INSIDE;
		goto _handle;
	}

	uint32_t phys_addr = TEMU_get_phys_addr(eip);

	// Check what ?
	taint_record_t records[0x04];
	uint64_t taint = taintcheck_memory_check(phys_addr, 1, (uint8_t *) records);

	if (taint) {
		// This may be generated code
		in_checked_module = LOC_GEN;
		// Log
		fprintf( loghandle,
				 "Tainted code: %s!%s eip=%08x\n",
				 current_proc,
                 mi ? mi->name: "<unknown>",
				 eip);

		goto _handle;
    }

	// Get the id of the current thread
	current_thread_id = get_current_tid();
	// Get the information about the current thread
	current_thread_node = (current_thread_id != -1UL) ? get_thread_info(current_thread_id) : NULL;

	// In system call
	if (current_thread_node) {
		if (current_thread_node->origin == 1 || current_thread_node->origin == 2) {
			// Jump out of malicious code
			if (((current_thread_node->esp & 0x80000000) == (esp & 0x80000000)) &&
				(current_thread_node->esp < esp))
			{
				// Return from malware
				delete_thread_info(current_thread_id);
				current_thread_node = NULL;
        		goto _finished;
			}

			if (((current_thread_node->esp & 0x80000000) == (esp & 0x80000000))	&&
				(current_thread_node->esp > esp))
			{
				// External call - set the caller
				current_thread_node->entry_eip = eip;
				// Follow the Hookfinder style
        		current_thread_node->origin = 3;

				goto _finished;
      		}
    	}
  	}

	// Skip the rest
	goto _finished;

_handle:
	// This is not the monitored process
  	if(current_thread_id == -1UL) {
		goto _finished;
	}

	// Set the current thread info
	if (! current_thread_node) {
		thread_info_t info;
		// Zero-out
		bzero( &info, sizeof(info) );
		// Set its members
		info.cr3 = cr3;
		info.esp = esp;
		// Why set its value to 0 ?
		info.eip = 0x00;
		info.origin = (uint32_t)in_checked_module;
		// Save the thread info
		write_thread_info(current_thread_id, &info);
		// and refer to the newly updated current thread
		current_thread_node = get_thread_info(current_thread_id);
  	}

	current_thread_node->eip = 0;
	current_thread_node->out_eip = 0;
	current_thread_node->entry_eip = 0;
	current_thread_node->origin = (uint32_t)in_checked_module;

_finished:
	//we should always check if there is a hook at this point,
	//no matter we are in the monitored context or not, because
	//some hooks are global.
	hookapi_check_call(should_monitor);
	// Thread ?
	in_checked_module = current_thread_node ? (enum location_t)current_thread_node->origin : LOC_NOWHERE;

	// Done
	return 0;
}

//! This callback is invoked for every instruction
static void detector_insn_begin()
{
	// if this is not the process we want to monitor, return immediately
	if (in_checked_module == LOC_NOWHERE) return;

	// Now we can analyze this instruction.  In Hookfinder, they save the
	// address of the next to last instruction
	uint32_t static eip;
	// Save the previous instruction
	last_eip = eip;
	// and get the next one
	TEMU_read_register(eip_reg, &eip);
}

//! Cleanup
void detector_cleanup()
{
	// Clean up everything we create
	procmod_cleanup();
	hookapi_cleanup();
	function_map_cleanup();
	// What's about the XED structure

	// Close the log file
	fclose(loghandle);
	// Reload ?
	loghandle = NULL;
}

//! Standard callback function - Initialize the plugin interface
plugin_interface_t * init_plugin()
{
	// Fail to create the plugin log
	if (!(loghandle = fopen(logfile, "w"))) {
		fprintf(stderr, "cannot create %s\n", logfile);
		return NULL;
	}

	// Init the function map, Don't really know its role
	// Check the definition in shared/hooks/function_map
	function_map_init();
	// Same as above, Don't know nothing about it
	// Check the definition in shared/hookapi
	init_hookapi();
	// Check the definition in shared/procmod
	procmod_init();
	// Check the definition in shared/reduce_taint.  There
	// is no documentation.  The f**k.
	reduce_taint_init();


	// XED2 is a X86 Encoder / Decoder.  My guess is that
	// TEMU use this tool to translate instruction from
	// assembly to machine language.
	// Check the following link for XED2 documentation
	// www.cs.virginia.edu/kim/publicity/pin/docs/24110/Xed/html/main.html
	// Init XED instruction table
	xed_tables_init();
	// Zero-out the structure ?
	xed_state_zero( &xed_state );
	// Update the XED2 structure with some pre-defined values
	xed_state_init( &xed_state, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b);


	// The following portion of code registers all the
	// call-back functions.  Check the file TEMU_main.h
	// for the full list of these functions.
	// These functions are user-defined functions which
	// we will play with

	// Cleanup
	interface.plugin_cleanup	= detector_cleanup;
	// How the taint analysis works
	interface.taint_record_size	= sizeof(taint_record_t);
	interface.taint_propagate	= detector_taint_propagate;
	// Copy from sample plugin & hookfinder
	interface.guest_message		= detector_guest_message;
	// Beginning of a block, used to indentify process
	interface.block_begin		= detector_block_begin;
	// Beginning of an instruction
	interface.insn_begin		= detector_insn_begin;
	// These twos are for user-interface
	interface.term_cmds			= detector_term_cmds;
	interface.info_cmds			= detector_info_cmds;
	// Send a tainted keystroke
	interface.send_keystroke	= detector_send_keystroke;
	// What to do with network I/O, we don't need this yet
	// my_interface.nic_recv	= detector_nic_recv;
	// my_interface.nic_send	= detector_nic_send;
	// Need this to get the value of CR3 register
	interface.monitored_cr3		= 0;

	// We have TEMU interface now
	return & interface;
}


