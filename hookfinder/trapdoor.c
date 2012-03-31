#include "vl.h"
#include "../shared/hookapi.h"
#include "../shared/procmod.h"
#include "taintcheck.h"

static void run_monitor_cmd(const char *cmd, int len)
{
    char *param1, *param2, *param3;
    if(!strcmp(cmd, "taint_file")) {
        param1 = cmd+11;
        param2 = param1+strlen(param1)+1;
        param3 = param2+strlen(param2)+1;
		term_printf("taint_file %s %s %s\n", param1, param2, param3);        
		do_taint_file(param1, atoi(param2), atoi(param3));
		return;
    }
    
    if(!strcmp(cmd, "usb_add")) {
        param1 = cmd+8;
	term_printf("usb_add %s \n", param1);        
	do_usb_add(param1);
	return;
    }

    if(!strcmp(cmd, "usb_del")) {
        param1 = cmd+8;
	term_printf("usb_del %s \n", param1);        
	do_usb_del(param1);
	return;
    }
    if(!strcmp(cmd, "loadvm")) {
        param1 = cmd+7;
	term_printf("loadvm %s \n", param1);        
	do_loadvm(param1);
	return;
    }
    if(!strcmp(cmd, "stop_unpack")) {
	term_printf("stop_unpack\n");        
	do_stop_unpack(param1);
	return;
    }

/*    if(!strcmp(cmd, "taint_sendkey")) {
        param1 = cmd+14;
        param2 = param1+strlen(param1)+1;
        term_printf("taint_sendkey %s %s \n", param1, param2);
        do_taint_sendkey(param1, atoi(param2));
        return;
    }
    if(!strcmp(cmd, "taint_nic")) {
        param1 = cmd+10;
		term_printf("taint_nic %s\n", param1);
		do_taint_nic(atoi(param1));
   		return;
   } */
}

static int RegSetValueExA_call(void *opaque)
{
	char proc[32];
	uint32_t buf[7], pid;
	char cmd[255];

	if(!taintcheck_running) return 0;

	find_process(cpu_single_env->cr[3], proc, &pid);
	if(strcasecmp(proc, "AutoHotkey.exe") && 
		strcasecmp(proc, "python.exe") ) return 0;

	if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_ESP], buf, 28, 0) < 0)
		return 0;

//	term_printf("RegSetValueExA [%s] %x:%x:%x \n", proc, buf[1], buf[5], buf[6]);
	if(!buf[5] || !buf[6]) return 0;

    bzero(cmd, 256);

	if(cpu_memory_rw_debug(cpu_single_env, buf[5], cmd, buf[6], 0) < 0) return;
	term_printf("RegSetValueExA [%s] %s \n", proc, cmd);
	run_monitor_cmd(cmd, buf[6]);
	return 0;
}

void trapdoor_init()
{
	register_hookapi(0x77ddebe7, RegSetValueExA_call, NULL);
}

