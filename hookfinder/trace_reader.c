typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include "tracing.h"
#include "xed-interface.h"

xed_state_t g_xState;

void print_trace_record(trace_record_t *rec)
{
  xed_decoded_inst_t xDecode;
  char asm_buf[32];
  int i;
  if(rec->is_new) {
	printf("NEW eip=%08x esp=%08x caller=%08x callee=%08x M[%08x]=%08x \n", 
		rec->eip, rec->esp, rec->caller, rec->callee, rec->mem_addr, 
		rec->mem_val);
	printf("    id=%08x", rec->define.dst_id[0]);

    for(i=1; rec->define.dst_id[i] && i<4; i++) 
	  printf(", %08x", rec->define.dst_id[i]);
	printf("\n");
  }
  else {
	printf("OLD eip=%08x esp=%08x caller=%08x callee=%08x is_move=%d\n", 
		rec->eip, rec->esp, rec->caller, rec->callee, rec->prop.is_move);
	if(rec->mem_addr) 
	  printf("    M[%08x]=%08x\n", rec->mem_addr, rec->mem_val);
	
	printf("    src_id=%08x", rec->prop.src_id[0]);
	for(i=1; rec->prop.src_id[i] !=0 && i<12; i++)
	  printf(", %08x", rec->prop.src_id[i]);
	printf("\n");

	printf("    dst_id=%08x", rec->prop.dst_id[0]);
	for(i=1; rec->prop.dst_id[i] !=0 && i<4; i++)
	  printf(", %08x", rec->prop.dst_id[i]);
	printf("\n");
  }

  if(rec->address_id) 
    printf("    address_id=%08x\n", rec->address_id);

/*  printf("    raw_insn: ");
  for(i=0; i<16; i++) 
	printf("%02x ", (uint8_t)rec->raw_insn[i]); */
  xed_decoded_inst_zero_set_mode(&xDecode, &g_xState);
  xed_error_enum_t xed_error = xed_decode(&xDecode, rec->raw_insn, 16);
  if(xed_error == XED_ERROR_NONE) {
    xed_format_intel(&xDecode, asm_buf, sizeof(asm_buf), rec->eip);
    printf("%s\n", asm_buf);
  }
}

void print_all_records(FILE *fp)
{
  trace_record_t rec;
  while(!feof(fp)){
    size_t ret = fread(&rec, sizeof(trace_record_t), 1, fp);
    if(ret != 1)
      break;
    print_trace_record(&rec);  
  }
}

void trace_back(FILE *fp, uint32_t id) 
{
  trace_record_t rec;
  int found=0, res, i;
  size_t ret;
  uint32_t src_id=0;
  while(!feof(fp)) {
	ret = fread(&rec, sizeof(trace_record_t), 1, fp);
	if(ret != 1)
	  break;
	for(i = 0; i < 4; i++) {
  	  if(rec.prop.dst_id[i] != id) 
  	    continue;
      found = 1;
	  src_id = rec.prop.src_id[0];
	  print_trace_record(&rec);
	  break;
    }
  }
  if(found == 0) {
	printf("not found!\n");
	return;
  }
  
  while (1) {
	res = fseek(fp, 0-2*sizeof(trace_record_t), SEEK_CUR);
	if(res < 0) break;
	ret = fread(&rec, sizeof(trace_record_t), 1, fp);
    if(ret != 1)
      break;
    for (i=0; i<4; i++) {
      if(!rec.is_new && rec.prop.dst_id[i] == src_id){
	    print_trace_record(&rec);
	    src_id = rec.prop.src_id[0];
	    break;
	  } else if(rec.is_new && rec.define.dst_id[i] == src_id) {
	    print_trace_record(&rec);
	    src_id = 0;
	    break;
	  }
	}
	if(src_id == 0) break;
  }
}

int main(int argn, char **argv)
{
  uint32_t depend_id = 0;
  char *tail;
  static struct option long_options[] = {
	{"depend_id", 1, 0, 'd'},
	{0, 0, 0, 0}
  };

  xed_tables_init();

  // The state of the machine -- required for decoding
  xed_state_t dstate;
  xed_state_zero(&dstate);
  xed_state_init(&dstate,
                 XED_MACHINE_MODE_LEGACY_32, 
                 XED_ADDRESS_WIDTH_32b, 
                 XED_ADDRESS_WIDTH_32b);



  while (1) {
    int option_index = 0;
    int c = getopt_long(argn, argv, "d:", long_options, 
    	  &option_index);
	if (c == -1) break;

	switch (c) 
	{
	  case 0: 
		if (long_options[option_index].flag != 0)
		  break;
		printf ("option %s", long_options[option_index].name);
		if (optarg) 
		  printf(" with arg %s", optarg);
		printf("\n");
		break;
	  case 'd': 
		depend_id = strtol(optarg, &tail, 0);
		break;

	  default:
		abort();
	}
  }

  //trace_record_t rec;
  if(optind >= argn) {
    printf("usage: %s [-d id] trace_file\n", argv[0]);
    return -1;
  }
  
  FILE *fp = fopen(argv[optind++],"r");
  if(!fp) {
    printf("cannnot open %s! errno=%d\n", argv[optind-1], errno);
    return -1;
  }

  if(depend_id == 0)
	print_all_records(fp);
  else
	trace_back(fp, depend_id);
  
  fclose(fp);
  return 0;
}
