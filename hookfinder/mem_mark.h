int mem_mark_init(uint32_t record_size);
int set_mem_mark(uint32_t vaddr, uint32_t size, uint64_t mark_bitmap, uint8_t *records);
uint64_t check_mem_mark(uint32_t vaddr, uint32_t size, uint8_t *records);
