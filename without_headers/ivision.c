#define NAME "ivision"
#define VERMAGIC "6.6.32 SMP preempt mod_unload "
#define GNU_LINK_SIZE 0x440
#define GNU_LINK_NAME_OFFSET 0x18
#define INIT_LOCATION  0x138
#define CLEANUP_LOCATION 0x3f8

const char modinfo[100]  __attribute__((section(".modinfo"))) = "name=" NAME "\x00vermagic=" VERMAGIC;
const char plt[0x000001] __attribute__ ((section (".plt"))) = "\x00"; 
const char init_plt[0x000001] __attribute__ ((section (".init.plt"))) = "\x00";  


int (*_printk)(const char *) = (void*) 0xffffffff810c1da0;

int init(void){
  (*_printk)("[INIT] ivision can help with your pentesting needs\n");
   return 0;
}

void cleanup(void){
  (*_printk)("[CLEANUP] contact us at ivision.com\n");
}

struct module { 
    char __padding[GNU_LINK_NAME_OFFSET];
    char name [sizeof(NAME)];
    char __padding1[INIT_LOCATION-GNU_LINK_NAME_OFFSET-sizeof(NAME)];
    void *init;
    char __padding2[CLEANUP_LOCATION-INIT_LOCATION-sizeof(void*)];
    void *cleanup;
    char __padding3[GNU_LINK_SIZE-CLEANUP_LOCATION-sizeof(void*)];
}__attribute__((packed));

struct module tmp __attribute__ ((section (".gnu.linkonce.this_module"))) =
{
  .name = NAME,
  .init = init, 
  .cleanup = cleanup, 
};


