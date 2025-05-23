// Build using $ gcc -c kernel.c -o kernel.ko
// Make sure to set user_key to an existing key value (keyctl show)
// Make sure to set *key_lookup using cat /proc/kallsyms| grep key_lookup
// Load with insmod kernel.ko 

#define NAME "all_key_dumper"
#define VERMAGIC "vermagic=6.6.32 SMP preempt mod_unload "
#define GNU_LINK_SIZE 1088 
#define GNU_LINK_NAME_OFFSET 24 
#define INIT_LOCATION 312 
#define CLEANUP_LOCATION 1016

static int user_key = 946511309; //HARDCODED KEY GOES HERE;
struct key* (*key_lookup)(unsigned long keyID) = (void*) 0xffffffff812a6cb0;;

#include "all_key_dumper.h"

// Needed For ARM support. Not used by x86. Never seen the values contain anything
char modinfo[100]  __attribute__((section(".modinfo"))) = "name=" NAME " " VERMAGIC;

void print_key_data(struct key* key){

	_printk("[Key - %s]: %s,\n", key->description, key->type->name);	
	if(!strcmp(key->type->name, "user") || !strcmp(key->type->name, "logon")){
		print_user_key_data(key);
	}else if(!strcmp(key->type->name,"asymmetric")){
		print_asym_key_data(key);	
	}	

}

void print_user_key_data(struct key* key){
	struct user_key_payload * key_data = (struct user_key_payload*) key->payload.data[0];
	print_hex_dump(KERN_DEBUG, "\t[Payload]: ", DUMP_PREFIX_NONE, 16, 1, key_data->data, key_data->datalen,1);

}

void print_asym_key_data(struct key* key){
	struct public_key * key_data = (struct public_key *) key->payload.data[0];
	if (key_data->key_is_private){	
		print_hex_dump(KERN_DEBUG, "\t[Payload - Private Key]: ", DUMP_PREFIX_NONE, 16, 1, key_data->key, key_data->keylen,1);
	}else{	
		print_hex_dump(KERN_DEBUG, "\t[Payload - Public Key]: ", DUMP_PREFIX_NONE, 16, 1, key_data->key, key_data->keylen,1);
	}
}


void dump_keys(void){
	struct key *user_k = key_lookup(user_key);
	//walk tree to a root
	struct rb_node *root = &(user_k->serial_node);
	while (rb_parent(root) != 0){
		root = rb_parent(root);
	}

	struct rb_node *node;
	for (node = root; node; node = rb_prev(node)){
		struct key* key = rb_entry(node, struct key, serial_node);
		print_key_data(key);
	}
 
	if (rb_next(root) != 0){
		for (node = root; node; node = rb_next(node)){
			struct key* key = rb_entry(node, struct key, serial_node);

			print_key_data(key);
		}
	}

}


int init(void){
	 dump_keys();
    return 0;
}

void cleanup(void){
  _printk("Made by Jesson Soto Ventura @ sotoventura.com");
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

struct module gnu_export __attribute__ ((section (".gnu.linkonce.this_module"))) =
{
  .name = NAME,
  .init = init,
  .cleanup = cleanup,
};
    
