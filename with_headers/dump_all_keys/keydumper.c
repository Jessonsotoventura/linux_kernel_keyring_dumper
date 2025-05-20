#include <linux/module.h>	
#include <linux/kernel.h>	
#include <linux/key.h>
#include <linux/string.h>
#include <linux/key-type.h>
#include <linux/rbtree.h>
#include <keys/user-type.h>
#include <crypto/public_key.h>  
#include <keys/asymmetric-subtype.h>
MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("Jesson Soto Ventura"); 
MODULE_DESCRIPTION("Dumps Keys From Linux Kernel Module"); 
MODULE_VERSION("1.0"); 

static int user_key = 605228736;
module_param(user_key,int,S_IRUGO); 
MODULE_PARM_DESC(user_key, "Existing Key in LLKRS"); 

//extern struct rb_root key_serial_tree;

void print_key_data(struct key* key);
void print_user_key_data(struct key* key);
void print_asym_key_data(struct key* key);

void print_key_data(struct key* key){
	printk("[Key - %s]: %s\n", key->description, key->type->name);	
	if(!strcmp(key->type->name, key_type_user.name) || !strcmp(key->type->name, key_type_logon.name)){
		print_user_key_data(key);
	}else if(!strcmp(key->type->name,key_type_asymmetric.name)){
		print_asym_key_data(key);	
	}	

}

void print_user_key_data(struct key* key){

	typedef struct user_key_payload {
		struct rcu_head	rcu;		/* RCU destructor */
		unsigned short	datalen;	/* length of this data */
		char		data[] __aligned(__alignof__(u64)); /* actual data */
	} user_key_payload;

	user_key_payload * key_data = (user_key_payload*) key->payload.data[0];
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

void dump_user_logon_keys(void){
	struct key *user_k = key_lookup(user_key);

	//walk tree to a root
	struct rb_node *root = &(user_k->serial_node);
	while (rb_parent(root) != NULL){
		root = rb_parent(root);
	}

	struct rb_node *node;
	for (node = root; node; node = rb_prev(node)){
		struct key* key = rb_entry(node, struct key, serial_node);
		print_key_data(key);
	}

	if (rb_next(root) != NULL){
		for (node = root; node; node = rb_next(node)){
			struct key* key = rb_entry(node, struct key, serial_node);
			print_key_data(key);
		}
	}

}

int init_module(void)
{
	
	dump_user_logon_keys();
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Goodbye world 1.\n");
}
