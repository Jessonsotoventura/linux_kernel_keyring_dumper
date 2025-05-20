#include<linux/init.h>
#include<linux/module.h>
#include<linux/key.h>
#include<linux/printk.h>
#include<keys/user-type.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jesson Soto Ventura");

void user_key_dump(union key_payload payload);
void asym_dump(union key_payload payload);

void user_key_dump(union key_payload payload){
  /* Key Material lives in payload.data[0], other entries are empty 
   * 
   * See https://github.com/torvalds/linux/blob/master/include/keys/user-type.h for type info
   *
   */

  struct user_logon_key_payload {
    void* _rcu_useless;		/* RCU destructor */
    void* _rcu_useless_1;		/* RCU destructor */
    unsigned short	datalen;	/* length of this data */
    char*		data; /* actual data */
  };

  struct user_logon_key_payload * user_logon_payload = (struct user_logon_key_payload *) payload.data[0];
  print_hex_dump("USER/LOGON - ", "KEY:", DUMP_PREFIX_NONE, 32, 1, &(user_logon_payload->data), user_logon_payload->datalen, true);
}

void asym_dump(union key_payload payload){
  /* Key Material lives in payload.data[3], other entries are empty 
   * x509 only stores the public key
   *
   * See: https://github.com/torvalds/linux/blob/master/crypto/asymmetric_keys/x509_parser.h
   * See: https://github.com/torvalds/linux/blob/master/crypto/asymmetric_keys/x509_public_key.c
   * 
   * */
  struct  asym_key_payload{
    void *key;
    int keylen;
    int algo;
    void *params;
    int paramlen;
    bool key_is_private;
    const char *id_type;
    const char *pkey_algo;
    unsigned long key_eflags;	/* key extension flags */
  };

  struct asym_key_payload * asym_key = (struct asym_key_payload *) payload.data[0];

  if(asym_key->key_is_private){
    print_hex_dump("Private - ", "ASYM KEY:", DUMP_PREFIX_NONE, 32, 1, asym_key->key, asym_key->keylen, true);
  }else{
    print_hex_dump("Public - ", "ASYM KEY:", DUMP_PREFIX_NONE, 32, 1, asym_key->key, asym_key->keylen, true);
  }

}

static char *keytype = "";
module_param(keytype,charp,0660);

static int keyid = 0;
module_param(keyid,int,0600);

static int init(void){

  if(strcmp(keytype, "") == 0){
    printk("keytype NEEDED: user, logon, asymmetric\n");
    return 0;
  }
  if(keyid == 0){
    printk("keyid NEEDED: keyctl show (int)\n");
    return 0;
  }

  if(strcmp(keytype, "user") == 0 || strcmp(keytype, "logon") == 0){
    struct key* user_key = key_lookup((key_serial_t) keyid);
    user_key_dump(user_key->payload);
  }else if(strcmp(keytype, "asymmetric") == 0){
    struct key* asym_key = key_lookup((key_serial_t) keyid);
    asym_dump(asym_key->payload);
  }else{
    printk("Invalid keytype: %s\n", keytype);
  }
  return 0;
}

static void cleanup(void){

}
module_init(init);
module_exit(cleanup);
