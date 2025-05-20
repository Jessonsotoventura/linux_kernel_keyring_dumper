#define KERN_SOH	"\001"
#define KERN_DEBUG	KERN_SOH "7"
#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

typedef int	size_t;

enum {
	DUMP_PREFIX_NONE,
	DUMP_PREFIX_ADDRESS,
	DUMP_PREFIX_OFFSET
};

struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));

struct rb_root {
	struct rb_node *rb_node;
};

struct key_type{
  const char* name;
  void * reset_ignored;
};


struct user_key_payload{
  char __padding[16];
  unsigned short datalen;
  char __padding_2[6];
  char data[64]; 
};


struct public_key {
	void *key;
	int keylen;
	int algo;
	void *params;
	int paramlen;
	int key_is_private;
	const char *id_type;
	const char *pkey_algo;
	unsigned long key_eflags;	/* key extension flags */
};

union key_payload {
	void      *rcu_data0;
	void			*data[4];
};

struct key {
  unsigned int usage;
  unsigned int serial;
  struct rb_node serial_node;
  char __padding[120];
  struct key_type *type;
  void* domain_tag;
  char* description;

	union key_payload payload;
};

extern int _strcmp(char*, char*);
extern int _printk(const char *, ...);
extern int print_hex_dump(const char *, const char *, int, int,int, void*, int, int);
extern struct rb_node* rb_next(struct rb_node*);
extern struct rb_node* rb_prev(struct rb_node*);

void print_key_data(struct key* key);
void print_user_key_data(struct key* key);
void print_asym_key_data(struct key* key);

int strcmp(const char *cs, const char *ct)
{
	unsigned char c1, c2;

	while (1) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
	}
	return 0;
}
