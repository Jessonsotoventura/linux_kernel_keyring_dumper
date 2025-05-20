import argparse
from elftools.elf.elffile import ELFFile


def get_vermagic(module):
    """
        Vermagic is a magic string that the kernel validates matches its own vermagic. This value indicates that the kernel module was built to support the current running kernel.
        Should be part of .modinfo section.
        Could also be retrieved using:
            readelf *.ko -j .modinfo
            strings *.ko | grep vermagic

            Keep in mind the vermagic should likely have a space and \x00 at the end
    """
    modinfo = module.get_section_by_name(".modinfo")
    values = modinfo.data().split(b"\x00")
    for section in values:
        if (b"vermagic=") in section:
            return section

def get_linkonce_size(module):
    """
        The section size of ".gnu.linkonce.this_module" must match the size expected by the kernel.

        readelf -S amd-rng.ko -W | grep linkonce_this

          [Nr] Name                      Type            Address          Off    Size   ES Flg Lk Inf Al
          ...
          [26] .gnu.linkonce.this_module PROGBITS        0000000000000000 000900 000440 00  WA  0   0 64

          Size is 0x440
    """
    return module.get_section_by_name(".gnu.linkonce.this_module").data_size

def get_linkonce_name_offset(module):
    section = module.get_section_by_name(".gnu.linkonce.this_module").data()
    count = 0
    for c in section:
        if (c == 0):
            count += 1
        else:
            return count

def get_init_cleanup_relocations(module):
    """
        Determine where init_module and cleanup_module references should be stored. 
        There should only be 2 refernces:
        init_modules, cleanup_module in that order 

    """
    if (module.get_section_by_name('.rel.gnu.linkonce.this_module')):
        refs = list(module.get_section_by_name('.rel.gnu.linkonce.this_module').iter_relocations())
    else:
        refs = list(module.get_section_by_name('.rela.gnu.linkonce.this_module').iter_relocations())
    init_module_offset = refs[0]['r_offset']
    cleanup_module_offset = refs[1]['r_offset']
    return (init_module_offset, cleanup_module_offset)


def get_module_name(module):
    """
        Determine the module name so we can calculate the correct offsets
        These two should match:
        readelf *.ko -j .modinfo
            name=*SOMENAME*

        readelf *.ko -j .gnu.linkonce.this_module | strings
            *SOMENAME*
    """
    
    modinfo = module.get_section_by_name(".modinfo")
    values = modinfo.data().split(b"\x00")
    for section in values:
        if (b"name=") in section:
            return section.split(b"=")[1]


def main():
    parser = argparse.ArgumentParser(description="Extracts key values from a Linux kernel module (.ko) file to enable creation of standalone Linux kernel modules")
    parser.add_argument('kernel', help='Exising Kernel Module')
    parser.add_argument('output', help='output for c file')
    parser.add_argument('name', help='New of the new module\'s name')

    args = parser.parse_args()
    print(vars(args))
    module = ELFFile(open(args.kernel, "rb"))

    old_name = get_module_name(module)
    if (old_name):
        print("[Module Name]: %s" %(old_name.decode()))

    vermagic = get_vermagic(module)
    print("[Vermagic]: %s" %(vermagic.decode()))

    gnu_link_size = get_linkonce_size(module)
    print("[.gnu.linkonce.this_module Size]: %d" %(gnu_link_size))

    name_offset  = get_linkonce_name_offset(module)
    print("[Module Name Offset]: %d" %(name_offset))
    
    init_offset, clean_offset = get_init_cleanup_relocations(module)
    print("[Init Module Relocation Offset]: %d" %(init_offset))
    print("[Cleanup Module Relocation Offset]: %d" %(clean_offset))


    with open(args.output, "wb") as output:
        output.write(gen_c_file(args.name,vermagic.decode(), gnu_link_size, name_offset, init_offset, clean_offset).encode())



def gen_c_file(name,vermagic,gnu_link_size,link_name_offset,init,cleanup):
    template = """#define NAME "%s"
#define VERMAGIC "%s"
#define GNU_LINK_SIZE %d 
#define GNU_LINK_NAME_OFFSET %d 
#define INIT_LOCATION %d 
#define CLEANUP_LOCATION %d

// Build using $ gcc -c kernel.c -o kernel.ko
// Load with insmod kernel.ko 

// Needed For ARM support. Not used by x86. Never seen the values contain anything
char modinfo[100]  __attribute__((section(".modinfo"))) = "name=" NAME "\x00" VERMAGIC;

int init(void){
    return 0;
}

void cleanup(void){
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
    """
    return template % (name,vermagic,gnu_link_size,link_name_offset,init,cleanup)

main()

