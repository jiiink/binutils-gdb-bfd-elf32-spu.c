/* SPU specific support for 32-bit ELF

   Copyright (C) 2006-2025 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#include "sysdep.h"
#include "libiberty.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/spu.h"
#include "elf32-spu.h"

/* All users of this file have bfd_octets_per_byte (abfd, sec) == 1.  */
#define OCTETS_PER_BYTE(ABFD, SEC) 1

/* We use RELA style relocs.  Don't define USE_REL.  */

static bfd_reloc_status_type spu_elf_rel9 (bfd *, arelent *, asymbol *,
					   void *, asection *,
					   bfd *, char **);

/* Values of type 'enum elf_spu_reloc_type' are used to index this
   array, so it must be declared in the order of that type.  */

static reloc_howto_type elf_howto_table[] = {
  HOWTO (R_SPU_NONE,	   0, 0,  0, false,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_NONE",
	 false, 0, 0x00000000, false),
  HOWTO (R_SPU_ADDR10,	   4, 4, 10, false, 14, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR10",
	 false, 0, 0x00ffc000, false),
  HOWTO (R_SPU_ADDR16,	   2, 4, 16, false,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR16",
	 false, 0, 0x007fff80, false),
  HOWTO (R_SPU_ADDR16_HI, 16, 4, 16, false,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR16_HI",
	 false, 0, 0x007fff80, false),
  HOWTO (R_SPU_ADDR16_LO,  0, 4, 16, false,  7, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_ADDR16_LO",
	 false, 0, 0x007fff80, false),
  HOWTO (R_SPU_ADDR18,	   0, 4, 18, false,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR18",
	 false, 0, 0x01ffff80, false),
  HOWTO (R_SPU_ADDR32,	   0, 4, 32, false,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_ADDR32",
	 false, 0, 0xffffffff, false),
  HOWTO (R_SPU_REL16,	   2, 4, 16,  true,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_REL16",
	 false, 0, 0x007fff80, true),
  HOWTO (R_SPU_ADDR7,	   0, 4,  7, false, 14, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_ADDR7",
	 false, 0, 0x001fc000, false),
  HOWTO (R_SPU_REL9,	   2, 4,  9,  true,  0, complain_overflow_signed,
	 spu_elf_rel9,		"SPU_REL9",
	 false, 0, 0x0180007f, true),
  HOWTO (R_SPU_REL9I,	   2, 4,  9,  true,  0, complain_overflow_signed,
	 spu_elf_rel9,		"SPU_REL9I",
	 false, 0, 0x0000c07f, true),
  HOWTO (R_SPU_ADDR10I,	   0, 4, 10, false, 14, complain_overflow_signed,
	 bfd_elf_generic_reloc, "SPU_ADDR10I",
	 false, 0, 0x00ffc000, false),
  HOWTO (R_SPU_ADDR16I,	   0, 4, 16, false,  7, complain_overflow_signed,
	 bfd_elf_generic_reloc, "SPU_ADDR16I",
	 false, 0, 0x007fff80, false),
  HOWTO (R_SPU_REL32,	   0, 4, 32, true,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_REL32",
	 false, 0, 0xffffffff, true),
  HOWTO (R_SPU_ADDR16X,	   0, 4, 16, false,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR16X",
	 false, 0, 0x007fff80, false),
  HOWTO (R_SPU_PPU32,	   0, 4, 32, false,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_PPU32",
	 false, 0, 0xffffffff, false),
  HOWTO (R_SPU_PPU64,	   0, 8, 64, false,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_PPU64",
	 false, 0, -1, false),
  HOWTO (R_SPU_ADD_PIC,	   0, 0,  0, false,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_ADD_PIC",
	 false, 0, 0x00000000, false),
};

static struct bfd_elf_special_section const spu_elf_special_sections[] = {
  { "._ea", 4, 0, SHT_PROGBITS, SHF_WRITE },
  { ".toe", 4, 0, SHT_NOBITS, SHF_ALLOC },
  { NULL, 0, 0, 0, 0 }
};

static enum elf_spu_reloc_type
spu_elf_bfd_to_reloc_type (bfd_reloc_code_real_type code)
{
  static const struct {
    bfd_reloc_code_real_type bfd_code;
    enum elf_spu_reloc_type spu_type;
  } reloc_map[] = {
    { BFD_RELOC_NONE,         R_SPU_NONE },
    { BFD_RELOC_SPU_IMM10W,   R_SPU_ADDR10 },
    { BFD_RELOC_SPU_IMM16W,   R_SPU_ADDR16 },
    { BFD_RELOC_SPU_LO16,     R_SPU_ADDR16_LO },
    { BFD_RELOC_SPU_HI16,     R_SPU_ADDR16_HI },
    { BFD_RELOC_SPU_IMM18,    R_SPU_ADDR18 },
    { BFD_RELOC_SPU_PCREL16,  R_SPU_REL16 },
    { BFD_RELOC_SPU_IMM7,     R_SPU_ADDR7 },
    { BFD_RELOC_SPU_IMM8,     R_SPU_NONE },
    { BFD_RELOC_SPU_PCREL9a,  R_SPU_REL9 },
    { BFD_RELOC_SPU_PCREL9b,  R_SPU_REL9I },
    { BFD_RELOC_SPU_IMM10,    R_SPU_ADDR10I },
    { BFD_RELOC_SPU_IMM16,    R_SPU_ADDR16I },
    { BFD_RELOC_32,           R_SPU_ADDR32 },
    { BFD_RELOC_32_PCREL,     R_SPU_REL32 },
    { BFD_RELOC_SPU_PPU32,    R_SPU_PPU32 },
    { BFD_RELOC_SPU_PPU64,    R_SPU_PPU64 },
    { BFD_RELOC_SPU_ADD_PIC,  R_SPU_ADD_PIC }
  };

  #define INVALID_RELOC_TYPE ((enum elf_spu_reloc_type) -1)
  #define RELOC_MAP_SIZE (sizeof(reloc_map) / sizeof(reloc_map[0]))

  for (size_t i = 0; i < RELOC_MAP_SIZE; i++) {
    if (reloc_map[i].bfd_code == code) {
      return reloc_map[i].spu_type;
    }
  }

  return INVALID_RELOC_TYPE;
}

static bool
spu_elf_info_to_howto (bfd *abfd,
		       arelent *cache_ptr,
		       Elf_Internal_Rela *dst)
{
  enum elf_spu_reloc_type r_type;

  r_type = (enum elf_spu_reloc_type) ELF32_R_TYPE (dst->r_info);
  if (r_type >= R_SPU_max)
    {
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }
  cache_ptr->howto = &elf_howto_table[(int) r_type];
  return true;
}

static reloc_howto_type *
spu_elf_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			   bfd_reloc_code_real_type code)
{
  enum elf_spu_reloc_type r_type = spu_elf_bfd_to_reloc_type (code);

  if (r_type == (enum elf_spu_reloc_type) -1)
    return NULL;

  return elf_howto_table + r_type;
}

static reloc_howto_type *
spu_elf_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			   const char *r_name)
{
  const size_t table_size = sizeof (elf_howto_table) / sizeof (elf_howto_table[0]);
  
  for (size_t i = 0; i < table_size; i++)
    {
      if (elf_howto_table[i].name != NULL
          && strcasecmp (elf_howto_table[i].name, r_name) == 0)
        return &elf_howto_table[i];
    }

  return NULL;
}

/* Apply R_SPU_REL9 and R_SPU_REL9I relocs.  */

static bfd_vma
get_symbol_value(asymbol *symbol)
{
  bfd_vma val = 0;
  
  if (!bfd_is_com_section(symbol->section))
    val = symbol->value;
    
  if (symbol->section->output_section)
    val += symbol->section->output_section->vma;
    
  return val;
}

static bfd_vma
calculate_pc_relative_offset(bfd_vma val, asection *input_section)
{
  return val - input_section->output_section->vma - input_section->output_offset;
}

static bfd_vma
encode_rel9_value(bfd_vma val)
{
  #define REL9_LOW_MASK 0x7f
  #define REL9_HIGH_MASK 0x180
  #define REL9I_SHIFT 7
  #define REL9_SHIFT 16
  
  return (val & REL9_LOW_MASK) | 
         ((val & REL9_HIGH_MASK) << REL9I_SHIFT) | 
         ((val & REL9_HIGH_MASK) << REL9_SHIFT);
}

static void
update_instruction(bfd *abfd, void *data, bfd_size_type octets, 
                  bfd_vma val, arelent *reloc_entry)
{
  long insn = bfd_get_32(abfd, (bfd_byte *)data + octets);
  insn &= ~reloc_entry->howto->dst_mask;
  insn |= val & reloc_entry->howto->dst_mask;
  bfd_put_32(abfd, insn, (bfd_byte *)data + octets);
}

static bfd_reloc_status_type
spu_elf_rel9(bfd *abfd, arelent *reloc_entry, asymbol *symbol,
            void *data, asection *input_section,
            bfd *output_bfd, char **error_message)
{
  #define REL9_OFFSET_SHIFT 2
  #define REL9_MIN_OFFSET -256
  #define REL9_MAX_OFFSET 255
  
  if (output_bfd != NULL)
    return bfd_elf_generic_reloc(abfd, reloc_entry, symbol, data,
                                 input_section, output_bfd, error_message);

  if (reloc_entry->address > bfd_get_section_limit(abfd, input_section))
    return bfd_reloc_outofrange;
    
  bfd_size_type octets = reloc_entry->address * OCTETS_PER_BYTE(abfd, input_section);
  
  bfd_vma val = get_symbol_value(symbol);
  val += reloc_entry->addend;
  val = calculate_pc_relative_offset(val, input_section);
  val >>= REL9_OFFSET_SHIFT;
  
  if (val < REL9_MIN_OFFSET || val > REL9_MAX_OFFSET)
    return bfd_reloc_overflow;
  
  val = encode_rel9_value(val);
  update_instruction(abfd, data, octets, val, reloc_entry);
  
  return bfd_reloc_ok;
}

static bool
spu_elf_new_section_hook (bfd *abfd, asection *sec)
{
  struct _spu_elf_section_data *sdata;

  sdata = bfd_zalloc (abfd, sizeof (*sdata));
  if (sdata == NULL)
    return false;
  sec->used_by_bfd = sdata;

  return _bfd_elf_new_section_hook (abfd, sec);
}

/* Set up overlay info for executables.  */

static bool is_overlay_segment(Elf_Internal_Phdr *phdr)
{
    return phdr->p_type == PT_LOAD && (phdr->p_flags & PF_OVERLAY) != 0;
}

static bool is_new_buffer_needed(Elf_Internal_Phdr *last_phdr, Elf_Internal_Phdr *phdr)
{
    #define ADDRESS_MASK 0x3ffff
    return last_phdr == NULL || ((last_phdr->p_vaddr ^ phdr->p_vaddr) & ADDRESS_MASK) != 0;
}

static bool section_in_overlay(Elf_Internal_Shdr *shdr, Elf_Internal_Phdr *phdr)
{
    return shdr->bfd_section != NULL &&
           ELF_SECTION_SIZE(shdr, phdr) != 0 &&
           ELF_SECTION_IN_SEGMENT(shdr, phdr);
}

static void mark_overlay_section(asection *sec, unsigned int ovl_index, unsigned int ovl_buf)
{
    spu_elf_section_data(sec)->u.o.ovl_index = ovl_index;
    spu_elf_section_data(sec)->u.o.ovl_buf = ovl_buf;
}

static void process_overlay_sections(bfd *abfd, Elf_Internal_Phdr *phdr, 
                                    unsigned int num_ovl, unsigned int num_buf)
{
    unsigned int j;
    for (j = 1; j < elf_numsections(abfd); j++)
    {
        Elf_Internal_Shdr *shdr = elf_elfsections(abfd)[j];
        if (section_in_overlay(shdr, phdr))
        {
            mark_overlay_section(shdr->bfd_section, num_ovl, num_buf);
        }
    }
}

static void process_overlay_segments(bfd *abfd)
{
    unsigned int i, num_ovl = 0, num_buf = 0;
    Elf_Internal_Phdr *phdr = elf_tdata(abfd)->phdr;
    Elf_Internal_Ehdr *ehdr = elf_elfheader(abfd);
    Elf_Internal_Phdr *last_phdr = NULL;

    for (i = 0; i < ehdr->e_phnum; i++, phdr++)
    {
        if (!is_overlay_segment(phdr))
            continue;

        ++num_ovl;
        if (is_new_buffer_needed(last_phdr, phdr))
            ++num_buf;
        
        last_phdr = phdr;
        process_overlay_sections(abfd, phdr, num_ovl, num_buf);
    }
}

static bool spu_elf_object_p(bfd *abfd)
{
    if ((abfd->flags & (EXEC_P | DYNAMIC)) != 0)
    {
        process_overlay_segments(abfd);
    }
    return true;
}

/* Specially mark defined symbols named _EAR_* with BSF_KEEP so that
   strip --strip-unneeded will not remove them.  */

static void
spu_elf_backend_symbol_processing (bfd *abfd ATTRIBUTE_UNUSED, asymbol *sym)
{
  const char *EAR_PREFIX = "_EAR_";
  
  if (sym->name == NULL || sym->section == bfd_abs_section_ptr) {
    return;
  }
  
  if (startswith (sym->name, EAR_PREFIX)) {
    sym->flags |= BSF_KEEP;
  }
}

/* SPU ELF linker hash table.  */

struct spu_link_hash_table
{
  struct elf_link_hash_table elf;

  struct spu_elf_params *params;

  /* Shortcuts to overlay sections.  */
  asection *ovtab;
  asection *init;
  asection *toe;
  asection **ovl_sec;

  /* Count of stubs in each overlay section.  */
  unsigned int *stub_count;

  /* The stub section for each overlay section.  */
  asection **stub_sec;

  struct elf_link_hash_entry *ovly_entry[2];

  /* Number of overlay buffers.  */
  unsigned int num_buf;

  /* Total number of overlays.  */
  unsigned int num_overlays;

  /* For soft icache.  */
  unsigned int line_size_log2;
  unsigned int num_lines_log2;
  unsigned int fromelem_size_log2;

  /* How much memory we have.  */
  unsigned int local_store;

  /* Count of overlay stubs needed in non-overlay area.  */
  unsigned int non_ovly_stub;

  /* Pointer to the fixup section */
  asection *sfixup;

  /* Set on error.  */
  unsigned int stub_err : 1;
};

/* Hijack the generic got fields for overlay stub accounting.  */

struct got_entry
{
  struct got_entry *next;
  unsigned int ovl;
  union {
    bfd_vma addend;
    bfd_vma br_addr;
  };
  bfd_vma stub_addr;
};

#define spu_hash_table(p) \
  ((is_elf_hash_table ((p)->hash)					\
    && elf_hash_table_id (elf_hash_table (p)) == SPU_ELF_DATA)		\
   ? (struct spu_link_hash_table *) (p)->hash : NULL)

struct call_info
{
  struct function_info *fun;
  struct call_info *next;
  unsigned int count;
  unsigned int max_depth;
  unsigned int is_tail : 1;
  unsigned int is_pasted : 1;
  unsigned int broken_cycle : 1;
  unsigned int priority : 13;
};

struct function_info
{
  /* List of functions called.  Also branches to hot/cold part of
     function.  */
  struct call_info *call_list;
  /* For hot/cold part of function, point to owner.  */
  struct function_info *start;
  /* Symbol at start of function.  */
  union {
    Elf_Internal_Sym *sym;
    struct elf_link_hash_entry *h;
  } u;
  /* Function section.  */
  asection *sec;
  asection *rodata;
  /* Where last called from, and number of sections called from.  */
  asection *last_caller;
  unsigned int call_count;
  /* Address range of (this part of) function.  */
  bfd_vma lo, hi;
  /* Offset where we found a store of lr, or -1 if none found.  */
  bfd_vma lr_store;
  /* Offset where we found the stack adjustment insn.  */
  bfd_vma sp_adjust;
  /* Stack usage.  */
  int stack;
  /* Distance from root of call tree.  Tail and hot/cold branches
     count as one deeper.  We aren't counting stack frames here.  */
  unsigned int depth;
  /* Set if global symbol.  */
  unsigned int global : 1;
  /* Set if known to be start of function (as distinct from a hunk
     in hot/cold section.  */
  unsigned int is_func : 1;
  /* Set if not a root node.  */
  unsigned int non_root : 1;
  /* Flags used during call tree traversal.  It's cheaper to replicate
     the visit flags than have one which needs clearing after a traversal.  */
  unsigned int visit1 : 1;
  unsigned int visit2 : 1;
  unsigned int marking : 1;
  unsigned int visit3 : 1;
  unsigned int visit4 : 1;
  unsigned int visit5 : 1;
  unsigned int visit6 : 1;
  unsigned int visit7 : 1;
};

struct spu_elf_stack_info
{
  int num_fun;
  int max_fun;
  /* Variable size array describing functions, one per contiguous
     address range belonging to a function.  */
  struct function_info fun[1];
};

static struct function_info *find_function (asection *, bfd_vma,
					    struct bfd_link_info *);

/* Create a spu ELF linker hash table.  */

static struct bfd_link_hash_table *
spu_elf_link_hash_table_create (bfd *abfd)
{
  struct spu_link_hash_table *htab;

  htab = bfd_zmalloc (sizeof (*htab));
  if (htab == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&htab->elf, abfd,
				      _bfd_elf_link_hash_newfunc,
				      sizeof (struct elf_link_hash_entry)))
    {
      free (htab);
      return NULL;
    }

  htab->elf.init_got_refcount.refcount = 0;
  htab->elf.init_got_refcount.glist = NULL;
  htab->elf.init_got_offset.offset = 0;
  htab->elf.init_got_offset.glist = NULL;
  return &htab->elf.root;
}

void
spu_elf_setup (struct bfd_link_info *info, struct spu_elf_params *params)
{
  const int QUADWORD_SHIFT = 4;
  bfd_vma max_branch_log2;

  struct spu_link_hash_table *htab = spu_hash_table (info);
  htab->params = params;
  htab->line_size_log2 = bfd_log2 (htab->params->line_size);
  htab->num_lines_log2 = bfd_log2 (htab->params->num_lines);

  max_branch_log2 = bfd_log2 (htab->params->max_branch);
  htab->fromelem_size_log2 = max_branch_log2 > QUADWORD_SHIFT ? max_branch_log2 - QUADWORD_SHIFT : 0;
}

/* Find the symbol for the given R_SYMNDX in IBFD and set *HP and *SYMP
   to (hash, NULL) for global symbols, and (NULL, sym) for locals.  Set
   *SYMSECP to the symbol's section.  *LOCSYMSP caches local syms.  */

static struct elf_link_hash_entry *
resolve_indirect_hash(struct elf_link_hash_entry *h)
{
    while (h->root.type == bfd_link_hash_indirect ||
           h->root.type == bfd_link_hash_warning) {
        h = (struct elf_link_hash_entry *) h->root.u.i.link;
    }
    return h;
}

static asection *
get_hash_section(struct elf_link_hash_entry *h)
{
    if (h->root.type == bfd_link_hash_defined ||
        h->root.type == bfd_link_hash_defweak) {
        return h->root.u.def.section;
    }
    return NULL;
}

static Elf_Internal_Sym *
load_local_symbols(bfd *ibfd, Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym **locsymsp)
{
    Elf_Internal_Sym *locsyms = *locsymsp;
    
    if (locsyms != NULL) {
        return locsyms;
    }
    
    locsyms = (Elf_Internal_Sym *) symtab_hdr->contents;
    if (locsyms == NULL) {
        locsyms = bfd_elf_get_elf_syms(ibfd, symtab_hdr,
                                       symtab_hdr->sh_info,
                                       0, NULL, NULL, NULL);
    }
    
    *locsymsp = locsyms;
    return locsyms;
}

static bool
handle_global_symbol(struct elf_link_hash_entry **hp,
                    Elf_Internal_Sym **symp,
                    asection **symsecp,
                    unsigned long r_symndx,
                    bfd *ibfd,
                    Elf_Internal_Shdr *symtab_hdr)
{
    struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(ibfd);
    struct elf_link_hash_entry *h = sym_hashes[r_symndx - symtab_hdr->sh_info];
    
    h = resolve_indirect_hash(h);
    
    if (hp != NULL) {
        *hp = h;
    }
    
    if (symp != NULL) {
        *symp = NULL;
    }
    
    if (symsecp != NULL) {
        *symsecp = get_hash_section(h);
    }
    
    return true;
}

static bool
handle_local_symbol(struct elf_link_hash_entry **hp,
                   Elf_Internal_Sym **symp,
                   asection **symsecp,
                   Elf_Internal_Sym **locsymsp,
                   unsigned long r_symndx,
                   bfd *ibfd,
                   Elf_Internal_Shdr *symtab_hdr)
{
    Elf_Internal_Sym *locsyms = load_local_symbols(ibfd, symtab_hdr, locsymsp);
    
    if (locsyms == NULL) {
        return false;
    }
    
    Elf_Internal_Sym *sym = locsyms + r_symndx;
    
    if (hp != NULL) {
        *hp = NULL;
    }
    
    if (symp != NULL) {
        *symp = sym;
    }
    
    if (symsecp != NULL) {
        *symsecp = bfd_section_from_elf_index(ibfd, sym->st_shndx);
    }
    
    return true;
}

static bool
get_sym_h(struct elf_link_hash_entry **hp,
         Elf_Internal_Sym **symp,
         asection **symsecp,
         Elf_Internal_Sym **locsymsp,
         unsigned long r_symndx,
         bfd *ibfd)
{
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
    
    if (r_symndx >= symtab_hdr->sh_info) {
        return handle_global_symbol(hp, symp, symsecp, r_symndx, ibfd, symtab_hdr);
    }
    
    return handle_local_symbol(hp, symp, symsecp, locsymsp, r_symndx, ibfd, symtab_hdr);
}

/* Create the note section if not already present.  This is done early so
   that the linker maps the sections to the right place in the output.  */

bool
spu_elf_create_sections (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd;

  ibfd = find_spu_ptnote_section(info);
  
  if (ibfd == NULL)
    {
      ibfd = info->input_bfds;
      if (!create_spu_ptnote_section(ibfd, info))
        return false;
    }

  if (htab->params->emit_fixups)
    {
      if (!create_fixup_section(htab, ibfd))
        return false;
    }

  return true;
}

static bfd*
find_spu_ptnote_section(struct bfd_link_info *info)
{
  bfd *ibfd;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    if (bfd_get_section_by_name (ibfd, SPU_PTNOTE_SPUNAME) != NULL)
      return ibfd;
  return NULL;
}

static bool
create_spu_ptnote_section(bfd *ibfd, struct bfd_link_info *info)
{
  asection *s;
  flagword flags;

  flags = SEC_LOAD | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
  s = bfd_make_section_anyway_with_flags (ibfd, SPU_PTNOTE_SPUNAME, flags);
  if (s == NULL || !bfd_set_section_alignment (s, 4))
    return false;
    
  elf_section_type (s) = SHT_NOTE;

  return setup_ptnote_section_contents(s, ibfd, info);
}

static bool
setup_ptnote_section_contents(asection *s, bfd *ibfd, struct bfd_link_info *info)
{
  size_t name_len;
  size_t size;
  bfd_byte *data;

  name_len = strlen (bfd_get_filename (info->output_bfd)) + 1;
  size = calculate_ptnote_section_size(name_len);

  if (!bfd_set_section_size (s, size))
    return false;

  data = bfd_zalloc (ibfd, size);
  if (data == NULL)
    return false;

  populate_ptnote_data(ibfd, data, name_len, info);
  
  s->contents = data;
  s->alloced = 1;
  
  return true;
}

static size_t
calculate_ptnote_section_size(size_t name_len)
{
  #define HEADER_SIZE 12
  #define ALIGNMENT_MASK -4
  
  size_t size = HEADER_SIZE + ((sizeof (SPU_PLUGIN_NAME) + 3) & ALIGNMENT_MASK);
  size += (name_len + 3) & ALIGNMENT_MASK;
  return size;
}

static void
populate_ptnote_data(bfd *ibfd, bfd_byte *data, size_t name_len, struct bfd_link_info *info)
{
  #define NAME_TYPE_FIELD 1
  #define ALIGNMENT_MASK -4
  
  bfd_put_32 (ibfd, sizeof (SPU_PLUGIN_NAME), data + 0);
  bfd_put_32 (ibfd, name_len, data + 4);
  bfd_put_32 (ibfd, NAME_TYPE_FIELD, data + 8);
  
  memcpy (data + 12, SPU_PLUGIN_NAME, sizeof (SPU_PLUGIN_NAME));
  memcpy (data + 12 + ((sizeof (SPU_PLUGIN_NAME) + 3) & ALIGNMENT_MASK),
          bfd_get_filename (info->output_bfd), name_len);
}

static bool
create_fixup_section(struct spu_link_hash_table *htab, bfd *ibfd)
{
  asection *s;
  flagword flags;

  if (htab->elf.dynobj == NULL)
    htab->elf.dynobj = ibfd;
    
  ibfd = htab->elf.dynobj;
  flags = (SEC_LOAD | SEC_ALLOC | SEC_READONLY | SEC_HAS_CONTENTS
           | SEC_IN_MEMORY | SEC_LINKER_CREATED);
           
  s = bfd_make_section_anyway_with_flags (ibfd, ".fixup", flags);
  if (s == NULL || !bfd_set_section_alignment (s, 2))
    return false;
    
  htab->sfixup = s;
  return true;
}

/* qsort predicate to sort sections by vma.  */

static int
sort_sections (const void *a, const void *b)
{
  const asection *const *s1 = a;
  const asection *const *s2 = b;
  bfd_signed_vma delta = (*s1)->vma - (*s2)->vma;

  if (delta != 0)
    return delta < 0 ? -1 : 1;

  return (*s1)->index - (*s2)->index;
}

/* Identify overlays in the output bfd, and number them.
   Returns 0 on error, 1 if no overlays, 2 if overlays.  */

int
spu_elf_find_overlays (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection **alloc_sec;
  unsigned int i, n, ovl_index, num_buf;
  asection *s;
  bfd_vma ovl_end;
  static const char *const entry_names[2][2] = {
    { "__ovly_load", "__icache_br_handler" },
    { "__ovly_return", "__icache_call_handler" }
  };

  if (info->output_bfd->section_count < 2)
    return 1;

  alloc_sec = bfd_malloc (info->output_bfd->section_count * sizeof (*alloc_sec));
  if (alloc_sec == NULL)
    return 0;

  n = collect_allocated_sections(info, alloc_sec);
  if (n == 0)
    {
      free (alloc_sec);
      return 1;
    }

  qsort (alloc_sec, n, sizeof (*alloc_sec), sort_sections);

  ovl_end = alloc_sec[0]->vma + alloc_sec[0]->size;
  
  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      if (!process_soft_icache_overlays(info, htab, alloc_sec, n, &ovl_index, &num_buf, &ovl_end))
        return 0;
    }
  else
    {
      process_standard_overlays(info, htab, alloc_sec, n, &ovl_index, &num_buf, &ovl_end);
    }

  htab->num_overlays = ovl_index;
  htab->num_buf = num_buf;
  htab->ovl_sec = alloc_sec;

  if (ovl_index == 0)
    return 1;

  if (!setup_overlay_entries(htab, entry_names))
    return 0;

  return 2;
}

static unsigned int
collect_allocated_sections(struct bfd_link_info *info, asection **alloc_sec)
{
  unsigned int n = 0;
  asection *s;
  
  for (s = info->output_bfd->sections; s != NULL; s = s->next)
    if (is_valid_allocated_section(s))
      alloc_sec[n++] = s;
  
  return n;
}

static int
is_valid_allocated_section(asection *s)
{
  return (s->flags & SEC_ALLOC) != 0
      && (s->flags & (SEC_LOAD | SEC_THREAD_LOCAL)) != SEC_THREAD_LOCAL
      && s->size != 0;
}

static int
process_soft_icache_overlays(struct bfd_link_info *info,
                             struct spu_link_hash_table *htab,
                             asection **alloc_sec,
                             unsigned int n,
                             unsigned int *ovl_index,
                             unsigned int *num_buf,
                             bfd_vma *ovl_end)
{
  unsigned int i;
  bfd_vma vma_start = 0;
  
  i = find_first_overlay_section(alloc_sec, n, htab, ovl_end, &vma_start);
  
  if (!process_cache_area_sections(info, htab, alloc_sec, n, i, vma_start, ovl_index, num_buf))
    return 0;
  
  if (!validate_remaining_sections(info, alloc_sec, n, i + *ovl_index, *ovl_end))
    return 0;
  
  return 1;
}

static unsigned int
find_first_overlay_section(asection **alloc_sec,
                           unsigned int n,
                           struct spu_link_hash_table *htab,
                           bfd_vma *ovl_end,
                           bfd_vma *vma_start)
{
  unsigned int i;
  
  for (i = 1; i < n; i++)
    {
      asection *s = alloc_sec[i];
      if (s->vma < *ovl_end)
        {
          asection *s0 = alloc_sec[i - 1];
          *vma_start = s0->vma;
          *ovl_end = (s0->vma + ((bfd_vma) 1 << (htab->num_lines_log2 + htab->line_size_log2)));
          return i - 1;
        }
      *ovl_end = s->vma + s->size;
    }
  return i;
}

static int
process_cache_area_sections(struct bfd_link_info *info,
                            struct spu_link_hash_table *htab,
                            asection **alloc_sec,
                            unsigned int n,
                            unsigned int start_idx,
                            bfd_vma vma_start,
                            unsigned int *ovl_index,
                            unsigned int *num_buf)
{
  unsigned int i, prev_buf = 0, set_id = 0;
  
  *ovl_index = 0;
  *num_buf = 0;
  
  for (i = start_idx; i < n; i++)
    {
      asection *s = alloc_sec[i];
      if (s->vma >= vma_start + ((bfd_vma) 1 << (htab->num_lines_log2 + htab->line_size_log2)))
        break;
      
      if (startswith (s->name, ".ovl.init"))
        continue;
      
      *num_buf = ((s->vma - vma_start) >> htab->line_size_log2) + 1;
      set_id = (*num_buf == prev_buf) ? set_id + 1 : 0;
      prev_buf = *num_buf;
      
      if (!validate_cache_alignment(info, s, vma_start, htab->params->line_size))
        return 0;
      
      if (!validate_cache_size(info, s, htab->params->line_size))
        return 0;
      
      alloc_sec[(*ovl_index)++] = s;
      spu_elf_section_data (s)->u.o.ovl_index = (set_id << htab->num_lines_log2) + *num_buf;
      spu_elf_section_data (s)->u.o.ovl_buf = *num_buf;
    }
  
  return 1;
}

static int
validate_cache_alignment(struct bfd_link_info *info, asection *s, bfd_vma vma_start, unsigned int line_size)
{
  if ((s->vma - vma_start) & (line_size - 1))
    {
      info->callbacks->einfo (_("%X%P: overlay section %pA does not start on a cache line\n"), s);
      bfd_set_error (bfd_error_bad_value);
      return 0;
    }
  return 1;
}

static int
validate_cache_size(struct bfd_link_info *info, asection *s, unsigned int line_size)
{
  if (s->size > line_size)
    {
      info->callbacks->einfo (_("%X%P: overlay section %pA is larger than a cache line\n"), s);
      bfd_set_error (bfd_error_bad_value);
      return 0;
    }
  return 1;
}

static int
validate_remaining_sections(struct bfd_link_info *info, asection **alloc_sec, unsigned int n, unsigned int start_idx, bfd_vma ovl_end)
{
  unsigned int i;
  
  for (i = start_idx; i < n; i++)
    {
      asection *s = alloc_sec[i];
      if (s->vma < ovl_end)
        {
          info->callbacks->einfo (_("%X%P: overlay section %pA is not in cache area\n"), alloc_sec[i-1]);
          bfd_set_error (bfd_error_bad_value);
          return 0;
        }
      ovl_end = s->vma + s->size;
    }
  return 1;
}

static void
process_standard_overlays(struct bfd_link_info *info,
                          struct spu_link_hash_table *htab,
                          asection **alloc_sec,
                          unsigned int n,
                          unsigned int *ovl_index,
                          unsigned int *num_buf,
                          bfd_vma *ovl_end)
{
  unsigned int i;
  
  *ovl_index = 0;
  *num_buf = 0;
  
  for (i = 1; i < n; i++)
    {
      asection *s = alloc_sec[i];
      if (s->vma < *ovl_end)
        {
          if (!process_overlapping_section(info, alloc_sec, i, ovl_index, num_buf, ovl_end))
            return;
        }
      else
        *ovl_end = s->vma + s->size;
    }
}

static int
process_overlapping_section(struct bfd_link_info *info,
                            asection **alloc_sec,
                            unsigned int idx,
                            unsigned int *ovl_index,
                            unsigned int *num_buf,
                            bfd_vma *ovl_end)
{
  asection *s = alloc_sec[idx];
  asection *s0 = alloc_sec[idx - 1];
  
  if (spu_elf_section_data (s0)->u.o.ovl_index == 0)
    {
      (*num_buf)++;
      if (!startswith (s0->name, ".ovl.init"))
        {
          alloc_sec[*ovl_index] = s0;
          spu_elf_section_data (s0)->u.o.ovl_index = ++(*ovl_index);
          spu_elf_section_data (s0)->u.o.ovl_buf = *num_buf;
        }
      else
        *ovl_end = s->vma + s->size;
    }
  
  if (!startswith (s->name, ".ovl.init"))
    {
      alloc_sec[*ovl_index] = s;
      spu_elf_section_data (s)->u.o.ovl_index = ++(*ovl_index);
      spu_elf_section_data (s)->u.o.ovl_buf = *num_buf;
      
      if (s0->vma != s->vma)
        {
          info->callbacks->einfo (_("%X%P: overlay sections %pA and %pA do not start at the same address\n"), s0, s);
          bfd_set_error (bfd_error_bad_value);
          return 0;
        }
      
      if (*ovl_end < s->vma + s->size)
        *ovl_end = s->vma + s->size;
    }
  
  return 1;
}

static int
setup_overlay_entries(struct spu_link_hash_table *htab, const char *const entry_names[2][2])
{
  int i;
  
  for (i = 0; i < 2; i++)
    {
      const char *name = entry_names[i][htab->params->ovly_flavour];
      struct elf_link_hash_entry *h = elf_link_hash_lookup (&htab->elf, name, true, false, false);
      
      if (h == NULL)
        return 0;
      
      if (h->root.type == bfd_link_hash_new)
        {
          h->root.type = bfd_link_hash_undefined;
          h->ref_regular = 1;
          h->ref_regular_nonweak = 1;
          h->non_elf = 0;
        }
      htab->ovly_entry[i] = h;
    }
  
  return 1;
}

/* Non-zero to use bra in overlay stubs rather than br.  */
#define BRA_STUBS 0

#define BRA	0x30000000
#define BRASL	0x31000000
#define BR	0x32000000
#define BRSL	0x33000000
#define NOP	0x40200000
#define LNOP	0x00200000
#define ILA	0x42000000

/* Return true for all relative and absolute branch instructions.
   bra   00110000 0..
   brasl 00110001 0..
   br    00110010 0..
   brsl  00110011 0..
   brz   00100000 0..
   brnz  00100001 0..
   brhz  00100010 0..
   brhnz 00100011 0..  */

static bool is_branch(const unsigned char *insn)
{
    #define BRANCH_OPCODE_MASK 0xec
    #define BRANCH_OPCODE_VALUE 0x20
    #define BRANCH_OPERAND_MASK 0x80
    #define BRANCH_OPERAND_VALUE 0

    bool opcode_matches = (insn[0] & BRANCH_OPCODE_MASK) == BRANCH_OPCODE_VALUE;
    bool operand_matches = (insn[1] & BRANCH_OPERAND_MASK) == BRANCH_OPERAND_VALUE;
    
    return opcode_matches && operand_matches;
}

/* Return true for all indirect branch instructions.
   bi     00110101 000
   bisl   00110101 001
   iret   00110101 010
   bisled 00110101 011
   biz    00100101 000
   binz   00100101 001
   bihz   00100101 010
   bihnz  00100101 011  */

static bool is_indirect_branch(const unsigned char *insn)
{
    const unsigned char INDIRECT_BRANCH_MASK1 = 0xef;
    const unsigned char INDIRECT_BRANCH_VALUE1 = 0x25;
    const unsigned char INDIRECT_BRANCH_MASK2 = 0x80;
    const unsigned char INDIRECT_BRANCH_VALUE2 = 0x00;
    
    bool first_byte_matches = (insn[0] & INDIRECT_BRANCH_MASK1) == INDIRECT_BRANCH_VALUE1;
    bool second_byte_matches = (insn[1] & INDIRECT_BRANCH_MASK2) == INDIRECT_BRANCH_VALUE2;
    
    return first_byte_matches && second_byte_matches;
}

/* Return true for branch hint instructions.
   hbra  0001000..
   hbrr  0001001..  */

static bool is_hint(const unsigned char *insn)
{
    const unsigned char HINT_MASK = 0xfc;
    const unsigned char HINT_PATTERN = 0x10;
    
    return (insn[0] & HINT_MASK) == HINT_PATTERN;
}

/* True if INPUT_SECTION might need overlay stubs.  */

static bool
maybe_needs_stubs (asection *input_section)
{
  if ((input_section->flags & SEC_ALLOC) == 0)
    return false;

  if (input_section->output_section == bfd_abs_section_ptr)
    return false;

  if (strcmp (input_section->name, ".eh_frame") == 0)
    return false;

  return true;
}

enum _stub_type
{
  no_stub,
  call_ovl_stub,
  br000_ovl_stub,
  br001_ovl_stub,
  br010_ovl_stub,
  br011_ovl_stub,
  br100_ovl_stub,
  br101_ovl_stub,
  br110_ovl_stub,
  br111_ovl_stub,
  nonovl_stub,
  stub_error
};

/* Return non-zero if this reloc symbol should go via an overlay stub.
   Return 2 if the stub must be in non-overlay area.  */

static bool is_overlay_manager_symbol(struct elf_link_hash_entry *h, struct spu_link_hash_table *htab)
{
  return h == htab->ovly_entry[0] || h == htab->ovly_entry[1];
}

static bool is_setjmp_symbol(struct elf_link_hash_entry *h)
{
  if (!h)
    return false;
  return startswith(h->root.root.string, "setjmp") &&
         (h->root.root.string[6] == '\0' || h->root.root.string[6] == '@');
}

static bool is_valid_section(asection *sym_sec)
{
  return sym_sec != NULL &&
         sym_sec->output_section != bfd_abs_section_ptr &&
         spu_elf_section_data(sym_sec->output_section) != NULL;
}

static bfd_byte* get_instruction_contents(asection *input_section, 
                                          Elf_Internal_Rela *irela,
                                          bfd_byte *contents,
                                          bfd_byte *insn_buffer)
{
  if (contents)
    return contents + irela->r_offset;
    
  if (!bfd_get_section_contents(input_section->owner,
                                input_section,
                                insn_buffer,
                                irela->r_offset, 4))
    return NULL;
  return insn_buffer;
}

static void warn_non_function_call(struct elf_link_hash_entry *h,
                                   Elf_Internal_Sym *sym,
                                   asection *input_section,
                                   asection *sym_sec)
{
  const char *sym_name;
  
  if (h) {
    sym_name = h->root.root.string;
  } else {
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(input_section->owner)->symtab_hdr;
    sym_name = bfd_elf_sym_name(input_section->owner, symtab_hdr, sym, sym_sec);
  }
  
  _bfd_error_handler(_("warning: call to non-function symbol %s defined in %pB"),
                    sym_name, sym_sec->owner);
}

static bool should_skip_stub(bool branch, bool hint,
                             unsigned int sym_type,
                             asection *sym_sec,
                             struct spu_link_hash_table *htab)
{
  if (!branch && htab->params->ovly_flavour == ovly_soft_icache)
    return true;
    
  if (sym_type != STT_FUNC && !branch && !hint && !(sym_sec->flags & SEC_CODE))
    return true;
    
  return false;
}

static enum _stub_type determine_overlay_stub_type(bfd_byte *contents,
                                                   bool branch,
                                                   bool call,
                                                   unsigned int sym_type)
{
  if (!branch)
    return no_stub;
    
  unsigned int lrlive = (contents[1] & 0x70) >> 4;
  
  if (!lrlive && (call || sym_type == STT_FUNC))
    return call_ovl_stub;
    
  return br000_ovl_stub + lrlive;
}

static enum _stub_type
needs_ovl_stub(struct elf_link_hash_entry *h,
              Elf_Internal_Sym *sym,
              asection *sym_sec,
              asection *input_section,
              Elf_Internal_Rela *irela,
              bfd_byte *contents,
              struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table(info);
  enum elf_spu_reloc_type r_type;
  unsigned int sym_type;
  bool branch = false, hint = false, call = false;
  enum _stub_type ret = no_stub;
  bfd_byte insn[4];

  if (!is_valid_section(sym_sec))
    return ret;

  if (h) {
    if (is_overlay_manager_symbol(h, htab))
      return ret;
    if (is_setjmp_symbol(h))
      ret = call_ovl_stub;
    sym_type = h->type;
  } else {
    sym_type = ELF_ST_TYPE(sym->st_info);
  }

  r_type = ELF32_R_TYPE(irela->r_info);
  
  if (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16) {
    contents = get_instruction_contents(input_section, irela, contents, insn);
    if (!contents)
      return stub_error;

    branch = is_branch(contents);
    hint = is_hint(contents);
    
    if (branch || hint) {
      call = (contents[0] & 0xfd) == 0x31;
      if (call && sym_type != STT_FUNC && contents != insn)
        warn_non_function_call(h, sym, input_section, sym_sec);
    }
  }

  if (should_skip_stub(branch, hint, sym_type, sym_sec, htab))
    return no_stub;

  if (spu_elf_section_data(sym_sec->output_section)->u.o.ovl_index == 0 &&
      !htab->params->non_overlay_stubs)
    return ret;

  if (spu_elf_section_data(sym_sec->output_section)->u.o.ovl_index !=
      spu_elf_section_data(input_section->output_section)->u.o.ovl_index)
    ret = determine_overlay_stub_type(contents, branch, call, sym_type);

  if (!branch && !hint && sym_type == STT_FUNC &&
      htab->params->ovly_flavour != ovly_soft_icache)
    ret = nonovl_stub;

  return ret;
}

static struct got_entry **
get_got_entry_head(bfd *ibfd, struct elf_link_hash_entry *h, const Elf_Internal_Rela *irela)
{
  if (h != NULL)
    return &h->got.glist;

  if (elf_local_got_ents (ibfd) == NULL)
    {
      bfd_size_type amt = (elf_tdata (ibfd)->symtab_hdr.sh_info
                           * sizeof (*elf_local_got_ents (ibfd)));
      elf_local_got_ents (ibfd) = bfd_zmalloc (amt);
      if (elf_local_got_ents (ibfd) == NULL)
        return NULL;
    }
  return elf_local_got_ents (ibfd) + ELF32_R_SYM (irela->r_info);
}

static struct got_entry *
find_got_entry(struct got_entry *head, bfd_vma addend, unsigned int ovl)
{
  struct got_entry *g;
  for (g = head; g != NULL; g = g->next)
    if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
      return g;
  return NULL;
}

static void
remove_matching_stubs(struct got_entry **head, bfd_vma addend, struct spu_link_hash_table *htab)
{
  struct got_entry *g, *gnext;
  for (g = *head; g != NULL; g = gnext)
    {
      gnext = g->next;
      if (g->addend == addend)
        {
          htab->stub_count[g->ovl] -= 1;
          free (g);
        }
    }
}

static struct got_entry *
create_got_entry(unsigned int ovl, bfd_vma addend, struct got_entry **head)
{
  struct got_entry *g = bfd_malloc (sizeof *g);
  if (g == NULL)
    return NULL;
  g->ovl = ovl;
  g->addend = addend;
  g->stub_addr = (bfd_vma) -1;
  g->next = *head;
  *head = g;
  return g;
}

static bool
handle_soft_icache(struct spu_link_hash_table *htab, unsigned int ovl)
{
  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      htab->stub_count[ovl] += 1;
      return true;
    }
  return false;
}

static bool
count_stub (struct spu_link_hash_table *htab,
            bfd *ibfd,
            asection *isec,
            enum _stub_type stub_type,
            struct elf_link_hash_entry *h,
            const Elf_Internal_Rela *irela)
{
  unsigned int ovl = 0;
  struct got_entry *g, **head;
  bfd_vma addend;

  if (stub_type != nonovl_stub)
    ovl = spu_elf_section_data (isec->output_section)->u.o.ovl_index;

  head = get_got_entry_head(ibfd, h, irela);
  if (head == NULL)
    return false;

  if (handle_soft_icache(htab, ovl))
    return true;

  addend = 0;
  if (irela != NULL)
    addend = irela->r_addend;

  if (ovl == 0)
    {
      g = find_got_entry(*head, addend, 0);
      if (g == NULL)
        remove_matching_stubs(head, addend, htab);
    }
  else
    {
      g = find_got_entry(*head, addend, ovl);
    }

  if (g == NULL)
    {
      g = create_got_entry(ovl, addend, head);
      if (g == NULL)
        return false;
      htab->stub_count[ovl] += 1;
    }

  return true;
}

/* Support two sizes of overlay stubs, a slower more compact stub of two
   instructions, and a faster stub of four instructions.
   Soft-icache stubs are four or eight words.  */

static unsigned int
ovl_stub_size (struct spu_elf_params *params)
{
  const unsigned int BASE_STUB_SIZE = 16;
  unsigned int size = BASE_STUB_SIZE << params->ovly_flavour;
  return size >> params->compact_stub;
}

static unsigned int
ovl_stub_size_log2 (struct spu_elf_params *params)
{
  const int BASE_SIZE_LOG2 = 4;
  return BASE_SIZE_LOG2 + params->ovly_flavour - params->compact_stub;
}

/* Two instruction overlay stubs look like:

   brsl $75,__ovly_load
   .word target_ovl_and_address

   ovl_and_address is a word with the overlay number in the top 14 bits
   and local store address in the bottom 18 bits.

   Four instruction overlay stubs look like:

   ila $78,ovl_number
   lnop
   ila $79,target_address
   br __ovly_load

   Software icache stubs are:

   .word target_index
   .word target_ia;
   .word lrlive_branchlocalstoreaddr;
   brasl $75,__icache_br_handler
   .quad xor_pattern
*/

#define ILA_BASE 78
#define ILA_DEST_BASE 79
#define BRASL_BASE 75
#define SHIFT_7 7
#define SHIFT_5 5
#define SHIFT_18 18
#define SHIFT_29 29
#define MASK_3FFFF 0x3ffff
#define MASK_1FFFF80 0x01ffff80
#define MASK_7FFF80 0x007fff80
#define BR_OFFSET 12
#define STUB_SIZE_4 4
#define STUB_SIZE_8 8
#define STUB_SIZE_12 12
#define STUB_SIZE_16 16
#define LRLIVE_ENTRY 5
#define LRLIVE_FRAME_SP 1
#define LRLIVE_FRAME_LR 4
#define LRLIVE_BETWEEN 3

static struct got_entry* allocate_got_entry(unsigned int ovl, const Elf_Internal_Rela *irela, asection *isec)
{
  struct got_entry *g = bfd_malloc(sizeof *g);
  if (g == NULL)
    return NULL;
  g->ovl = ovl;
  g->br_addr = 0;
  if (irela != NULL)
    g->br_addr = irela->r_offset + isec->output_offset + isec->output_section->vma;
  return g;
}

static struct got_entry* find_existing_got_entry(struct got_entry *head, bfd_vma addend, unsigned int ovl)
{
  for (struct got_entry *g = head; g != NULL; g = g->next)
    if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
      return g;
  abort();
  return NULL;
}

static bfd_vma calculate_destination(asection *dest_sec)
{
  return dest_sec->output_offset + dest_sec->output_section->vma;
}

static bool check_alignment(bfd_vma dest, bfd_vma to, bfd_vma from, struct spu_link_hash_table *htab)
{
  if (((dest | to | from) & 3) != 0)
  {
    htab->stub_err = 1;
    return false;
  }
  return true;
}

static void write_normal_stub(asection *sec, unsigned int dest_ovl, bfd_vma dest, bfd_vma to, bfd_vma from, bool compact)
{
  if (!compact)
  {
    bfd_put_32(sec->owner, ILA + ((dest_ovl << SHIFT_7) & MASK_1FFFF80) + ILA_BASE, sec->contents + sec->size);
    bfd_put_32(sec->owner, LNOP, sec->contents + sec->size + STUB_SIZE_4);
    bfd_put_32(sec->owner, ILA + ((dest << SHIFT_7) & MASK_1FFFF80) + ILA_DEST_BASE, sec->contents + sec->size + STUB_SIZE_8);
    if (!BRA_STUBS)
      bfd_put_32(sec->owner, BR + (((to - (from + BR_OFFSET)) << SHIFT_5) & MASK_7FFF80), sec->contents + sec->size + STUB_SIZE_12);
    else
      bfd_put_32(sec->owner, BRA + ((to << SHIFT_5) & MASK_7FFF80), sec->contents + sec->size + STUB_SIZE_12);
  }
  else
  {
    if (!BRA_STUBS)
      bfd_put_32(sec->owner, BRSL + (((to - from) << SHIFT_5) & MASK_7FFF80) + BRASL_BASE, sec->contents + sec->size);
    else
      bfd_put_32(sec->owner, BRASL + ((to << SHIFT_5) & MASK_7FFF80) + BRASL_BASE, sec->contents + sec->size);
    bfd_put_32(sec->owner, (dest & MASK_3FFFF) | (dest_ovl << SHIFT_18), sec->contents + sec->size + STUB_SIZE_4);
  }
}

static struct function_info* find_earliest_frame_function(struct function_info *caller)
{
  struct function_info *found = NULL;
  
  if (caller->lr_store != (bfd_vma) -1 || caller->sp_adjust != (bfd_vma) -1)
    found = caller;
    
  while (caller->start != NULL)
  {
    caller = caller->start;
    if (caller->lr_store != (bfd_vma) -1 || caller->sp_adjust != (bfd_vma) -1)
      found = caller;
  }
  
  return found ? found : caller;
}

static unsigned int analyze_lrlive(struct function_info *caller, bfd_vma off)
{
  if (off > caller->sp_adjust)
  {
    if (off > caller->lr_store)
      return LRLIVE_FRAME_SP;
    else
      return LRLIVE_FRAME_LR;
  }
  else if (off > caller->lr_store)
  {
    BFD_ASSERT(0);
    return LRLIVE_BETWEEN;
  }
  else
    return LRLIVE_ENTRY;
}

static unsigned int get_lrlive_value(enum _stub_type stub_type, asection *isec, 
                                    const Elf_Internal_Rela *irela, 
                                    struct bfd_link_info *info,
                                    struct spu_link_hash_table *htab)
{
  unsigned int lrlive = 0;
  
  if (stub_type == nonovl_stub)
    return lrlive;
  else if (stub_type == call_ovl_stub)
    return LRLIVE_ENTRY;
  else if (!htab->params->lrlive_analysis)
    return LRLIVE_FRAME_SP;
  else if (irela != NULL)
  {
    struct function_info *caller = find_function(isec, irela->r_offset, info);
    bfd_vma off;
    
    if (caller->start == NULL)
      off = irela->r_offset;
    else
    {
      struct function_info *found = find_earliest_frame_function(caller);
      if (found != NULL)
        caller = found;
      off = (bfd_vma) -1;
    }
    
    lrlive = analyze_lrlive(caller, off);
    
    if (stub_type != br000_ovl_stub && lrlive != stub_type - br000_ovl_stub)
      info->callbacks->einfo(_("%pA:0x%v lrlive .brinfo (%u) differs from analysis (%u)\n"),
                            isec, irela->r_offset, lrlive, stub_type - br000_ovl_stub);
  }
  
  if (stub_type > br000_ovl_stub)
    lrlive = stub_type - br000_ovl_stub;
    
  return lrlive;
}

static void write_soft_icache_stub(asection *sec, struct got_entry *g, 
                                  unsigned int dest_ovl, bfd_vma dest,
                                  bfd_vma to, bfd_vma br_dest,
                                  unsigned int lrlive, unsigned int ovl,
                                  const Elf_Internal_Rela *irela,
                                  struct spu_link_hash_table *htab)
{
  unsigned int set_id = ((dest_ovl - 1) >> htab->num_lines_log2) + 1;
  bfd_vma patt = dest ^ br_dest;
  
  if (irela != NULL && ELF32_R_TYPE(irela->r_info) == R_SPU_REL16)
    patt = (dest - g->br_addr) ^ (br_dest - g->br_addr);
    
  bfd_put_32(sec->owner, (set_id << SHIFT_18) | (dest & MASK_3FFFF), sec->contents + sec->size);
  bfd_put_32(sec->owner, BRASL + ((to << SHIFT_5) & MASK_7FFF80) + BRASL_BASE, sec->contents + sec->size + STUB_SIZE_4);
  bfd_put_32(sec->owner, (lrlive << SHIFT_29) | (g->br_addr & MASK_3FFFF), sec->contents + sec->size + STUB_SIZE_8);
  bfd_put_32(sec->owner, (patt << SHIFT_5) & MASK_7FFF80, sec->contents + sec->size + STUB_SIZE_12);
  
  if (ovl == 0)
    sec->size += STUB_SIZE_16;
}

static char* create_stub_symbol_name(struct got_entry *g, struct elf_link_hash_entry *h,
                                    asection *dest_sec, const Elf_Internal_Rela *irela)
{
  size_t len = 8 + sizeof(".ovl_call.") - 1;
  int add = 0;
  char *name;
  
  if (h != NULL)
    len += strlen(h->root.root.string);
  else
    len += 8 + 1 + 8;
    
  if (irela != NULL)
    add = (int)irela->r_addend & 0xffffffff;
  if (add != 0)
    len += 1 + 8;
    
  name = bfd_malloc(len + 1);
  if (name == NULL)
    return NULL;
    
  sprintf(name, "%08x.ovl_call.", g->ovl);
  
  if (h != NULL)
    strcpy(name + 8 + sizeof(".ovl_call.") - 1, h->root.root.string);
  else
    sprintf(name + 8 + sizeof(".ovl_call.") - 1, "%x:%x",
           dest_sec->id & 0xffffffff,
           (int)ELF32_R_SYM(irela->r_info) & 0xffffffff);
           
  if (add != 0)
    sprintf(name + len - 9, "+%x", add);
    
  return name;
}

static bool create_stub_symbol(struct spu_link_hash_table *htab, struct got_entry *g,
                              struct elf_link_hash_entry *h, asection *dest_sec,
                              const Elf_Internal_Rela *irela, asection *sec)
{
  char *name = create_stub_symbol_name(g, h, dest_sec, irela);
  if (name == NULL)
    return false;
    
  h = elf_link_hash_lookup(&htab->elf, name, true, true, false);
  free(name);
  
  if (h == NULL)
    return false;
    
  if (h->root.type == bfd_link_hash_new)
  {
    h->root.type = bfd_link_hash_defined;
    h->root.u.def.section = sec;
    h->size = ovl_stub_size(htab->params);
    h->root.u.def.value = sec->size - h->size;
    h->type = STT_FUNC;
    h->ref_regular = 1;
    h->def_regular = 1;
    h->ref_regular_nonweak = 1;
    h->forced_local = 1;
    h->non_elf = 0;
  }
  
  return true;
}

static bool
build_stub (struct bfd_link_info *info,
           bfd *ibfd,
           asection *isec,
           enum _stub_type stub_type,
           struct elf_link_hash_entry *h,
           const Elf_Internal_Rela *irela,
           bfd_vma dest,
           asection *dest_sec)
{
  struct spu_link_hash_table *htab = spu_hash_table(info);
  unsigned int ovl = 0;
  struct got_entry *g, **head;
  asection *sec;
  bfd_vma addend = 0, from, to, br_dest;
  unsigned int lrlive, dest_ovl;

  if (stub_type != nonovl_stub)
    ovl = spu_elf_section_data(isec->output_section)->u.o.ovl_index;

  if (h != NULL)
    head = &h->got.glist;
  else
    head = elf_local_got_ents(ibfd) + ELF32_R_SYM(irela->r_info);

  if (irela != NULL)
    addend = irela->r_addend;

  if (htab->params->ovly_flavour == ovly_soft_icache)
  {
    g = allocate_got_entry(ovl, irela, isec);
    if (g == NULL)
      return false;
    g->next = *head;
    *head = g;
  }
  else
  {
    g = find_existing_got_entry(*head, addend, ovl);
    if (g->ovl == 0 && ovl != 0)
      return true;
    if (g->stub_addr != (bfd_vma) -1)
      return true;
  }

  sec = htab->stub_sec[ovl];
  dest += calculate_destination(dest_sec);
  from = sec->size + sec->output_offset + sec->output_section->vma;
  g->stub_addr = from;
  to = htab->ovly_entry[0]->root.u.def.value + calculate_destination(htab->ovly_entry[0]->root.u.def.section);

  if (!check_alignment(dest, to, from, htab))
    return false;

  dest_ovl = spu_elf_section_data(dest_sec->output_section)->u.o.ovl_index;

  if (htab->params->ovly_flavour == ovly_normal)
  {
    write_normal_stub(sec, dest_ovl, dest, to, from, htab->params->compact_stub);
  }
  else if (htab->params->ovly_flavour == ovly_soft_icache && htab->params->compact_stub)
  {
    lrlive = get_lrlive_value(stub_type, isec, irela, info, htab);
    
    if (ovl == 0)
      to = htab->ovly_entry[1]->root.u.def.value + calculate_destination(htab->ovly_entry[1]->root.u.def.section);
    
    g->stub_addr += STUB_SIZE_4;
    br_dest = g->stub_addr;
    
    if (irela == NULL)
    {
      BFD_ASSERT(stub_type == nonovl_stub);
      g->br_addr = g->stub_addr;
      br_dest = to;
    }
    
    write_soft_icache_stub(sec, g, dest_ovl, dest, to, br_dest, lrlive, ovl, irela, htab);
  }
  else
    abort();

  sec->size += ovl_stub_size(htab->params);

  if (htab->params->emit_stub_syms)
  {
    if (!create_stub_symbol(htab, g, h, dest_sec, irela, sec))
      return false;
  }

  return true;
}

/* Called via elf_link_hash_traverse to allocate stubs for any _SPUEAR_
   symbols.  */

static bool is_spuear_symbol(const char *name)
{
    return startswith(name, "_SPUEAR_");
}

static bool is_defined_or_weak(struct elf_link_hash_entry *h)
{
    return h->root.type == bfd_link_hash_defined || 
           h->root.type == bfd_link_hash_defweak;
}

static bool has_valid_output_section(asection *sym_sec)
{
    if (sym_sec == NULL)
        return false;
    
    if (sym_sec->output_section == bfd_abs_section_ptr)
        return false;
    
    return spu_elf_section_data(sym_sec->output_section) != NULL;
}

static bool needs_stub(struct spu_link_hash_table *htab, asection *output_section)
{
    struct spu_elf_stack_info *section_data = spu_elf_section_data(output_section);
    
    if (section_data->u.o.ovl_index != 0)
        return true;
    
    return htab->params->non_overlay_stubs;
}

static bool
allocate_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
    struct bfd_link_info *info = inf;
    struct spu_link_hash_table *htab = spu_hash_table(info);
    asection *sym_sec;

    if (!is_defined_or_weak(h))
        return true;

    if (!h->def_regular)
        return true;

    if (!is_spuear_symbol(h->root.root.string))
        return true;

    sym_sec = h->root.u.def.section;
    if (!has_valid_output_section(sym_sec))
        return true;

    if (!needs_stub(htab, sym_sec->output_section))
        return true;

    return count_stub(htab, NULL, NULL, nonovl_stub, h, NULL);
}

static bool is_defined_or_defweak(struct elf_link_hash_entry *h)
{
    return h->root.type == bfd_link_hash_defined || 
           h->root.type == bfd_link_hash_defweak;
}

static bool is_spuear_symbol(const char *name)
{
    return startswith(name, "_SPUEAR_");
}

static bool has_valid_section(asection *section)
{
    return section != NULL && 
           section->output_section != bfd_abs_section_ptr;
}

static bool needs_stub(asection *sym_sec, struct spu_link_hash_table *htab)
{
    struct spu_elf_section_data *sec_data;
    
    if (!has_valid_section(sym_sec))
        return false;
    
    sec_data = spu_elf_section_data(sym_sec->output_section);
    if (sec_data == NULL)
        return false;
    
    return sec_data->u.o.ovl_index != 0 || htab->params->non_overlay_stubs;
}

static bool
build_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
    struct bfd_link_info *info = inf;
    struct spu_link_hash_table *htab = spu_hash_table(info);
    asection *sym_sec;
    
    if (!is_defined_or_defweak(h))
        return true;
    
    if (!h->def_regular)
        return true;
    
    if (!is_spuear_symbol(h->root.root.string))
        return true;
    
    sym_sec = h->root.u.def.section;
    
    if (!needs_stub(sym_sec, htab))
        return true;
    
    return build_stub(info, NULL, NULL, nonovl_stub, h, NULL,
                     h->root.u.def.value, sym_sec);
}

/* Size or build stubs.  */

static bool
is_spu_elf32_bfd(bfd *ibfd)
{
    extern const bfd_target spu_elf32_vec;
    return ibfd->xvec == &spu_elf32_vec;
}

static bool
has_valid_symbol_table(bfd *ibfd)
{
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
    return symtab_hdr->sh_info != 0;
}

static bool
section_needs_processing(asection *isec)
{
    if ((isec->flags & SEC_RELOC) == 0 || isec->reloc_count == 0)
        return false;
    return maybe_needs_stubs(isec);
}

static void
free_relocs_if_needed(asection *isec, Elf_Internal_Rela *internal_relocs)
{
    if (elf_section_data(isec)->relocs != internal_relocs)
        free(internal_relocs);
}

static void
free_local_syms_if_needed(Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *local_syms)
{
    if (symtab_hdr->contents != (unsigned char *)local_syms)
        free(local_syms);
}

static bool
allocate_stub_count_if_needed(struct spu_link_hash_table *htab)
{
    if (htab->stub_count != NULL)
        return true;
    
    bfd_size_type amt = (htab->num_overlays + 1) * sizeof(*htab->stub_count);
    htab->stub_count = bfd_zmalloc(amt);
    return htab->stub_count != NULL;
}

static bfd_vma
calculate_destination(struct elf_link_hash_entry *h, Elf_Internal_Sym *sym, Elf_Internal_Rela *irela)
{
    bfd_vma dest;
    if (h != NULL)
        dest = h->root.u.def.value;
    else
        dest = sym->st_value;
    return dest + irela->r_addend;
}

static bool
process_stub_relocation(struct bfd_link_info *info, bfd *ibfd, asection *isec,
                        Elf_Internal_Rela *irela, Elf_Internal_Sym **local_syms,
                        struct spu_link_hash_table *htab, bool build)
{
    enum elf_spu_reloc_type r_type = ELF32_R_TYPE(irela->r_info);
    unsigned int r_indx = ELF32_R_SYM(irela->r_info);
    
    if (r_type >= R_SPU_max)
    {
        bfd_set_error(bfd_error_bad_value);
        return false;
    }
    
    asection *sym_sec;
    Elf_Internal_Sym *sym;
    struct elf_link_hash_entry *h;
    
    if (!get_sym_h(&h, &sym, &sym_sec, local_syms, r_indx, ibfd))
        return false;
    
    enum _stub_type stub_type = needs_ovl_stub(h, sym, sym_sec, isec, irela, NULL, info);
    
    if (stub_type == no_stub)
        return true;
    if (stub_type == stub_error)
        return false;
    
    if (!allocate_stub_count_if_needed(htab))
        return false;
    
    if (!build)
        return count_stub(htab, ibfd, isec, stub_type, h, irela);
    
    bfd_vma dest = calculate_destination(h, sym, irela);
    return build_stub(info, ibfd, isec, stub_type, h, irela, dest, sym_sec);
}

static bool
process_section_relocations(struct bfd_link_info *info, bfd *ibfd, asection *isec,
                           Elf_Internal_Sym **local_syms, struct spu_link_hash_table *htab,
                           bool build)
{
    if (!section_needs_processing(isec))
        return true;
    
    Elf_Internal_Rela *internal_relocs = _bfd_elf_link_read_relocs(ibfd, isec, NULL, NULL,
                                                                    info->keep_memory);
    if (internal_relocs == NULL)
        return false;
    
    Elf_Internal_Rela *irela = internal_relocs;
    Elf_Internal_Rela *irelaend = irela + isec->reloc_count;
    
    for (; irela < irelaend; irela++)
    {
        if (!process_stub_relocation(info, ibfd, isec, irela, local_syms, htab, build))
        {
            free_relocs_if_needed(isec, internal_relocs);
            return false;
        }
    }
    
    free_relocs_if_needed(isec, internal_relocs);
    return true;
}

static void
handle_local_syms_cleanup(struct bfd_link_info *info, Elf_Internal_Shdr *symtab_hdr,
                          Elf_Internal_Sym *local_syms)
{
    if (local_syms != NULL && symtab_hdr->contents != (unsigned char *)local_syms)
    {
        if (!info->keep_memory)
            free(local_syms);
        else
            symtab_hdr->contents = (unsigned char *)local_syms;
    }
}

static bool
process_bfd_stubs(struct bfd_link_info *info, bfd *ibfd, struct spu_link_hash_table *htab,
                  bool build)
{
    if (!is_spu_elf32_bfd(ibfd) || !has_valid_symbol_table(ibfd))
        return true;
    
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
    Elf_Internal_Sym *local_syms = NULL;
    
    for (asection *isec = ibfd->sections; isec != NULL; isec = isec->next)
    {
        if (!process_section_relocations(info, ibfd, isec, &local_syms, htab, build))
        {
            free_local_syms_if_needed(symtab_hdr, local_syms);
            return false;
        }
    }
    
    handle_local_syms_cleanup(info, symtab_hdr, local_syms);
    return true;
}

static bool
process_stubs(struct bfd_link_info *info, bool build)
{
    struct spu_link_hash_table *htab = spu_hash_table(info);
    
    for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
        if (!process_bfd_stubs(info, ibfd, htab, build))
            return false;
    }
    
    return true;
}

/* Allocate space for overlay call and return stubs.
   Return 0 on error, 1 if no overlays, 2 otherwise.  */

int
spu_elf_size_stubs (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab;
  bfd *ibfd;

  if (!process_stubs (info, false))
    return 0;

  htab = spu_hash_table (info);
  elf_link_hash_traverse (&htab->elf, allocate_spuear_stubs, info);
  if (htab->stub_err)
    return 0;

  ibfd = info->input_bfds;
  
  if (htab->stub_count != NULL)
    {
      if (!create_stub_sections(htab, ibfd))
        return 0;
    }

  if (!create_overlay_tables(htab, ibfd))
    return 0;

  if (!create_toe_section(htab, ibfd))
    return 0;

  return 2;
}

static bool
create_stub_sections(struct spu_link_hash_table *htab, bfd *ibfd)
{
  bfd_size_type amt;
  unsigned int i;
  
  amt = (htab->num_overlays + 1) * sizeof (*htab->stub_sec);
  htab->stub_sec = bfd_zmalloc (amt);
  if (htab->stub_sec == NULL)
    return false;

  if (!create_main_stub_section(htab, ibfd))
    return false;

  for (i = 0; i < htab->num_overlays; ++i)
    {
      if (!create_overlay_stub_section(htab, ibfd, i))
        return false;
    }
  
  return true;
}

static bool
create_main_stub_section(struct spu_link_hash_table *htab, bfd *ibfd)
{
  #define STUB_FLAGS (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY)
  #define SOFT_ICACHE_EXTRA_SIZE 16
  
  asection *stub = bfd_make_section_anyway_with_flags (ibfd, ".stub", STUB_FLAGS);
  htab->stub_sec[0] = stub;
  
  if (stub == NULL || !bfd_set_section_alignment (stub, ovl_stub_size_log2 (htab->params)))
    return false;
    
  stub->size = htab->stub_count[0] * ovl_stub_size (htab->params);
  if (htab->params->ovly_flavour == ovly_soft_icache)
    stub->size += htab->stub_count[0] * SOFT_ICACHE_EXTRA_SIZE;
    
  return true;
}

static bool
create_overlay_stub_section(struct spu_link_hash_table *htab, bfd *ibfd, unsigned int i)
{
  #define STUB_FLAGS (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY)
  
  asection *osec = htab->ovl_sec[i];
  unsigned int ovl = spu_elf_section_data (osec)->u.o.ovl_index;
  asection *stub = bfd_make_section_anyway_with_flags (ibfd, ".stub", STUB_FLAGS);
  
  htab->stub_sec[ovl] = stub;
  if (stub == NULL || !bfd_set_section_alignment (stub, ovl_stub_size_log2 (htab->params)))
    return false;
    
  stub->size = htab->stub_count[ovl] * ovl_stub_size (htab->params);
  return true;
}

static bool
create_overlay_tables(struct spu_link_hash_table *htab, bfd *ibfd)
{
  if (htab->params->ovly_flavour == ovly_soft_icache)
    return create_soft_icache_tables(htab, ibfd);
  else if (htab->stub_count == NULL)
    return true;
  else
    return create_standard_ovtab(htab, ibfd);
}

static bool
create_soft_icache_tables(struct spu_link_hash_table *htab, bfd *ibfd)
{
  #define OVTAB_FLAGS SEC_ALLOC
  #define OVINI_FLAGS (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY)
  #define ALIGNMENT_4 4
  #define TAG_ARRAY_SIZE 16
  #define REWRITE_TO_SIZE 16
  #define OVINI_SIZE 16
  
  htab->ovtab = bfd_make_section_anyway_with_flags (ibfd, ".ovtab", OVTAB_FLAGS);
  if (htab->ovtab == NULL || !bfd_set_section_alignment (htab->ovtab, ALIGNMENT_4))
    return false;

  htab->ovtab->size = (TAG_ARRAY_SIZE + REWRITE_TO_SIZE + (16 << htab->fromelem_size_log2))
                      << htab->num_lines_log2;

  htab->init = bfd_make_section_anyway_with_flags (ibfd, ".ovini", OVINI_FLAGS);
  if (htab->init == NULL || !bfd_set_section_alignment (htab->init, ALIGNMENT_4))
    return false;

  htab->init->size = OVINI_SIZE;
  return true;
}

static bool
create_standard_ovtab(struct spu_link_hash_table *htab, bfd *ibfd)
{
  #define OVTAB_FLAGS (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY)
  #define ALIGNMENT_4 4
  #define OVLY_TABLE_ENTRY_SIZE 16
  #define OVLY_TABLE_HEADER_SIZE 16
  #define BUF_TABLE_ENTRY_SIZE 4
  
  htab->ovtab = bfd_make_section_anyway_with_flags (ibfd, ".ovtab", OVTAB_FLAGS);
  if (htab->ovtab == NULL || !bfd_set_section_alignment (htab->ovtab, ALIGNMENT_4))
    return false;

  htab->ovtab->size = htab->num_overlays * OVLY_TABLE_ENTRY_SIZE + 
                      OVLY_TABLE_HEADER_SIZE + 
                      htab->num_buf * BUF_TABLE_ENTRY_SIZE;
  return true;
}

static bool
create_toe_section(struct spu_link_hash_table *htab, bfd *ibfd)
{
  #define TOE_FLAGS SEC_ALLOC
  #define ALIGNMENT_4 4
  #define TOE_SIZE 16
  
  htab->toe = bfd_make_section_anyway_with_flags (ibfd, ".toe", TOE_FLAGS);
  if (htab->toe == NULL || !bfd_set_section_alignment (htab->toe, ALIGNMENT_4))
    return false;
    
  htab->toe->size = TOE_SIZE;
  return true;
}

/* Called from ld to place overlay manager data sections.  This is done
   after the overlay manager itself is loaded, mainly so that the
   linker's htab->init section is placed after any other .ovl.init
   sections.  */

void
spu_elf_place_overlay_data (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  
  place_stub_sections(htab);
  place_init_section(htab);
  place_ovtab_section(htab);
  place_toe_section(htab);
}

static void
place_stub_sections(struct spu_link_hash_table *htab)
{
  if (htab->stub_sec == NULL)
    return;
    
  place_section(htab, htab->stub_sec[0], NULL, ".text");
  place_overlay_stubs(htab);
}

static void
place_overlay_stubs(struct spu_link_hash_table *htab)
{
  unsigned int i;
  
  for (i = 0; i < htab->num_overlays; ++i)
    {
      asection *osec = htab->ovl_sec[i];
      unsigned int ovl = spu_elf_section_data (osec)->u.o.ovl_index;
      place_section(htab, htab->stub_sec[ovl], osec, NULL);
    }
}

static void
place_init_section(struct spu_link_hash_table *htab)
{
  if (htab->params->ovly_flavour == ovly_soft_icache)
    place_section(htab, htab->init, NULL, ".ovl.init");
}

static void
place_ovtab_section(struct spu_link_hash_table *htab)
{
  if (htab->ovtab == NULL)
    return;
    
  const char *ovout = get_ovtab_output_section(htab);
  place_section(htab, htab->ovtab, NULL, ovout);
}

static const char*
get_ovtab_output_section(struct spu_link_hash_table *htab)
{
  if (htab->params->ovly_flavour == ovly_soft_icache)
    return ".bss";
  return ".data";
}

static void
place_toe_section(struct spu_link_hash_table *htab)
{
  if (htab->toe != NULL)
    place_section(htab, htab->toe, NULL, ".toe");
}

static void
place_section(struct spu_link_hash_table *htab, asection *sec, 
              asection *after, const char *output)
{
  (*htab->params->place_spu_section) (sec, after, output);
}

/* Functions to handle embedded spu_ovl.o object.  */

static void *ovl_mgr_open(struct bfd *nbfd ATTRIBUTE_UNUSED, void *stream)
{
    return stream;
}

static file_ptr
ovl_mgr_pread (struct bfd *abfd ATTRIBUTE_UNUSED,
	       void *stream,
	       void *buf,
	       file_ptr nbytes,
	       file_ptr offset)
{
  struct _ovl_stream *os = (struct _ovl_stream *) stream;
  size_t max = (const char *) os->end - (const char *) os->start;

  if ((ufile_ptr) offset >= max)
    return 0;

  size_t count = nbytes;
  if (count > max - offset)
    count = max - offset;

  memcpy (buf, (const char *) os->start + offset, count);
  return count;
}

static int
ovl_mgr_stat (struct bfd *abfd ATTRIBUTE_UNUSED,
	      void *stream,
	      struct stat *sb)
{
  struct _ovl_stream *os = (struct _ovl_stream *) stream;

  memset (sb, 0, sizeof (*sb));
  sb->st_size = (const char *) os->end - (const char *) os->start;
  return 0;
}

bool
spu_elf_open_builtin_lib (bfd **ovl_bfd, const struct _ovl_stream *stream)
{
  const char *BUILTIN_OVL_MGR_NAME = "builtin ovl_mgr";
  const char *SPU_ELF_FORMAT = "elf32-spu";
  
  *ovl_bfd = bfd_openr_iovec (BUILTIN_OVL_MGR_NAME,
			      SPU_ELF_FORMAT,
			      ovl_mgr_open,
			      (void *) stream,
			      ovl_mgr_pread,
			      NULL,
			      ovl_mgr_stat);
  return *ovl_bfd != NULL;
}

static unsigned int
overlay_index (asection *sec)
{
  if (sec == NULL || sec->output_section == bfd_abs_section_ptr)
    return 0;
  
  return spu_elf_section_data (sec->output_section)->u.o.ovl_index;
}

/* Define an STT_OBJECT symbol.  */

static void set_hash_entry_as_defined(struct elf_link_hash_entry *h, struct spu_link_hash_table *htab)
{
    h->root.type = bfd_link_hash_defined;
    h->root.u.def.section = htab->ovtab;
    h->type = STT_OBJECT;
    h->ref_regular = 1;
    h->def_regular = 1;
    h->ref_regular_nonweak = 1;
    h->non_elf = 0;
}

static struct elf_link_hash_entry *handle_definition_error(struct elf_link_hash_entry *h, bool is_script)
{
    if (is_script)
    {
        _bfd_error_handler(_("you are not allowed to define %s in a script"),
                          h->root.root.string);
    }
    else
    {
        _bfd_error_handler(_("%pB is not allowed to define %s"),
                          h->root.u.def.section->owner,
                          h->root.root.string);
    }
    bfd_set_error(bfd_error_bad_value);
    return NULL;
}

static bool is_already_defined(struct elf_link_hash_entry *h)
{
    return h->root.type == bfd_link_hash_defined && h->def_regular;
}

static struct elf_link_hash_entry *
define_ovtab_symbol(struct spu_link_hash_table *htab, const char *name)
{
    struct elf_link_hash_entry *h;

    h = elf_link_hash_lookup(&htab->elf, name, true, false, false);
    if (h == NULL)
        return NULL;

    if (!is_already_defined(h))
    {
        set_hash_entry_as_defined(h, htab);
        return h;
    }

    if (h->root.u.def.section->owner != NULL)
        return handle_definition_error(h, false);

    return handle_definition_error(h, true);
}

/* Fill in all stubs and the overlay tables.  */

static bool
validate_overlay_entry(struct elf_link_hash_entry *h)
{
  if (h == NULL)
    return true;
    
  if ((h->root.type != bfd_link_hash_defined && 
       h->root.type != bfd_link_hash_defweak) || 
      !h->def_regular)
    return true;
    
  asection *s = h->root.u.def.section->output_section;
  if (spu_elf_section_data(s)->u.o.ovl_index)
  {
    _bfd_error_handler(_("%s in overlay section"), h->root.root.string);
    bfd_set_error(bfd_error_bad_value);
    return false;
  }
  
  return true;
}

static bool
validate_overlay_entries(struct spu_link_hash_table *htab)
{
  if (htab->num_overlays == 0)
    return true;
    
  for (unsigned int i = 0; i < 2; i++)
  {
    if (!validate_overlay_entry(htab->ovly_entry[i]))
      return false;
  }
  
  return true;
}

static bool
allocate_stub_section(asection *stub_sec)
{
  if (stub_sec->size == 0)
    return true;
    
  stub_sec->contents = bfd_zalloc(stub_sec->owner, stub_sec->size);
  if (stub_sec->contents == NULL)
    return false;
    
  stub_sec->alloced = 1;
  stub_sec->rawsize = stub_sec->size;
  stub_sec->size = 0;
  
  return true;
}

static bool
allocate_stub_sections(struct spu_link_hash_table *htab)
{
  for (unsigned int i = 0; i <= htab->num_overlays; i++)
  {
    if (!allocate_stub_section(htab->stub_sec[i]))
      return false;
  }
  
  return true;
}

static bool
verify_stub_size(asection *stub_sec)
{
  if (stub_sec->size != stub_sec->rawsize)
  {
    _bfd_error_handler(_("stubs don't match calculated size"));
    bfd_set_error(bfd_error_bad_value);
    return false;
  }
  
  stub_sec->rawsize = 0;
  return true;
}

static bool
verify_stub_sizes(struct spu_link_hash_table *htab)
{
  for (unsigned int i = 0; i <= htab->num_overlays; i++)
  {
    if (!verify_stub_size(htab->stub_sec[i]))
      return false;
  }
  
  return true;
}

static bool
build_stub_sections(struct bfd_link_info *info, struct spu_link_hash_table *htab)
{
  if (htab->stub_sec == NULL)
    return true;
    
  if (!allocate_stub_sections(htab))
    return false;
    
  process_stubs(info, true);
  
  if (!htab->stub_err)
    elf_link_hash_traverse(&htab->elf, build_spuear_stubs, info);
    
  if (htab->stub_err)
  {
    _bfd_error_handler(_("overlay stub relocation overflow"));
    bfd_set_error(bfd_error_bad_value);
    return false;
  }
  
  return verify_stub_sizes(htab);
}

static bool
allocate_ovtab(struct spu_link_hash_table *htab)
{
  htab->ovtab->contents = bfd_zalloc(htab->ovtab->owner, htab->ovtab->size);
  if (htab->ovtab->contents == NULL)
    return false;
    
  htab->ovtab->alloced = 1;
  return true;
}

#define ICACHE_TAG_ARRAY_SIZE (16 << htab->num_lines_log2)
#define ICACHE_REWRITE_FROM_SIZE (16 << (htab->fromelem_size_log2 + htab->num_lines_log2))
#define ICACHE_LINE_SIZE (1 << htab->line_size_log2)
#define ICACHE_CACHE_SIZE (1 << (htab->num_lines_log2 + htab->line_size_log2))
#define OVERLAY_TABLE_ENTRY_SIZE 16
#define OVERLAY_BUFFER_ENTRY_SIZE 4

static bool
define_symbol_with_value(struct spu_link_hash_table *htab, const char *name, 
                         bfd_vma value, asection *section, bfd_vma size)
{
  struct elf_link_hash_entry *h = define_ovtab_symbol(htab, name);
  if (h == NULL)
    return false;
    
  h->root.u.def.value = value;
  h->root.u.def.section = section;
  h->size = size;
  
  return true;
}

static bool
define_abs_symbol(struct spu_link_hash_table *htab, const char *name, bfd_vma value)
{
  return define_symbol_with_value(htab, name, value, bfd_abs_section_ptr, 0);
}

static bool
setup_icache_tag_array(struct spu_link_hash_table *htab, bfd_vma *off)
{
  if (!define_symbol_with_value(htab, "__icache_tag_array", 0, 
                                htab->ovtab->output_section, ICACHE_TAG_ARRAY_SIZE))
    return false;
    
  *off = ICACHE_TAG_ARRAY_SIZE;
  
  return define_abs_symbol(htab, "__icache_tag_array_size", ICACHE_TAG_ARRAY_SIZE);
}

static bool
setup_icache_rewrite_to(struct spu_link_hash_table *htab, bfd_vma *off)
{
  if (!define_symbol_with_value(htab, "__icache_rewrite_to", *off, 
                                htab->ovtab->output_section, ICACHE_TAG_ARRAY_SIZE))
    return false;
    
  *off += ICACHE_TAG_ARRAY_SIZE;
  
  return define_abs_symbol(htab, "__icache_rewrite_to_size", ICACHE_TAG_ARRAY_SIZE);
}

static bool
setup_icache_rewrite_from(struct spu_link_hash_table *htab, bfd_vma *off)
{
  if (!define_symbol_with_value(htab, "__icache_rewrite_from", *off, 
                                htab->ovtab->output_section, ICACHE_REWRITE_FROM_SIZE))
    return false;
    
  *off += ICACHE_REWRITE_FROM_SIZE;
  
  if (!define_abs_symbol(htab, "__icache_rewrite_from_size", ICACHE_REWRITE_FROM_SIZE))
    return false;
    
  return define_abs_symbol(htab, "__icache_log2_fromelemsize", htab->fromelem_size_log2);
}

static bool
setup_icache_base_params(struct spu_link_hash_table *htab)
{
  if (!define_symbol_with_value(htab, "__icache_base", htab->ovl_sec[0]->vma, 
                                bfd_abs_section_ptr, htab->num_buf << htab->line_size_log2))
    return false;
    
  if (!define_abs_symbol(htab, "__icache_linesize", ICACHE_LINE_SIZE))
    return false;
    
  if (!define_abs_symbol(htab, "__icache_log2_linesize", htab->line_size_log2))
    return false;
    
  return define_abs_symbol(htab, "__icache_neg_log2_linesize", -htab->line_size_log2);
}

static bool
setup_icache_cache_params(struct spu_link_hash_table *htab)
{
  if (!define_abs_symbol(htab, "__icache_cachesize", ICACHE_CACHE_SIZE))
    return false;
    
  if (!define_abs_symbol(htab, "__icache_log2_cachesize", 
                         htab->num_lines_log2 + htab->line_size_log2))
    return false;
    
  return define_abs_symbol(htab, "__icache_neg_log2_cachesize", 
                           -(htab->num_lines_log2 + htab->line_size_log2));
}

static bool
setup_icache_init(struct spu_link_hash_table *htab)
{
  if (htab->init == NULL || htab->init->size == 0)
    return true;
    
  htab->init->contents = bfd_zalloc(htab->init->owner, htab->init->size);
  if (htab->init->contents == NULL)
    return false;
    
  htab->init->alloced = 1;
  
  return define_symbol_with_value(htab, "__icache_fileoff", 0, htab->init, 8);
}

static bool
setup_soft_icache_ovtab(struct spu_link_hash_table *htab)
{
  bfd_vma off;
  
  if (!setup_icache_tag_array(htab, &off))
    return false;
    
  if (!setup_icache_rewrite_to(htab, &off))
    return false;
    
  if (!setup_icache_rewrite_from(htab, &off))
    return false;
    
  if (!setup_icache_base_params(htab))
    return false;
    
  if (!setup_icache_cache_params(htab))
    return false;
    
  return setup_icache_init(htab);
}

static void
write_overlay_entry(struct spu_link_hash_table *htab, asection *s, bfd_byte *p)
{
  unsigned int ovl_index = spu_elf_section_data(s)->u.o.ovl_index;
  
  if (ovl_index == 0)
    return;
    
  unsigned long off = ovl_index * OVERLAY_TABLE_ENTRY_SIZE;
  unsigned int ovl_buf = spu_elf_section_data(s)->u.o.ovl_buf;
  
  bfd_put_32(htab->ovtab->owner, s->vma, p + off);
  bfd_put_32(htab->ovtab->owner, (s->size + 15) & -16, p + off + 4);
  bfd_put_32(htab->ovtab->owner, ovl_buf, p + off + 12);
}

static void
write_overlay_table(struct spu_link_hash_table *htab, bfd_byte *p)
{
  p[7] = 1;
  
  bfd *obfd = htab->ovtab->output_section->owner;
  for (asection *s = obfd->sections; s != NULL; s = s->next)
  {
    write_overlay_entry(htab, s, p);
  }
}

static bool
define_overlay_table_symbols(struct spu_link_hash_table *htab)
{
  bfd_vma table_start = OVERLAY_TABLE_ENTRY_SIZE;
  bfd_vma table_end = htab->num_overlays * OVERLAY_TABLE_ENTRY_SIZE + table_start;
  bfd_vma buf_table_start = table_end;
  bfd_vma buf_table_end = buf_table_start + htab->num_buf * OVERLAY_BUFFER_ENTRY_SIZE;
  
  if (!define_symbol_with_value(htab, "_ovly_table", table_start, 
                                htab->ovtab->output_section, 
                                htab->num_overlays * OVERLAY_TABLE_ENTRY_SIZE))
    return false;
    
  if (!define_symbol_with_value(htab, "_ovly_table_end", table_end, 
                                htab->ovtab->output_section, 0))
    return false;
    
  if (!define_symbol_with_value(htab, "_ovly_buf_table", buf_table_start, 
                                htab->ovtab->output_section, 
                                htab->num_buf * OVERLAY_BUFFER_ENTRY_SIZE))
    return false;
    
  return define_symbol_with_value(htab, "_ovly_buf_table_end", buf_table_end, 
                                  htab->ovtab->output_section, 0);
}

static bool
setup_standard_ovtab(struct spu_link_hash_table *htab)
{
  bfd_byte *p = htab->ovtab->contents;
  
  write_overlay_table(htab, p);
  
  return define_overlay_table_symbols(htab);
}

static bool
setup_ovtab_content(struct spu_link_hash_table *htab)
{
  if (htab->params->ovly_flavour == ovly_soft_icache)
    return setup_soft_icache_ovtab(htab);
  else
    return setup_standard_ovtab(htab);
}

static bool
define_ear_symbol(struct spu_link_hash_table *htab)
{
  return define_symbol_with_value(htab, "_EAR_", 0, htab->toe, 16);
}

static bool
spu_elf_build_stubs(struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table(info);
  
  if (!validate_overlay_entries(htab))
    return false;
    
  if (!build_stub_sections(info, htab))
    return false;
    
  if (htab->ovtab == NULL || htab->ovtab->size == 0)
    return true;
    
  if (!allocate_ovtab(htab))
    return false;
    
  if (!setup_ovtab_content(htab))
    return false;
    
  return define_ear_symbol(htab);
}

/* Check that all loadable section VMAs lie in the range
   LO .. HI inclusive, and stash some parameters for --auto-overlay.  */

asection *
spu_elf_check_vma (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *abfd = info->output_bfd;
  bfd_vma hi = htab->params->local_store_hi;
  bfd_vma lo = htab->params->local_store_lo;

  htab->local_store = hi + 1 - lo;

  return find_invalid_vma_section(elf_seg_map(abfd), lo, hi);
}

static asection *
find_invalid_vma_section(struct elf_segment_map *m, bfd_vma lo, bfd_vma hi)
{
  for (; m != NULL; m = m->next)
  {
    if (m->p_type != PT_LOAD)
      continue;
    
    asection *invalid_section = check_load_segment_sections(m, lo, hi);
    if (invalid_section != NULL)
      return invalid_section;
  }
  
  return NULL;
}

static asection *
check_load_segment_sections(struct elf_segment_map *m, bfd_vma lo, bfd_vma hi)
{
  unsigned int i;
  
  for (i = 0; i < m->count; i++)
  {
    asection *section = m->sections[i];
    if (is_invalid_section(section, lo, hi))
      return section;
  }
  
  return NULL;
}

static bfd_boolean
is_invalid_section(asection *section, bfd_vma lo, bfd_vma hi)
{
  if (section->size == 0)
    return FALSE;
    
  bfd_vma section_start = section->vma;
  bfd_vma section_end = section_start + section->size - 1;
  
  return section_start < lo || section_start > hi || section_end > hi;
}

/* OFFSET in SEC (presumably) is the beginning of a function prologue.
   Search for stack adjusting insns, and return the sp delta.
   If a store of lr is found save the instruction offset to *LR_STORE.
   If a stack adjusting instruction is found, save that offset to
   *SP_ADJUST.  */

static int
find_function_stack_adjust (asection *sec,
			    bfd_vma offset,
			    bfd_vma *lr_store,
			    bfd_vma *sp_adjust)
{
  int32_t reg[128];

  memset (reg, 0, sizeof (reg));
  for ( ; offset + 4 <= sec->size; offset += 4)
    {
      unsigned char buf[4];
      int rt, ra;
      uint32_t imm;

      if (!bfd_get_section_contents (sec->owner, sec, buf, offset, 4))
	break;

      rt = buf[3] & 0x7f;
      ra = ((buf[2] & 0x3f) << 1) | (buf[3] >> 7);

      if (buf[0] == 0x24)
	{
	  if (rt == 0 && ra == 1)
	    *lr_store = offset;
	  continue;
	}

      imm = (buf[1] << 9) | (buf[2] << 1) | (buf[3] >> 7);

      if (buf[0] == 0x1c)
	{
	  imm >>= 7;
	  imm = (imm ^ 0x200) - 0x200;
	  reg[rt] = reg[ra] + imm;

	  if (rt == 1)
	    {
	      if (reg[rt] > 0)
		break;
	      *sp_adjust = offset;
	      return reg[rt];
	    }
	}
      else if (buf[0] == 0x18 && (buf[1] & 0xe0) == 0)
	{
	  int rb = ((buf[1] & 0x1f) << 2) | ((buf[2] & 0xc0) >> 6);

	  reg[rt] = reg[ra] + reg[rb];
	  if (rt == 1)
	    {
	      if (reg[rt] > 0)
		break;
	      *sp_adjust = offset;
	      return reg[rt];
	    }
	}
      else if (buf[0] == 0x08 && (buf[1] & 0xe0) == 0)
	{
	  int rb = ((buf[1] & 0x1f) << 2) | ((buf[2] & 0xc0) >> 6);

	  reg[rt] = reg[rb] - reg[ra];
	  if (rt == 1)
	    {
	      if (reg[rt] > 0)
		break;
	      *sp_adjust = offset;
	      return reg[rt];
	    }
	}
      else if ((buf[0] & 0xfc) == 0x40)
	{
	  if (buf[0] >= 0x42)
	    imm |= (buf[0] & 1) << 17;
	  else
	    {
	      imm &= 0xffff;

	      if (buf[0] == 0x40)
		{
		  if ((buf[1] & 0x80) == 0)
		    continue;
		  imm = (imm ^ 0x8000) - 0x8000;
		}
	      else if ((buf[1] & 0x80) == 0)
		imm <<= 16;
	    }
	  reg[rt] = imm;
	  continue;
	}
      else if (buf[0] == 0x60 && (buf[1] & 0x80) != 0)
	{
	  reg[rt] |= imm & 0xffff;
	  continue;
	}
      else if (buf[0] == 0x04)
	{
	  imm >>= 7;
	  imm = (imm ^ 0x200) - 0x200;
	  reg[rt] = reg[ra] | imm;
	  continue;
	}
      else if (buf[0] == 0x32 && (buf[1] & 0x80) != 0)
	{
	  reg[rt] = (  ((imm & 0x8000) ? 0xff000000 : 0)
		     | ((imm & 0x4000) ? 0x00ff0000 : 0)
		     | ((imm & 0x2000) ? 0x0000ff00 : 0)
		     | ((imm & 0x1000) ? 0x000000ff : 0));
	  continue;
	}
      else if (buf[0] == 0x16)
	{
	  imm >>= 7;
	  imm &= 0xff;
	  imm |= imm << 8;
	  imm |= imm << 16;
	  reg[rt] = reg[ra] & imm;
	  continue;
	}
      else if (buf[0] == 0x33 && imm == 1)
	{
	  reg[rt] = 0;
	  continue;
	}
      else if (is_branch (buf) || is_indirect_branch (buf))
	break;
    }

  return 0;
}

/* qsort predicate to sort symbols by section and value.  */

static Elf_Internal_Sym *sort_syms_syms;
static asection **sort_syms_psecs;

static int compare_sections(asection *sec1, asection *sec2)
{
    return sec1->index - sec2->index;
}

static int compare_values(bfd_signed_vma val1, bfd_signed_vma val2)
{
    bfd_signed_vma delta = val1 - val2;
    if (delta == 0)
        return 0;
    return delta < 0 ? -1 : 1;
}

static int compare_pointers(const void *ptr1, const void *ptr2)
{
    return ptr1 < ptr2 ? -1 : 1;
}

static asection* get_section_for_symbol(Elf_Internal_Sym *sym)
{
    return sort_syms_psecs[sym - sort_syms_syms];
}

static int sort_syms(const void *a, const void *b)
{
    Elf_Internal_Sym *const *s1 = a;
    Elf_Internal_Sym *const *s2 = b;
    asection *sec1 = get_section_for_symbol(*s1);
    asection *sec2 = get_section_for_symbol(*s2);
    int result;

    if (sec1 != sec2)
        return compare_sections(sec1, sec2);

    result = compare_values((*s1)->st_value, (*s2)->st_value);
    if (result != 0)
        return result;

    result = compare_values((*s2)->st_size, (*s1)->st_size);
    if (result != 0)
        return result;

    return compare_pointers(*s1, *s2);
}

/* Allocate a struct spu_elf_stack_info with MAX_FUN struct function_info
   entries for section SEC.  */

static struct spu_elf_stack_info *
alloc_stack_info (asection *sec, int max_fun)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  bfd_size_type amt;

  amt = sizeof (struct spu_elf_stack_info);
  amt += (max_fun - 1) * sizeof (struct function_info);
  sec_data->u.i.stack_info = bfd_zmalloc (amt);
  if (sec_data->u.i.stack_info != NULL)
    sec_data->u.i.stack_info->max_fun = max_fun;
  return sec_data->u.i.stack_info;
}

/* Add a new struct function_info describing a (part of a) function
   starting at SYM_H.  Keep the array sorted by address.  */

static void extract_symbol_info(void *sym_h, bool global, bfd_vma *off, bfd_vma *size)
{
  if (!global)
    {
      Elf_Internal_Sym *sym = sym_h;
      *off = sym->st_value;
      *size = sym->st_size;
    }
  else
    {
      struct elf_link_hash_entry *h = sym_h;
      *off = h->root.u.def.value;
      *size = h->size;
    }
}

static int find_function_index(struct spu_elf_stack_info *sinfo, bfd_vma off)
{
  int i;
  for (i = sinfo->num_fun; --i >= 0; )
    if (sinfo->fun[i].lo <= off)
      break;
  return i;
}

static struct function_info *update_existing_function(struct spu_elf_stack_info *sinfo, 
                                                      int i, 
                                                      bfd_vma off, 
                                                      bfd_vma size,
                                                      void *sym_h, 
                                                      bool global, 
                                                      bool is_func)
{
  if (sinfo->fun[i].lo == off)
    {
      if (global && !sinfo->fun[i].global)
        {
          sinfo->fun[i].global = true;
          sinfo->fun[i].u.h = sym_h;
        }
      if (is_func)
        sinfo->fun[i].is_func = true;
      return &sinfo->fun[i];
    }
  else if (sinfo->fun[i].hi > off && size == 0)
    return &sinfo->fun[i];
  
  return NULL;
}

#define INITIAL_STACK_INFO_SIZE 20
#define STACK_INFO_GROWTH_FACTOR 20

static struct spu_elf_stack_info *ensure_stack_info_capacity(struct spu_elf_stack_info *sinfo,
                                                             struct _spu_elf_section_data *sec_data)
{
  if (sinfo->num_fun >= sinfo->max_fun)
    {
      bfd_size_type amt = sizeof (struct spu_elf_stack_info);
      bfd_size_type old = amt;

      old += (sinfo->max_fun - 1) * sizeof (struct function_info);
      sinfo->max_fun += STACK_INFO_GROWTH_FACTOR + (sinfo->max_fun >> 1);
      amt += (sinfo->max_fun - 1) * sizeof (struct function_info);
      sinfo = bfd_realloc (sinfo, amt);
      if (sinfo == NULL)
        return NULL;
      memset ((char *) sinfo + old, 0, amt - old);
      sec_data->u.i.stack_info = sinfo;
    }
  return sinfo;
}

static void initialize_function_info(struct function_info *func,
                                     asection *sec,
                                     void *sym_h,
                                     bool global,
                                     bool is_func,
                                     bfd_vma off,
                                     bfd_vma size)
{
  func->is_func = is_func;
  func->global = global;
  func->sec = sec;
  if (global)
    func->u.h = sym_h;
  else
    func->u.sym = sym_h;
  func->lo = off;
  func->hi = off + size;
  func->lr_store = -1;
  func->sp_adjust = -1;
  func->stack = -find_function_stack_adjust(sec, off, &func->lr_store, &func->sp_adjust);
}

static struct function_info *
maybe_insert_function (asection *sec,
                      void *sym_h,
                      bool global,
                      bool is_func)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  int i;
  bfd_vma off, size;
  struct function_info *existing;

  if (sinfo == NULL)
    {
      sinfo = alloc_stack_info (sec, INITIAL_STACK_INFO_SIZE);
      if (sinfo == NULL)
        return NULL;
    }

  extract_symbol_info(sym_h, global, &off, &size);

  i = find_function_index(sinfo, off);

  if (i >= 0)
    {
      existing = update_existing_function(sinfo, i, off, size, sym_h, global, is_func);
      if (existing != NULL)
        return existing;
    }

  sinfo = ensure_stack_info_capacity(sinfo, sec_data);
  if (sinfo == NULL)
    return NULL;

  if (++i < sinfo->num_fun)
    memmove (&sinfo->fun[i + 1], &sinfo->fun[i],
            (sinfo->num_fun - i) * sizeof (sinfo->fun[i]));

  initialize_function_info(&sinfo->fun[i], sec, sym_h, global, is_func, off, size);

  sinfo->num_fun += 1;
  return &sinfo->fun[i];
}

/* Return the name of FUN.  */

static const char *
find_root_function(struct function_info *fun)
{
  while (fun->start != NULL)
    fun = fun->start;
  return fun;
}

static const char *
get_global_function_name(struct function_info *fun)
{
  return fun->u.h->root.root.string;
}

static const char *
create_unnamed_symbol_name(struct function_info *fun, asection *sec)
{
  size_t len = strlen(sec->name);
  char *name = bfd_malloc(len + 10);
  if (name == NULL)
    return "(null)";
  sprintf(name, "%s+%lx", sec->name,
          (unsigned long)fun->u.sym->st_value & 0xffffffff);
  return name;
}

static const char *
get_local_symbol_name(struct function_info *fun, asection *sec)
{
  bfd *ibfd = sec->owner;
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
  return bfd_elf_sym_name(ibfd, symtab_hdr, fun->u.sym, sec);
}

static const char *
func_name(struct function_info *fun)
{
  fun = find_root_function(fun);
  
  if (fun->global)
    return get_global_function_name(fun);
  
  asection *sec = fun->sec;
  
  if (fun->u.sym->st_name == 0)
    return create_unnamed_symbol_name(fun, sec);
  
  return get_local_symbol_name(fun, sec);
}

/* Read the instruction at OFF in SEC.  Return true iff the instruction
   is a nop, lnop, or stop 0 (all zero insn).  */

static bool
is_nop (asection *sec, bfd_vma off)
{
  unsigned char insn[4];

  if (off + 4 > sec->size
      || !bfd_get_section_contents (sec->owner, sec, insn, off, 4))
    return false;
  
  if ((insn[0] & 0xbf) == 0 && (insn[1] & 0xe0) == 0x20)
    return true;
  
  if (insn[0] == 0 && insn[1] == 0 && insn[2] == 0 && insn[3] == 0)
    return true;
  
  return false;
}

/* Extend the range of FUN to cover nop padding up to LIMIT.
   Return TRUE iff some instruction other than a NOP was found.  */

static bool
insns_at_end (struct function_info *fun, bfd_vma limit)
{
  bfd_vma off = (fun->hi + 3) & -4;

  while (off < limit && is_nop (fun->sec, off))
    off += 4;
  
  fun->hi = (off < limit) ? off : limit;
  return off < limit;
}

/* Check and fix overlapping function ranges.  Return TRUE iff there
   are gaps in the current info we have about functions in SEC.  */

static bool
check_function_overlap(struct spu_elf_stack_info *sinfo, int index, struct bfd_link_info *info)
{
    if (sinfo->fun[index - 1].hi <= sinfo->fun[index].lo)
        return false;
    
    const char *f1 = func_name(&sinfo->fun[index - 1]);
    const char *f2 = func_name(&sinfo->fun[index]);
    info->callbacks->einfo(_("warning: %s overlaps %s\n"), f1, f2);
    sinfo->fun[index - 1].hi = sinfo->fun[index].lo;
    return true;
}

static bool
check_function_gap(struct spu_elf_stack_info *sinfo, int index, unsigned int end_pos)
{
    return insns_at_end(&sinfo->fun[index], end_pos);
}

static bool
check_overlaps_and_gaps(struct spu_elf_stack_info *sinfo, struct bfd_link_info *info)
{
    bool gaps = false;
    
    for (int i = 1; i < sinfo->num_fun; i++)
    {
        if (!check_function_overlap(sinfo, i, info))
        {
            if (check_function_gap(sinfo, i - 1, sinfo->fun[i].lo))
                gaps = true;
        }
    }
    
    return gaps;
}

static bool
check_function_boundaries(struct spu_elf_stack_info *sinfo, asection *sec, struct bfd_link_info *info)
{
    bool gaps = false;
    int last_index = sinfo->num_fun - 1;
    
    if (sinfo->fun[0].lo != 0)
        gaps = true;
    
    if (sinfo->fun[last_index].hi > sec->size)
    {
        const char *f1 = func_name(&sinfo->fun[last_index]);
        info->callbacks->einfo(_("warning: %s exceeds section size\n"), f1);
        sinfo->fun[last_index].hi = sec->size;
    }
    else if (check_function_gap(sinfo, last_index, sec->size))
    {
        gaps = true;
    }
    
    return gaps;
}

static bool
check_function_ranges(asection *sec, struct bfd_link_info *info)
{
    struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
    struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
    
    if (sinfo == NULL)
        return false;
    
    if (sinfo->num_fun == 0)
        return true;
    
    bool gaps = check_overlaps_and_gaps(sinfo, info);
    bool boundary_gaps = check_function_boundaries(sinfo, sec, info);
    
    return gaps || boundary_gaps;
}

/* Search current function info for a function that contains address
   OFFSET in section SEC.  */

static struct function_info *
binary_search_function(struct spu_elf_stack_info *sinfo, bfd_vma offset)
{
  int lo = 0;
  int hi = sinfo->num_fun;
  
  while (lo < hi)
    {
      int mid = (lo + hi) / 2;
      if (offset < sinfo->fun[mid].lo)
        hi = mid;
      else if (offset >= sinfo->fun[mid].hi)
        lo = mid + 1;
      else
        return &sinfo->fun[mid];
    }
  
  return NULL;
}

static void
report_function_not_found(struct bfd_link_info *info, asection *sec, bfd_vma offset)
{
  info->callbacks->einfo(_("%pA:0x%v not found in function table\n"), sec, offset);
  bfd_set_error(bfd_error_bad_value);
}

static struct function_info *
find_function(asection *sec, bfd_vma offset, struct bfd_link_info *info)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  
  struct function_info *result = binary_search_function(sinfo, offset);
  
  if (result == NULL)
    report_function_not_found(info, sec, offset);
  
  return result;
}

/* Add CALLEE to CALLER call list if not already present.  Return TRUE
   if CALLEE was new.  If this function return FALSE, CALLEE should
   be freed.  */

static struct call_info* find_matching_callee(struct call_info **head, struct function_info *target_fun)
{
    struct call_info **pp = head;
    struct call_info *p;
    
    while ((p = *pp) != NULL)
    {
        if (p->fun == target_fun)
        {
            *pp = p->next;
            return p;
        }
        pp = &p->next;
    }
    return NULL;
}

static void update_existing_callee(struct call_info *existing, struct call_info *new_callee)
{
    existing->is_tail &= new_callee->is_tail;
    if (!existing->is_tail)
    {
        existing->fun->start = NULL;
        existing->fun->is_func = true;
    }
    existing->count += new_callee->count;
}

static void move_callee_to_front(struct call_info **head, struct call_info *callee)
{
    callee->next = *head;
    *head = callee;
}

static bool insert_callee(struct function_info *caller, struct call_info *callee)
{
    struct call_info *existing = find_matching_callee(&caller->call_list, callee->fun);
    
    if (existing != NULL)
    {
        update_existing_callee(existing, callee);
        move_callee_to_front(&caller->call_list, existing);
        return false;
    }
    
    move_callee_to_front(&caller->call_list, callee);
    return true;
}

/* Copy CALL and insert the copy into CALLER.  */

static bool
copy_callee (struct function_info *caller, const struct call_info *call)
{
  struct call_info *callee = bfd_malloc (sizeof (*callee));
  if (callee == NULL)
    return false;
  
  *callee = *call;
  if (!insert_callee (caller, callee))
    free (callee);
  
  return true;
}

/* We're only interested in code sections.  Testing SEC_IN_MEMORY excludes
   overlay stub sections.  */

static bool
interesting_section (asection *s)
{
  #define REQUIRED_FLAGS (SEC_ALLOC | SEC_LOAD | SEC_CODE)
  #define ALL_REQUIRED_FLAGS (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_IN_MEMORY)
  
  if (s->output_section == bfd_abs_section_ptr) {
    return false;
  }
  
  if (s->size == 0) {
    return false;
  }
  
  return (s->flags & ALL_REQUIRED_FLAGS) == REQUIRED_FLAGS;
  
  #undef REQUIRED_FLAGS
  #undef ALL_REQUIRED_FLAGS
}

/* Rummage through the relocs for SEC, looking for function calls.
   If CALL_TREE is true, fill in call graph.  If CALL_TREE is false,
   mark destination symbols on calls as being functions.  Also
   look at branches, which may be tail calls or go to hot/cold
   section part of same function.  */

static bool
process_relocation(asection *sec,
                  struct bfd_link_info *info,
                  Elf_Internal_Rela *irela,
                  void *psyms,
                  int call_tree,
                  unsigned int *priority,
                  bool *is_call,
                  bool *nonbranch,
                  static bool *warned)
{
    enum elf_spu_reloc_type r_type;
    unsigned int r_indx;
    asection *sym_sec;
    Elf_Internal_Sym *sym;
    struct elf_link_hash_entry *h;
    
    r_type = ELF32_R_TYPE(irela->r_info);
    *nonbranch = r_type != R_SPU_REL16 && r_type != R_SPU_ADDR16;
    
    r_indx = ELF32_R_SYM(irela->r_info);
    if (!get_sym_h(&h, &sym, &sym_sec, psyms, r_indx, sec->owner))
        return false;
    
    if (sym_sec == NULL || sym_sec->output_section == bfd_abs_section_ptr)
        return true;
    
    if (!*nonbranch) {
        unsigned char insn[4];
        
        if (!bfd_get_section_contents(sec->owner, sec, insn, irela->r_offset, 4))
            return false;
        
        if (is_branch(insn)) {
            *is_call = (insn[0] & 0xfd) == 0x31;
            *priority = insn[1] & 0x0f;
            *priority <<= 8;
            *priority |= insn[2];
            *priority <<= 8;
            *priority |= insn[3];
            *priority >>= 7;
            
            if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE))
                != (SEC_ALLOC | SEC_LOAD | SEC_CODE)) {
                if (!*warned) {
                    info->callbacks->einfo(
                        _("%pB(%pA+0x%v): call to non-code section"
                          " %pB(%pA), analysis incomplete\n"),
                        sec->owner, sec, irela->r_offset,
                        sym_sec->owner, sym_sec);
                    *warned = true;
                }
                return true;
            }
        } else {
            *nonbranch = true;
            if (is_hint(insn))
                return true;
        }
    }
    
    if (*nonbranch) {
        unsigned int sym_type = h ? h->type : ELF_ST_TYPE(sym->st_info);
        
        if (sym_type == STT_FUNC) {
            if (call_tree && spu_hash_table(info)->params->auto_overlay)
                spu_hash_table(info)->non_ovly_stub += 1;
            return true;
        }
        
        if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE))
            != (SEC_ALLOC | SEC_LOAD | SEC_CODE))
            return true;
    }
    
    return false;
}

static bool
handle_non_call_tree(asection *sym_sec,
                    Elf_Internal_Rela *irela,
                    struct elf_link_hash_entry *h,
                    Elf_Internal_Sym *sym,
                    bfd_vma val,
                    bool is_call)
{
    struct function_info *fun;
    
    if (irela->r_addend != 0) {
        Elf_Internal_Sym *fake = bfd_zmalloc(sizeof(*fake));
        if (fake == NULL)
            return false;
        fake->st_value = val;
        fake->st_shndx = _bfd_elf_section_from_bfd_section(sym_sec->owner, sym_sec);
        sym = fake;
    }
    
    if (sym)
        fun = maybe_insert_function(sym_sec, sym, false, is_call);
    else
        fun = maybe_insert_function(sym_sec, h, true, is_call);
    
    if (fun == NULL)
        return false;
    
    if (irela->r_addend != 0 && fun->u.sym != sym)
        free(sym);
    
    return true;
}

static struct function_info *
find_start_function(struct function_info *fun)
{
    while (fun->start)
        fun = fun->start;
    return fun;
}

static void
update_callee_function_state(struct call_info *callee,
                            struct function_info *caller,
                            asection *sec,
                            asection *sym_sec,
                            bool is_call)
{
    if (is_call || callee->fun->is_func || callee->fun->stack != 0)
        return;
    
    if (sec->owner != sym_sec->owner) {
        callee->fun->start = NULL;
        callee->fun->is_func = true;
        return;
    }
    
    if (callee->fun->start == NULL) {
        struct function_info *caller_start = find_start_function(caller);
        if (caller_start != callee->fun)
            callee->fun->start = caller_start;
    } else {
        struct function_info *callee_start = find_start_function(callee->fun);
        struct function_info *caller_start = find_start_function(caller);
        
        if (caller_start != callee_start) {
            callee->fun->start = NULL;
            callee->fun->is_func = true;
        }
    }
}

static bool
handle_call_tree(asection *sec,
                asection *sym_sec,
                struct bfd_link_info *info,
                Elf_Internal_Rela *irela,
                bfd_vma val,
                unsigned int priority,
                bool is_call,
                bool nonbranch)
{
    struct function_info *caller;
    struct call_info *callee;
    
    caller = find_function(sec, irela->r_offset, info);
    if (caller == NULL)
        return false;
    
    callee = bfd_malloc(sizeof *callee);
    if (callee == NULL)
        return false;
    
    callee->fun = find_function(sym_sec, val, info);
    if (callee->fun == NULL)
        return false;
    
    callee->is_tail = !is_call;
    callee->is_pasted = false;
    callee->broken_cycle = false;
    callee->priority = priority;
    callee->count = nonbranch ? 0 : 1;
    
    if (callee->fun->last_caller != sec) {
        callee->fun->last_caller = sec;
        callee->fun->call_count += 1;
    }
    
    if (!insert_callee(caller, callee)) {
        free(callee);
    } else {
        update_callee_function_state(callee, caller, sec, sym_sec, is_call);
    }
    
    return true;
}

static bool
mark_functions_via_relocs(asection *sec,
                         struct bfd_link_info *info,
                         int call_tree)
{
    Elf_Internal_Rela *internal_relocs, *irelaend, *irela;
    Elf_Internal_Shdr *symtab_hdr;
    void *psyms;
    static bool warned;
    
    if (!interesting_section(sec) || sec->reloc_count == 0)
        return true;
    
    internal_relocs = _bfd_elf_link_read_relocs(sec->owner, sec, NULL, NULL,
                                                info->keep_memory);
    if (internal_relocs == NULL)
        return false;
    
    symtab_hdr = &elf_tdata(sec->owner)->symtab_hdr;
    psyms = &symtab_hdr->contents;
    irela = internal_relocs;
    irelaend = irela + sec->reloc_count;
    
    for (; irela < irelaend; irela++) {
        unsigned int priority = 0;
        bool nonbranch, is_call = false;
        asection *sym_sec;
        Elf_Internal_Sym *sym;
        struct elf_link_hash_entry *h;
        bfd_vma val;
        
        if (!process_relocation(sec, info, irela, psyms, call_tree,
                               &priority, &is_call, &nonbranch, &warned))
            return false;
        
        unsigned int r_indx = ELF32_R_SYM(irela->r_info);
        if (!get_sym_h(&h, &sym, &sym_sec, psyms, r_indx, sec->owner))
            return false;
        
        if (sym_sec == NULL || sym_sec->output_section == bfd_abs_section_ptr)
            continue;
        
        val = h ? h->root.u.def.value : sym->st_value;
        val += irela->r_addend;
        
        if (!call_tree) {
            if (!handle_non_call_tree(sym_sec, irela, h, sym, val, is_call))
                return false;
        } else {
            if (!handle_call_tree(sec, sym_sec, info, irela, val,
                                 priority, is_call, nonbranch))
                return false;
        }
    }
    
    return true;
}

/* Handle something like .init or .fini, which has a piece of a function.
   These sections are pasted together to form a single function.  */

static bool
create_fake_symbol(asection *sec, Elf_Internal_Sym **fake_out)
{
  Elf_Internal_Sym *fake = bfd_zmalloc(sizeof(*fake));
  if (fake == NULL)
    return false;
    
  fake->st_value = 0;
  fake->st_size = sec->size;
  fake->st_shndx = _bfd_elf_section_from_bfd_section(sec->owner, sec);
  
  *fake_out = fake;
  return true;
}

static struct call_info *
create_callee_info(struct function_info *fun)
{
  struct call_info *callee = bfd_malloc(sizeof *callee);
  if (callee == NULL)
    return NULL;
    
  callee->fun = fun;
  callee->is_tail = true;
  callee->is_pasted = true;
  callee->broken_cycle = false;
  callee->priority = 0;
  callee->count = 1;
  
  return callee;
}

static struct function_info *
find_preceding_function(asection *sec)
{
  struct bfd_link_order *l;
  struct function_info *fun_start = NULL;
  
  for (l = sec->output_section->map_head.link_order; l != NULL; l = l->next)
  {
    if (l->u.indirect.section == sec)
      break;
      
    if (l->type == bfd_indirect_link_order)
    {
      struct _spu_elf_section_data *sec_data = spu_elf_section_data(l->u.indirect.section);
      if (sec_data != NULL)
      {
        struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
        if (sinfo != NULL && sinfo->num_fun != 0)
          fun_start = &sinfo->fun[sinfo->num_fun - 1];
      }
    }
  }
  
  return fun_start;
}

static bool
link_pasted_function(struct function_info *fun, struct function_info *fun_start)
{
  struct call_info *callee = create_callee_info(fun);
  if (callee == NULL)
    return false;
    
  fun->start = fun_start;
  
  if (!insert_callee(fun_start, callee))
    free(callee);
    
  return true;
}

static bool
pasted_function(asection *sec)
{
  Elf_Internal_Sym *fake;
  struct function_info *fun;
  struct function_info *fun_start;
  
  if (!create_fake_symbol(sec, &fake))
    return false;
    
  fun = maybe_insert_function(sec, fake, false, false);
  if (!fun)
    return false;
    
  fun_start = find_preceding_function(sec);
  
  if (fun_start != NULL)
    return link_pasted_function(fun, fun_start);
    
  return true;
}

/* Map address ranges in code sections to functions.  */

static int count_input_bfds(struct bfd_link_info *info)
{
  int count = 0;
  bfd *ibfd;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    count++;
  return count;
}

static bool is_spu_bfd(bfd *ibfd)
{
  extern const bfd_target spu_elf32_vec;
  return ibfd->xvec == &spu_elf32_vec;
}

static bool check_gaps_in_sections(bfd *ibfd, bool *gaps)
{
  asection *sec;
  if (*gaps)
    return true;
  
  for (sec = ibfd->sections; sec != NULL && !*gaps; sec = sec->next)
    if (interesting_section(sec))
      {
        *gaps = true;
        break;
      }
  return true;
}

static Elf_Internal_Sym* load_symbols(bfd *ibfd, size_t *symcount)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
  *symcount = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
  
  if (*symcount == 0)
    return NULL;
  
  free(symtab_hdr->contents);
  symtab_hdr->contents = NULL;
  Elf_Internal_Sym *syms = bfd_elf_get_elf_syms(ibfd, symtab_hdr, *symcount, 0,
                                                 NULL, NULL, NULL);
  symtab_hdr->contents = (void *)syms;
  return syms;
}

static bool is_function_symbol(Elf_Internal_Sym *sy)
{
  return ELF_ST_TYPE(sy->st_info) == STT_NOTYPE ||
         ELF_ST_TYPE(sy->st_info) == STT_FUNC;
}

static bool is_typed_function(Elf_Internal_Sym *sy)
{
  return ELF_ST_TYPE(sy->st_info) == STT_FUNC;
}

static bool is_global_notype(Elf_Internal_Sym *sy)
{
  return ELF_ST_TYPE(sy->st_info) != STT_FUNC &&
         ELF_ST_BIND(sy->st_info) == STB_GLOBAL;
}

static size_t filter_function_symbols(bfd *ibfd, Elf_Internal_Sym *syms, 
                                      size_t symcount, Elf_Internal_Sym ***psyms,
                                      asection ***psecs)
{
  *psyms = bfd_malloc((symcount + 1) * sizeof(**psyms));
  if (*psyms == NULL)
    return 0;
    
  *psecs = bfd_malloc(symcount * sizeof(**psecs));
  if (*psecs == NULL)
    return 0;
    
  Elf_Internal_Sym **psy = *psyms;
  asection **p = *psecs;
  Elf_Internal_Sym *sy;
  
  for (sy = syms; sy < syms + symcount; ++p, ++sy)
    {
      if (is_function_symbol(sy))
        {
          asection *s = bfd_section_from_elf_index(ibfd, sy->st_shndx);
          *p = s;
          if (s != NULL && interesting_section(s))
            *psy++ = sy;
        }
    }
  
  size_t filtered_count = psy - *psyms;
  *psy = NULL;
  return filtered_count;
}

static bool allocate_stack_info_for_sections(Elf_Internal_Sym **psyms, 
                                            size_t symcount, asection **psecs,
                                            Elf_Internal_Sym *syms)
{
  Elf_Internal_Sym **psy;
  for (psy = psyms; psy < psyms + symcount; )
    {
      asection *s = psecs[*psy - syms];
      Elf_Internal_Sym **psy2;
      
      for (psy2 = psy; ++psy2 < psyms + symcount; )
        if (psecs[*psy2 - syms] != s)
          break;
      
      if (!alloc_stack_info(s, psy2 - psy))
        return false;
      psy = psy2;
    }
  return true;
}

static bool install_typed_functions(Elf_Internal_Sym **psyms, size_t symcount,
                                   asection **psecs, Elf_Internal_Sym *syms)
{
  Elf_Internal_Sym **psy;
  for (psy = psyms; psy < psyms + symcount; ++psy)
    {
      Elf_Internal_Sym *sy = *psy;
      if (is_typed_function(sy))
        {
          asection *s = psecs[sy - syms];
          if (!maybe_insert_function(s, sy, false, true))
            return false;
        }
    }
  return true;
}

static bool check_section_gaps(bfd *ibfd, struct bfd_link_info *info, bool *gaps)
{
  asection *sec;
  for (sec = ibfd->sections; sec != NULL && !*gaps; sec = sec->next)
    if (interesting_section(sec))
      *gaps |= check_function_ranges(sec, info);
  return true;
}

static bool process_bfd_symbols(bfd *ibfd, int bfd_idx, 
                               Elf_Internal_Sym ***psym_arr,
                               asection ***sec_arr, bool *gaps,
                               struct bfd_link_info *info)
{
  if (!is_spu_bfd(ibfd))
    return true;
    
  size_t symcount;
  Elf_Internal_Sym *syms = load_symbols(ibfd, &symcount);
  
  if (symcount == 0)
    {
      check_gaps_in_sections(ibfd, gaps);
      return true;
    }
    
  if (syms == NULL)
    return false;
    
  Elf_Internal_Sym **psyms;
  asection **psecs;
  symcount = filter_function_symbols(ibfd, syms, symcount, &psyms, &psecs);
  
  if (psyms == NULL || psecs == NULL)
    return false;
    
  psym_arr[bfd_idx] = psyms;
  sec_arr[bfd_idx] = psecs;
  
  sort_syms_syms = syms;
  sort_syms_psecs = psecs;
  qsort(psyms, symcount, sizeof(*psyms), sort_syms);
  
  if (!allocate_stack_info_for_sections(psyms, symcount, psecs, syms))
    return false;
    
  if (!install_typed_functions(psyms, symcount, psecs, syms))
    return false;
    
  check_section_gaps(ibfd, info, gaps);
  return true;
}

static bool mark_functions_for_bfd(bfd *ibfd, int bfd_idx, 
                                  Elf_Internal_Sym ***psym_arr,
                                  struct bfd_link_info *info)
{
  asection *sec;
  if (psym_arr[bfd_idx] == NULL)
    return true;
    
  for (sec = ibfd->sections; sec != NULL; sec = sec->next)
    if (!mark_functions_via_relocs(sec, info, false))
      return false;
      
  return true;
}

static bool install_global_symbols(bfd *ibfd, int bfd_idx,
                                  Elf_Internal_Sym ***psym_arr,
                                  asection ***sec_arr,
                                  struct bfd_link_info *info)
{
  Elf_Internal_Sym **psyms = psym_arr[bfd_idx];
  if (psyms == NULL)
    return true;
    
  asection **psecs = sec_arr[bfd_idx];
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
  Elf_Internal_Sym *syms = (Elf_Internal_Sym *)symtab_hdr->contents;
  
  bool gaps = false;
  check_section_gaps(ibfd, info, &gaps);
  if (!gaps)
    return true;
    
  Elf_Internal_Sym **psy;
  Elf_Internal_Sym *sy;
  for (psy = psyms; (sy = *psy) != NULL; ++psy)
    {
      if (is_global_notype(sy))
        {
          asection *s = psecs[sy - syms];
          if (!maybe_insert_function(s, sy, false, false))
            return false;
        }
    }
  return true;
}

static bool extend_function_ranges_for_section(asection *sec)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  
  if (sinfo != NULL && sinfo->num_fun != 0)
    {
      int fun_idx;
      bfd_vma hi = sec->size;
      
      for (fun_idx = sinfo->num_fun; --fun_idx >= 0; )
        {
          sinfo->fun[fun_idx].hi = hi;
          hi = sinfo->fun[fun_idx].lo;
        }
      
      sinfo->fun[0].lo = 0;
    }
  else if (!pasted_function(sec))
    return false;
    
  return true;
}

static bool extend_function_ranges(bfd *ibfd)
{
  asection *sec;
  if (!is_spu_bfd(ibfd))
    return true;
    
  for (sec = ibfd->sections; sec != NULL; sec = sec->next)
    if (interesting_section(sec))
      if (!extend_function_ranges_for_section(sec))
        return false;
        
  return true;
}

static void cleanup_arrays(Elf_Internal_Sym ***psym_arr, asection ***sec_arr,
                          struct bfd_link_info *info)
{
  bfd *ibfd;
  int bfd_idx;
  
  for (ibfd = info->input_bfds, bfd_idx = 0;
       ibfd != NULL;
       ibfd = ibfd->link.next, bfd_idx++)
    {
      if (psym_arr[bfd_idx] != NULL)
        {
          free(psym_arr[bfd_idx]);
          free(sec_arr[bfd_idx]);
        }
    }
  
  free(psym_arr);
  free(sec_arr);
}

static bool
discover_functions(struct bfd_link_info *info)
{
  int bfd_count = count_input_bfds(info);
  
  Elf_Internal_Sym ***psym_arr = bfd_zmalloc(bfd_count * sizeof(*psym_arr));
  if (psym_arr == NULL)
    return false;
    
  asection ***sec_arr = bfd_zmalloc(bfd_count * sizeof(*sec_arr));
  if (sec_arr == NULL)
    {
      free(psym_arr);
      return false;
    }
  
  bool gaps = false;
  bfd *ibfd;
  int bfd_idx;
  
  for (ibfd = info->input_bfds, bfd_idx = 0;
       ibfd != NULL;
       ibfd = ibfd->link.next, bfd_idx++)
    {
      if (!process_bfd_symbols(ibfd, bfd_idx, psym_arr, sec_arr, &gaps, info))
        {
          cleanup_arrays(psym_arr, sec_arr, info);
          return false;
        }
    }
  
  if (gaps)
    {
      for (ibfd = info->input_bfds, bfd_idx = 0;
           ibfd != NULL;
           ibfd = ibfd->link.next, bfd_idx++)
        {
          if (!mark_functions_for_bfd(ibfd, bfd_idx, psym_arr, info))
            {
              cleanup_arrays(psym_arr, sec_arr, info);
              return false;
            }
        }
      
      for (ibfd = info->input_bfds, bfd_idx = 0;
           ibfd != NULL;
           ibfd = ibfd->link.next, bfd_idx++)
        {
          if (!install_global_symbols(ibfd, bfd_idx, psym_arr, sec_arr, info))
            {
              cleanup_arrays(psym_arr, sec_arr, info);
              return false;
            }
        }
      
      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
        {
          if (!extend_function_ranges(ibfd))
            {
              cleanup_arrays(psym_arr, sec_arr, info);
              return false;
            }
        }
    }
  
  cleanup_arrays(psym_arr, sec_arr, info);
  return true;
}

/* Iterate over all function_info we have collected, calling DOIT on
   each node if ROOT_ONLY is false.  Only call DOIT on root nodes
   if ROOT_ONLY.  */

static bool
process_function(struct function_info *fun, 
                bool (*doit)(struct function_info *, struct bfd_link_info *, void *),
                struct bfd_link_info *info,
                void *param,
                int root_only)
{
    if (root_only && fun->non_root)
        return true;
    return doit(fun, info, param);
}

static bool
process_section_functions(struct spu_elf_stack_info *sinfo,
                         bool (*doit)(struct function_info *, struct bfd_link_info *, void *),
                         struct bfd_link_info *info,
                         void *param,
                         int root_only)
{
    int i;
    for (i = 0; i < sinfo->num_fun; ++i)
        if (!process_function(&sinfo->fun[i], doit, info, param, root_only))
            return false;
    return true;
}

static bool
process_bfd_sections(bfd *ibfd,
                    bool (*doit)(struct function_info *, struct bfd_link_info *, void *),
                    struct bfd_link_info *info,
                    void *param,
                    int root_only)
{
    asection *sec;
    
    for (sec = ibfd->sections; sec != NULL; sec = sec->next)
    {
        struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
        if (sec_data == NULL)
            continue;
            
        struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
        if (sinfo == NULL)
            continue;
            
        if (!process_section_functions(sinfo, doit, info, param, root_only))
            return false;
    }
    return true;
}

static bool
for_each_node(bool (*doit)(struct function_info *, struct bfd_link_info *, void *),
             struct bfd_link_info *info,
             void *param,
             int root_only)
{
    extern const bfd_target spu_elf32_vec;
    bfd *ibfd;
    
    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
        if (ibfd->xvec != &spu_elf32_vec)
            continue;
            
        if (!process_bfd_sections(ibfd, doit, info, param, root_only))
            return false;
    }
    return true;
}

/* Transfer call info attached to struct function_info entries for
   all of a given function's sections to the first entry.  */

static bool
transfer_calls (struct function_info *fun,
		struct bfd_link_info *info ATTRIBUTE_UNUSED,
		void *param ATTRIBUTE_UNUSED)
{
  struct function_info *start = find_root_function(fun);

  if (start != NULL)
    {
      move_calls_to_root(fun, start);
    }
  return true;
}

static struct function_info *
find_root_function(struct function_info *fun)
{
  struct function_info *start = fun->start;
  
  if (start == NULL)
    return NULL;
    
  while (start->start != NULL)
    start = start->start;
    
  return start;
}

static void
move_calls_to_root(struct function_info *fun, struct function_info *root)
{
  struct call_info *call = fun->call_list;
  struct call_info *call_next;
  
  while (call != NULL)
    {
      call_next = call->next;
      if (!insert_callee (root, call))
        free (call);
      call = call_next;
    }
    
  fun->call_list = NULL;
}

/* Mark nodes in the call graph that are called by some other node.  */

static bool
mark_non_root (struct function_info *fun,
	       struct bfd_link_info *info ATTRIBUTE_UNUSED,
	       void *param ATTRIBUTE_UNUSED)
{
  struct call_info *call;

  if (fun->visit1)
    return true;
  fun->visit1 = true;
  for (call = fun->call_list; call; call = call->next)
    {
      call->fun->non_root = true;
      mark_non_root (call->fun, 0, 0);
    }
  return true;
}

/* Remove cycles from the call graph.  Set depth of nodes.  */

static bool should_report_cycle(struct bfd_link_info *info)
{
    struct spu_link_hash_table *htab = spu_hash_table(info);
    return !htab->params->auto_overlay && htab->params->stack_analysis;
}

static void report_cycle(struct function_info *fun, 
                        struct call_info *call,
                        struct bfd_link_info *info)
{
    const char *f1 = func_name(fun);
    const char *f2 = func_name(call->fun);
    info->callbacks->info(_("stack analysis will ignore the call "
                           "from %s to %s\n"), f1, f2);
}

static void update_call_depth(struct call_info *call, unsigned int depth)
{
    call->max_depth = depth + !call->is_pasted;
}

static bool process_unvisited_call(struct call_info *call,
                                   struct bfd_link_info *info,
                                   unsigned int *max_depth)
{
    if (!remove_cycles(call->fun, info, &call->max_depth))
        return false;
    
    if (*max_depth < call->max_depth)
        *max_depth = call->max_depth;
    
    return true;
}

static void process_cycle(struct function_info *fun,
                         struct call_info *call,
                         struct bfd_link_info *info)
{
    if (should_report_cycle(info))
        report_cycle(fun, call, info);
    
    call->broken_cycle = true;
}

static bool process_call(struct function_info *fun,
                         struct call_info *call,
                         struct bfd_link_info *info,
                         unsigned int depth,
                         unsigned int *max_depth)
{
    update_call_depth(call, depth);
    
    if (!call->fun->visit2)
        return process_unvisited_call(call, info, max_depth);
    
    if (call->fun->marking)
        process_cycle(fun, call, info);
    
    return true;
}

static bool remove_cycles(struct function_info *fun,
                         struct bfd_link_info *info,
                         void *param)
{
    struct call_info **callp, *call;
    unsigned int depth = *(unsigned int *)param;
    unsigned int max_depth = depth;
    
    fun->depth = depth;
    fun->visit2 = true;
    fun->marking = true;
    
    callp = &fun->call_list;
    while ((call = *callp) != NULL)
    {
        if (!process_call(fun, call, info, depth, &max_depth))
            return false;
        callp = &call->next;
    }
    
    fun->marking = false;
    *(unsigned int *)param = max_depth;
    return true;
}

/* Check that we actually visited all nodes in remove_cycles.  If we
   didn't, then there is some cycle in the call graph not attached to
   any root node.  Arbitrarily choose a node in the cycle as a new
   root and break the cycle.  */

static bool
mark_detached_root (struct function_info *fun,
		    struct bfd_link_info *info,
		    void *param)
{
  if (fun->visit2)
    return true;
  fun->non_root = false;
  *(unsigned int *) param = 0;
  return remove_cycles (fun, info, param);
}

/* Populate call_list for each function.  */

static bool process_input_sections(struct bfd_link_info *info)
{
    extern const bfd_target spu_elf32_vec;
    bfd *ibfd;
    
    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
        if (ibfd->xvec != &spu_elf32_vec)
            continue;
            
        asection *sec;
        for (sec = ibfd->sections; sec != NULL; sec = sec->next)
        {
            if (!mark_functions_via_relocs(sec, info, true))
                return false;
        }
    }
    return true;
}

static bool transfer_call_info(struct bfd_link_info *info)
{
    if (spu_hash_table(info)->params->auto_overlay)
        return true;
    return for_each_node(transfer_calls, info, 0, false);
}

static bool find_call_graph_roots(struct bfd_link_info *info)
{
    return for_each_node(mark_non_root, info, 0, false);
}

static bool remove_call_graph_cycles(struct bfd_link_info *info, unsigned int *depth)
{
    return for_each_node(remove_cycles, info, depth, true);
}

static bool mark_detached_roots(struct bfd_link_info *info, unsigned int *depth)
{
    return for_each_node(mark_detached_root, info, depth, false);
}

static bool build_call_tree(struct bfd_link_info *info)
{
    if (!process_input_sections(info))
        return false;
        
    if (!transfer_call_info(info))
        return false;
        
    if (!find_call_graph_roots(info))
        return false;
        
    unsigned int depth = 0;
    if (!remove_call_graph_cycles(info, &depth))
        return false;
        
    return mark_detached_roots(info, &depth);
}

/* qsort predicate to sort calls by priority, max_depth then count.  */

static int compare_priority(const struct call_info *c1, const struct call_info *c2)
{
    return c2->priority - c1->priority;
}

static int compare_max_depth(const struct call_info *c1, const struct call_info *c2)
{
    return c2->max_depth - c1->max_depth;
}

static int compare_count(const struct call_info *c1, const struct call_info *c2)
{
    return c2->count - c1->count;
}

static int compare_pointer_address(const void *a, const void *b)
{
    return (char *)a - (char *)b;
}

static int sort_calls(const void *a, const void *b)
{
    struct call_info *const *c1 = a;
    struct call_info *const *c2 = b;
    int delta;

    delta = compare_priority(*c1, *c2);
    if (delta != 0)
        return delta;

    delta = compare_max_depth(*c1, *c2);
    if (delta != 0)
        return delta;

    delta = compare_count(*c1, *c2);
    if (delta != 0)
        return delta;

    return compare_pointer_address(c1, c2);
}

struct _mos_param {
  unsigned int max_overlay_size;
};

/* Set linker_mark and gc_mark on any sections that we will put in
   overlays.  These flags are used by the generic ELF linker, but we
   won't be continuing on to bfd_elf_final_link so it is OK to use
   them.  linker_mark is clear before we get here.  Set segment_mark
   on sections that are part of a pasted function (excluding the last
   section).

   Set up function rodata section if --overlay-rodata.  We don't
   currently include merged string constant rodata sections since

   Sort the call graph so that the deepest nodes will be visited
   first.  */

static bool should_mark_section(struct function_info *fun,
                                struct spu_link_hash_table *htab)
{
    if (fun->sec->linker_mark)
        return false;
    
    if (htab->params->ovly_flavour == ovly_soft_icache
        && !htab->params->non_ia_text
        && !startswith(fun->sec->name, ".text.ia.")
        && strcmp(fun->sec->name, ".init") != 0
        && strcmp(fun->sec->name, ".fini") != 0)
        return false;
    
    return true;
}

static void mark_section(asection *sec)
{
    sec->linker_mark = 1;
    sec->gc_mark = 1;
    sec->segment_mark = 0;
}

static char* create_rodata_name(const char *sec_name)
{
    char *name = NULL;
    
    if (strcmp(sec_name, ".text") == 0)
    {
        name = bfd_malloc(sizeof(".rodata"));
        if (name != NULL)
            memcpy(name, ".rodata", sizeof(".rodata"));
    }
    else if (startswith(sec_name, ".text."))
    {
        size_t len = strlen(sec_name);
        name = bfd_malloc(len + 3);
        if (name != NULL)
        {
            memcpy(name, ".rodata", sizeof(".rodata"));
            memcpy(name + 7, sec_name + 5, len - 4);
        }
    }
    else if (startswith(sec_name, ".gnu.linkonce.t."))
    {
        size_t len = strlen(sec_name) + 1;
        name = bfd_malloc(len);
        if (name != NULL)
        {
            memcpy(name, sec_name, len);
            name[14] = 'r';
        }
    }
    
    return name;
}

static asection* find_rodata_in_group(asection *fun_sec, const char *name)
{
    asection *group_sec = elf_section_data(fun_sec)->next_in_group;
    
    while (group_sec != NULL && group_sec != fun_sec)
    {
        if (strcmp(group_sec->name, name) == 0)
            return group_sec;
        group_sec = elf_section_data(group_sec)->next_in_group;
    }
    
    return NULL;
}

static asection* find_rodata_section(asection *fun_sec, const char *name)
{
    asection *group_sec = elf_section_data(fun_sec)->next_in_group;
    
    if (group_sec == NULL)
        return bfd_get_section_by_name(fun_sec->owner, name);
    
    return find_rodata_in_group(fun_sec, name);
}

static unsigned int process_rodata(struct function_info *fun,
                                   struct spu_link_hash_table *htab,
                                   unsigned int size)
{
    char *name = create_rodata_name(fun->sec->name);
    if (name == NULL)
        return size;
    
    fun->rodata = find_rodata_section(fun->sec, name);
    free(name);
    
    if (fun->rodata == NULL)
        return size;
    
    unsigned int total_size = size + fun->rodata->size;
    
    if (htab->params->line_size != 0 && total_size > htab->params->line_size)
    {
        fun->rodata = NULL;
        return size;
    }
    
    mark_section(fun->rodata);
    fun->rodata->flags &= ~SEC_CODE;
    return total_size;
}

static unsigned int mark_and_measure_section(struct function_info *fun,
                                            struct spu_link_hash_table *htab)
{
    mark_section(fun->sec);
    fun->sec->flags |= SEC_CODE;
    
    unsigned int size = fun->sec->size;
    
    if (htab->params->auto_overlay & OVERLAY_RODATA)
        size = process_rodata(fun, htab, size);
    
    return size;
}

static bool sort_function_calls(struct function_info *fun)
{
    struct call_info *call;
    unsigned int count = 0;
    
    for (call = fun->call_list; call != NULL; call = call->next)
        count++;
    
    if (count <= 1)
        return true;
    
    struct call_info **calls = bfd_malloc(count * sizeof(*calls));
    if (calls == NULL)
        return false;
    
    count = 0;
    for (call = fun->call_list; call != NULL; call = call->next)
        calls[count++] = call;
    
    qsort(calls, count, sizeof(*calls), sort_calls);
    
    fun->call_list = NULL;
    while (count != 0)
    {
        --count;
        calls[count]->next = fun->call_list;
        fun->call_list = calls[count];
    }
    
    free(calls);
    return true;
}

static bool is_entry_or_overlay_init(struct function_info *fun,
                                    struct bfd_link_info *info)
{
    return (fun->lo + fun->sec->output_offset + fun->sec->output_section->vma
            == info->output_bfd->start_address)
           || startswith(fun->sec->output_section->name, ".ovl.init");
}

static void unmark_entry_sections(struct function_info *fun)
{
    fun->sec->linker_mark = 0;
    if (fun->rodata != NULL)
        fun->rodata->linker_mark = 0;
}

static bool
mark_overlay_section(struct function_info *fun,
                    struct bfd_link_info *info,
                    void *param)
{
    struct _mos_param *mos_param = param;
    struct spu_link_hash_table *htab = spu_hash_table(info);
    
    if (fun->visit4)
        return true;
    
    fun->visit4 = true;
    
    if (should_mark_section(fun, htab))
    {
        unsigned int size = mark_and_measure_section(fun, htab);
        
        if (mos_param->max_overlay_size < size)
            mos_param->max_overlay_size = size;
    }
    
    if (!sort_function_calls(fun))
        return false;
    
    for (struct call_info *call = fun->call_list; call != NULL; call = call->next)
    {
        if (call->is_pasted)
        {
            BFD_ASSERT(!fun->sec->segment_mark);
            fun->sec->segment_mark = 1;
        }
        if (!call->broken_cycle
            && !mark_overlay_section(call->fun, info, param))
            return false;
    }
    
    if (is_entry_or_overlay_init(fun, info))
        unmark_entry_sections(fun);
    
    return true;
}

/* If non-zero then unmark functions called from those within sections
   that we need to unmark.  Unfortunately this isn't reliable since the
   call graph cannot know the destination of function pointer calls.  */
#define RECURSE_UNMARK 0

struct _uos_param {
  asection *exclude_input_section;
  asection *exclude_output_section;
  unsigned long clearing;
};

/* Undo some of mark_overlay_section's work.  */

static bool
unmark_overlay_section (struct function_info *fun,
			struct bfd_link_info *info,
			void *param)
{
  struct _uos_param *uos_param = param;

  if (fun->visit5)
    return true;

  fun->visit5 = true;

  unsigned int excluded = is_excluded_section(fun, uos_param);

  update_clearing_state(uos_param, excluded, 1);

  if (should_unmark_section(uos_param, excluded))
    unmark_sections(fun);

  bool result = process_call_list(fun, info, param);

  update_clearing_state(uos_param, excluded, -1);

  return result;
}

static unsigned int
is_excluded_section(struct function_info *fun, struct _uos_param *uos_param)
{
  if (fun->sec == uos_param->exclude_input_section
      || fun->sec->output_section == uos_param->exclude_output_section)
    return 1;
  return 0;
}

static void
update_clearing_state(struct _uos_param *uos_param, unsigned int excluded, int direction)
{
  if (RECURSE_UNMARK)
    uos_param->clearing += excluded * direction;
}

static bool
should_unmark_section(struct _uos_param *uos_param, unsigned int excluded)
{
  return RECURSE_UNMARK ? uos_param->clearing : excluded;
}

static void
unmark_sections(struct function_info *fun)
{
  fun->sec->linker_mark = 0;
  if (fun->rodata)
    fun->rodata->linker_mark = 0;
}

static bool
process_call_list(struct function_info *fun, struct bfd_link_info *info, void *param)
{
  struct call_info *call;
  for (call = fun->call_list; call != NULL; call = call->next)
    if (!call->broken_cycle
	&& !unmark_overlay_section (call->fun, info, param))
      return false;
  return true;
}

struct _cl_param {
  unsigned int lib_size;
  asection **lib_sections;
};

/* Add sections we have marked as belonging to overlays to an array
   for consideration as non-overlay sections.  The array consist of
   pairs of sections, (text,rodata), for functions in the call graph.  */

static bool should_skip_function(struct function_info *fun)
{
    return fun->visit6 || 
           !fun->sec->linker_mark || 
           !fun->sec->gc_mark || 
           fun->sec->segment_mark;
}

static unsigned int calculate_function_size(struct function_info *fun)
{
    unsigned int size = fun->sec->size;
    if (fun->rodata)
        size += fun->rodata->size;
    return size;
}

static void mark_section_for_library(asection *sec, asection ***lib_sections)
{
    *(*lib_sections)++ = sec;
    sec->gc_mark = 0;
}

static void process_rodata_section(struct function_info *fun, asection ***lib_sections)
{
    if (fun->rodata && fun->rodata->linker_mark && fun->rodata->gc_mark)
        mark_section_for_library(fun->rodata, lib_sections);
    else
        *(*lib_sections)++ = NULL;
}

static void add_function_to_library(struct function_info *fun, struct _cl_param *lib_param)
{
    mark_section_for_library(fun->sec, &lib_param->lib_sections);
    process_rodata_section(fun, &lib_param->lib_sections);
}

static void process_function_calls(struct function_info *fun, 
                                  struct bfd_link_info *info, 
                                  void *param)
{
    struct call_info *call;
    for (call = fun->call_list; call != NULL; call = call->next)
        if (!call->broken_cycle)
            collect_lib_sections(call->fun, info, param);
}

static bool collect_lib_sections(struct function_info *fun,
                                struct bfd_link_info *info,
                                void *param)
{
    struct _cl_param *lib_param = param;
    
    if (should_skip_function(fun))
        return true;
    
    fun->visit6 = true;
    
    unsigned int size = calculate_function_size(fun);
    
    if (size <= lib_param->lib_size)
        add_function_to_library(fun, lib_param);
    
    process_function_calls(fun, info, param);
    
    return true;
}

/* qsort predicate to sort sections by call count.  */

static int calculate_section_call_count(asection *section)
{
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  int call_count = 0;
  int i;

  sec_data = spu_elf_section_data(section);
  if (sec_data == NULL)
    return 0;

  sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL)
    return 0;

  for (i = 0; i < sinfo->num_fun; ++i)
    call_count += sinfo->fun[i].call_count;

  return call_count;
}

static int
sort_lib (const void *a, const void *b)
{
  asection *const *s1 = a;
  asection *const *s2 = b;
  int delta;

  delta = calculate_section_call_count(*s2) - calculate_section_call_count(*s1);

  if (delta != 0)
    return delta;

  return s1 - s2;
}

/* Remove some sections from those marked to be in overlays.  Choose
   those that are called from many places, likely library functions.  */

static unsigned int count_lib_sections(struct bfd_link_info *info, unsigned int lib_size)
{
    bfd *ibfd;
    unsigned int lib_count = 0;
    extern const bfd_target spu_elf32_vec;

    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
        asection *sec;
        
        if (ibfd->xvec != &spu_elf32_vec)
            continue;

        for (sec = ibfd->sections; sec != NULL; sec = sec->next) {
            if (sec->linker_mark && sec->size < lib_size && (sec->flags & SEC_CODE) != 0)
                lib_count += 1;
        }
    }
    return lib_count;
}

static unsigned int calculate_stub_size_for_section(asection *sec, struct function_info *dummy_caller, struct spu_link_hash_table *htab)
{
    struct _spu_elf_section_data *sec_data;
    struct spu_elf_stack_info *sinfo;
    unsigned int stub_size = 0;
    
    sec_data = spu_elf_section_data(sec);
    if (sec_data == NULL)
        return 0;
        
    sinfo = sec_data->u.i.stack_info;
    if (sinfo == NULL)
        return 0;

    for (int k = 0; k < sinfo->num_fun; ++k) {
        struct call_info *call;
        for (call = sinfo->fun[k].call_list; call; call = call->next) {
            if (!call->fun->sec->linker_mark)
                continue;
                
            struct call_info *p;
            for (p = dummy_caller->call_list; p; p = p->next) {
                if (p->fun == call->fun)
                    break;
            }
            if (!p)
                stub_size += ovl_stub_size(htab->params);
        }
    }
    return stub_size;
}

static void remove_unneeded_call_stubs(struct function_info *dummy_caller, unsigned int *lib_size, struct spu_link_hash_table *htab)
{
    struct call_info **pp = &dummy_caller->call_list;
    struct call_info *p;
    
    while ((p = *pp) != NULL) {
        if (!p->fun->sec->linker_mark) {
            *lib_size += ovl_stub_size(htab->params);
            *pp = p->next;
            free(p);
        } else {
            pp = &p->next;
        }
    }
}

static unsigned int add_new_call_stubs(asection *sec, struct function_info *dummy_caller)
{
    struct _spu_elf_section_data *sec_data;
    struct spu_elf_stack_info *sinfo;
    
    sec_data = spu_elf_section_data(sec);
    if (sec_data == NULL)
        return 0;
        
    sinfo = sec_data->u.i.stack_info;
    if (sinfo == NULL)
        return 0;

    for (int k = 0; k < sinfo->num_fun; ++k) {
        struct call_info *call;
        for (call = sinfo->fun[k].call_list; call; call = call->next) {
            if (!call->fun->sec->linker_mark)
                continue;
                
            struct call_info *callee = bfd_malloc(sizeof(*callee));
            if (callee == NULL)
                return (unsigned int)-1;
                
            *callee = *call;
            if (!insert_callee(dummy_caller, callee))
                free(callee);
        }
    }
    return 0;
}

static void mark_sections_as_non_overlay(asection **lib_sections, unsigned int index)
{
    lib_sections[2 * index]->linker_mark = 0;
    if (lib_sections[2 * index + 1])
        lib_sections[2 * index + 1]->linker_mark = 0;
}

static unsigned int process_library_section(asection **lib_sections, unsigned int i, unsigned int lib_size, 
                                           struct function_info *dummy_caller, struct spu_link_hash_table *htab)
{
    asection *sec = lib_sections[2 * i];
    unsigned int tmp = sec->size;
    
    if (lib_sections[2 * i + 1])
        tmp += lib_sections[2 * i + 1]->size;
    
    unsigned int stub_size = 0;
    if (tmp < lib_size)
        stub_size = calculate_stub_size_for_section(sec, dummy_caller, htab);
    
    if (tmp + stub_size >= lib_size)
        return lib_size;
    
    mark_sections_as_non_overlay(lib_sections, i);
    lib_size -= tmp + stub_size;
    
    remove_unneeded_call_stubs(dummy_caller, &lib_size, htab);
    
    unsigned int result = add_new_call_stubs(sec, dummy_caller);
    if (result == (unsigned int)-1)
        return result;
    
    return lib_size;
}

static void cleanup_dummy_caller(struct function_info *dummy_caller)
{
    while (dummy_caller->call_list != NULL) {
        struct call_info *call = dummy_caller->call_list;
        dummy_caller->call_list = call->next;
        free(call);
    }
}

static void mark_lib_sections_gc(asection **lib_sections, unsigned int lib_count)
{
    for (unsigned int i = 0; i < 2 * lib_count; i++) {
        if (lib_sections[i])
            lib_sections[i]->gc_mark = 1;
    }
}

static unsigned int auto_ovl_lib_functions(struct bfd_link_info *info, unsigned int lib_size)
{
    asection **lib_sections;
    unsigned int i, lib_count;
    struct _cl_param collect_lib_param;
    struct function_info dummy_caller;
    struct spu_link_hash_table *htab;

    memset(&dummy_caller, 0, sizeof(dummy_caller));
    
    lib_count = count_lib_sections(info, lib_size);
    
    lib_sections = bfd_malloc(lib_count * 2 * sizeof(*lib_sections));
    if (lib_sections == NULL)
        return (unsigned int)-1;
        
    collect_lib_param.lib_size = lib_size;
    collect_lib_param.lib_sections = lib_sections;
    
    if (!for_each_node(collect_lib_sections, info, &collect_lib_param, true))
        return (unsigned int)-1;
        
    lib_count = (collect_lib_param.lib_sections - lib_sections) / 2;

    if (lib_count > 1)
        qsort(lib_sections, lib_count, 2 * sizeof(*lib_sections), sort_lib);

    htab = spu_hash_table(info);
    
    for (i = 0; i < lib_count; i++) {
        lib_size = process_library_section(lib_sections, i, lib_size, &dummy_caller, htab);
        if (lib_size == (unsigned int)-1)
            return (unsigned int)-1;
    }
    
    cleanup_dummy_caller(&dummy_caller);
    mark_lib_sections_gc(lib_sections, lib_count);
    free(lib_sections);
    
    return lib_size;
}

/* Build an array of overlay sections.  The deepest node's section is
   added first, then its parent node's section, then everything called
   from the parent section.  The idea being to group sections to
   minimise calls between different overlays.  */

static bool process_call_list(struct call_info *call_list, 
                               struct bfd_link_info *info, 
                               asection ***ovly_sections)
{
    struct call_info *call;
    for (call = call_list; call != NULL; call = call->next)
        if (!call->broken_cycle && !collect_overlays(call->fun, info, ovly_sections))
            return false;
    return true;
}

static bool find_first_valid_call(struct call_info *call_list, 
                                   struct bfd_link_info *info, 
                                   asection ***ovly_sections)
{
    struct call_info *call;
    for (call = call_list; call != NULL; call = call->next)
    {
        if (!call->is_pasted && !call->broken_cycle)
        {
            if (!collect_overlays(call->fun, info, ovly_sections))
                return false;
            break;
        }
    }
    return true;
}

static void mark_section_gc(asection *sec)
{
    if (sec && sec->linker_mark && sec->gc_mark)
        sec->gc_mark = 0;
}

static void add_section_to_overlay(asection *sec, asection ***ovly_sections)
{
    if (sec && sec->linker_mark && sec->gc_mark)
    {
        sec->gc_mark = 0;
        *(*ovly_sections)++ = sec;
    }
    else
    {
        *(*ovly_sections)++ = NULL;
    }
}

static void mark_pasted_sections(struct function_info *fun)
{
    struct function_info *call_fun = fun;
    struct call_info *call;
    
    do
    {
        for (call = call_fun->call_list; call != NULL; call = call->next)
        {
            if (call->is_pasted)
            {
                call_fun = call->fun;
                call_fun->sec->gc_mark = 0;
                if (call_fun->rodata)
                    call_fun->rodata->gc_mark = 0;
                break;
            }
        }
        if (call == NULL)
            abort();
    }
    while (call_fun->sec->segment_mark);
}

static bool process_stack_info_functions(struct function_info *fun, 
                                          struct bfd_link_info *info, 
                                          asection ***ovly_sections)
{
    struct _spu_elf_section_data *sec_data;
    struct spu_elf_stack_info *sinfo;
    int i;
    
    sec_data = spu_elf_section_data(fun->sec);
    if (sec_data == NULL)
        return true;
        
    sinfo = sec_data->u.i.stack_info;
    if (sinfo == NULL)
        return true;
        
    for (i = 0; i < sinfo->num_fun; ++i)
        if (!collect_overlays(&sinfo->fun[i], info, ovly_sections))
            return false;
            
    return true;
}

static bool add_function_sections(struct function_info *fun, asection ***ovly_sections)
{
    if (!fun->sec->linker_mark || !fun->sec->gc_mark)
        return false;
        
    fun->sec->gc_mark = 0;
    *(*ovly_sections)++ = fun->sec;
    add_section_to_overlay(fun->rodata, ovly_sections);
    
    if (fun->sec->segment_mark)
        mark_pasted_sections(fun);
        
    return true;
}

static bool
collect_overlays(struct function_info *fun,
                 struct bfd_link_info *info,
                 void *param)
{
    asection ***ovly_sections = param;
    bool added_fun;
    
    if (fun->visit7)
        return true;
        
    fun->visit7 = true;
    
    if (!find_first_valid_call(fun->call_list, info, ovly_sections))
        return false;
        
    added_fun = add_function_sections(fun, ovly_sections);
    
    if (!process_call_list(fun->call_list, info, ovly_sections))
        return false;
        
    if (added_fun)
        if (!process_stack_info_functions(fun, info, ovly_sections))
            return false;
            
    return true;
}

struct _sum_stack_param {
  size_t cum_stack;
  size_t overall_stack;
  bool emit_stack_syms;
};

/* Descend the call graph for FUN, accumulating total stack required.  */

static bool should_skip_call(struct call_info *call)
{
    return call->broken_cycle;
}

static bool is_normal_call(struct call_info *call)
{
    return !call->is_pasted;
}

static bool should_include_caller_stack(struct call_info *call, struct function_info *fun)
{
    return !call->is_tail || call->is_pasted || call->fun->start != NULL;
}

static size_t calculate_call_stack(struct call_info *call, struct function_info *fun, 
                                   struct bfd_link_info *info, struct _sum_stack_param *sum_stack_param)
{
    if (!sum_stack(call->fun, info, sum_stack_param))
        return 0;
    
    size_t stack = sum_stack_param->cum_stack;
    if (should_include_caller_stack(call, fun))
        stack += fun->stack;
    
    return stack;
}

static void process_calls(struct function_info *fun, struct bfd_link_info *info,
                         struct _sum_stack_param *sum_stack_param, 
                         bool *has_call, struct function_info **max, size_t *cum_stack)
{
    for (struct call_info *call = fun->call_list; call; call = call->next)
    {
        if (should_skip_call(call))
            continue;
        
        if (is_normal_call(call))
            *has_call = true;
        
        size_t stack = calculate_call_stack(call, fun, info, sum_stack_param);
        if (stack == 0)
            continue;
        
        if (*cum_stack < stack)
        {
            *cum_stack = stack;
            *max = call->fun;
        }
    }
}

static void update_function_stack(struct function_info *fun, size_t cum_stack,
                                 struct _sum_stack_param *sum_stack_param)
{
    sum_stack_param->cum_stack = cum_stack;
    fun->stack = cum_stack;
    fun->visit3 = true;
    
    if (!fun->non_root && sum_stack_param->overall_stack < cum_stack)
        sum_stack_param->overall_stack = cum_stack;
}

static void print_stack_info(struct function_info *fun, struct bfd_link_info *info,
                            const char *f1, size_t stack, size_t cum_stack)
{
    if (!fun->non_root)
        info->callbacks->info("  %s: 0x%v\n", f1, (bfd_vma) cum_stack);
    info->callbacks->minfo("%s: 0x%v 0x%v\n", f1, (bfd_vma) stack, (bfd_vma) cum_stack);
}

static void print_call_info(struct function_info *fun, struct bfd_link_info *info,
                           struct function_info *max)
{
    info->callbacks->minfo(_("  calls:\n"));
    for (struct call_info *call = fun->call_list; call; call = call->next)
    {
        if (!is_normal_call(call) || call->broken_cycle)
            continue;
        
        const char *f2 = func_name(call->fun);
        const char *ann1 = call->fun == max ? "*" : " ";
        const char *ann2 = call->is_tail ? "t" : " ";
        info->callbacks->minfo("   %s%s %s\n", ann1, ann2, f2);
    }
}

static void analyze_stack(struct function_info *fun, struct bfd_link_info *info,
                         struct spu_link_hash_table *htab, struct function_info *max,
                         bool has_call, size_t stack, size_t cum_stack)
{
    if (!htab->params->stack_analysis)
        return;
    
    const char *f1 = func_name(fun);
    print_stack_info(fun, info, f1, stack, cum_stack);
    
    if (has_call)
        print_call_info(fun, info, max);
}

#define STACK_SYM_PREFIX "__stack_"
#define STACK_SYM_FORMAT_GLOBAL "__stack_%s"
#define STACK_SYM_FORMAT_LOCAL "__stack_%x_%s"
#define SEC_ID_MASK 0xffffffff

static char* create_stack_symbol_name(struct function_info *fun, const char *f1)
{
    size_t name_len = 18 + strlen(f1);
    char *name = bfd_malloc(name_len);
    if (name == NULL)
        return NULL;
    
    if (fun->global || ELF_ST_BIND(fun->u.sym->st_info) == STB_GLOBAL)
        sprintf(name, STACK_SYM_FORMAT_GLOBAL, f1);
    else
        sprintf(name, STACK_SYM_FORMAT_LOCAL, fun->sec->id & SEC_ID_MASK, f1);
    
    return name;
}

static void setup_hash_entry(struct elf_link_hash_entry *h, size_t cum_stack)
{
    h->root.type = bfd_link_hash_defined;
    h->root.u.def.section = bfd_abs_section_ptr;
    h->root.u.def.value = cum_stack;
    h->size = 0;
    h->type = 0;
    h->ref_regular = 1;
    h->def_regular = 1;
    h->ref_regular_nonweak = 1;
    h->forced_local = 1;
    h->non_elf = 0;
}

static bool emit_stack_symbol(struct function_info *fun, struct spu_link_hash_table *htab,
                              const char *f1, size_t cum_stack)
{
    char *name = create_stack_symbol_name(fun, f1);
    if (name == NULL)
        return false;
    
    struct elf_link_hash_entry *h = elf_link_hash_lookup(&htab->elf, name, true, true, false);
    free(name);
    
    if (h != NULL && (h->root.type == bfd_link_hash_new ||
                     h->root.type == bfd_link_hash_undefined ||
                     h->root.type == bfd_link_hash_undefweak))
    {
        setup_hash_entry(h, cum_stack);
    }
    
    return true;
}

static bool
sum_stack (struct function_info *fun,
	   struct bfd_link_info *info,
	   void *param)
{
    struct _sum_stack_param *sum_stack_param = param;
    
    size_t cum_stack = fun->stack;
    sum_stack_param->cum_stack = cum_stack;
    
    if (fun->visit3)
        return true;
    
    bool has_call = false;
    struct function_info *max = NULL;
    
    process_calls(fun, info, sum_stack_param, &has_call, &max, &cum_stack);
    
    size_t stack = fun->stack;
    update_function_stack(fun, cum_stack, sum_stack_param);
    
    struct spu_link_hash_table *htab = spu_hash_table(info);
    if (htab->params->auto_overlay)
        return true;
    
    const char *f1 = func_name(fun);
    analyze_stack(fun, info, htab, max, has_call, stack, cum_stack);
    
    if (sum_stack_param->emit_stack_syms)
        return emit_stack_symbol(fun, htab, f1, cum_stack);
    
    return true;
}

/* SEC is part of a pasted function.  Return the call_info for the
   next section of this function.  */

static struct call_info *
find_pasted_call_in_function(struct function_info *fun)
{
  struct call_info *call;
  
  for (call = fun->call_list; call != NULL; call = call->next)
    if (call->is_pasted)
      return call;
  
  return NULL;
}

static struct call_info *
find_pasted_call (asection *sec)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  struct call_info *result;
  int k;

  for (k = 0; k < sinfo->num_fun; ++k)
  {
    result = find_pasted_call_in_function(&sinfo->fun[k]);
    if (result != NULL)
      return result;
  }
  
  abort ();
  return 0;
}

/* qsort predicate to sort bfds by file name.  */

static int
sort_bfds (const void *a, const void *b)
{
  bfd *const *abfd1 = a;
  bfd *const *abfd2 = b;

  return filename_cmp (bfd_get_filename (*abfd1), bfd_get_filename (*abfd2));
}

static const char* get_archive_name(asection *sec)
{
    return sec->owner->my_archive != NULL 
           ? bfd_get_filename(sec->owner->my_archive) 
           : "";
}

static int write_section_entry(FILE *script, asection *sec, struct bfd_link_info *info)
{
    if (sec == NULL)
        return 0;
    
    return fprintf(script, "   %s%c%s (%s)\n",
                   get_archive_name(sec),
                   info->path_separator,
                   bfd_get_filename(sec->owner),
                   sec->name) <= 0 ? -1 : 0;
}

static struct call_info* find_next_pasted_call(struct function_info *call_fun)
{
    struct call_info *call;
    for (call = call_fun->call_list; call; call = call->next)
        if (call->is_pasted)
            break;
    return call;
}

static int process_pasted_calls(FILE *script, asection *sec, 
                                struct bfd_link_info *info,
                                asection* (*get_section_func)(struct function_info*))
{
    struct call_info *call = find_pasted_call(sec);
    
    while (call != NULL)
    {
        struct function_info *call_fun = call->fun;
        asection *target_sec = get_section_func(call_fun);
        
        if (write_section_entry(script, target_sec, info) == -1)
            return -1;
        
        call = find_next_pasted_call(call_fun);
    }
    
    return 0;
}

static asection* get_function_section(struct function_info *fun)
{
    return fun->sec;
}

static asection* get_rodata_section(struct function_info *fun)
{
    return fun->rodata;
}

static int process_overlay_sections(FILE *script, unsigned int base, unsigned int count,
                                   unsigned int ovlynum, unsigned int *ovly_map,
                                   asection **ovly_sections, struct bfd_link_info *info,
                                   int section_offset, int process_segments)
{
    unsigned int j;
    
    for (j = base; j < count && ovly_map[j] == ovlynum; j++)
    {
        asection *sec = ovly_sections[2 * j + section_offset];
        
        if (write_section_entry(script, sec, info) == -1)
            return -1;
        
        if (process_segments && section_offset == 0 && sec->segment_mark)
        {
            if (process_pasted_calls(script, sec, info, get_function_section) == -1)
                return -1;
        }
    }
    
    return j;
}

static int process_rodata_segments(FILE *script, unsigned int base, unsigned int count,
                                  unsigned int ovlynum, unsigned int *ovly_map,
                                  asection **ovly_sections, struct bfd_link_info *info)
{
    unsigned int j;
    
    for (j = base; j < count && ovly_map[j] == ovlynum; j++)
    {
        asection *sec = ovly_sections[2 * j];
        
        if (sec->segment_mark)
        {
            if (process_pasted_calls(script, sec, info, get_rodata_section) == -1)
                return -1;
        }
    }
    
    return 0;
}

static unsigned int
print_one_overlay_section (FILE *script,
                          unsigned int base,
                          unsigned int count,
                          unsigned int ovlynum,
                          unsigned int *ovly_map,
                          asection **ovly_sections,
                          struct bfd_link_info *info)
{
    unsigned int j;
    
    j = process_overlay_sections(script, base, count, ovlynum, ovly_map, 
                                 ovly_sections, info, 0, 1);
    if (j == (unsigned int)-1)
        return -1;
    
    if (process_overlay_sections(script, base, count, ovlynum, ovly_map, 
                                 ovly_sections, info, 1, 0) == (unsigned int)-1)
        return -1;
    
    if (process_rodata_segments(script, base, count, ovlynum, ovly_map, 
                               ovly_sections, info) == -1)
        return -1;
    
    return j;
}

/* Handle --auto-overlay.  */

#define LOAD_SECTION_FLAGS (SEC_ALLOC | SEC_LOAD)
#define ICACHE_FIXED_SIZE_ADJUSTMENT 16
#define QUADWORD_SIZE 16
#define OVERLAY_INIT_PREFIX ".ovl.init"
#define OVLY_LOAD_ENTRY "__ovly_load"
#define ICACHE_BR_HANDLER "__icache_br_handler"

static unsigned int get_section_end(asection *section)
{
  return section->vma + section->size - 1;
}

static void update_load_extents(asection *section, unsigned int *lo, unsigned int *hi)
{
  if (section->size != 0)
  {
    if (section->vma < *lo)
      *lo = section->vma;
    if (get_section_end(section) > *hi)
      *hi = get_section_end(section);
  }
}

static unsigned int find_load_extents(struct bfd_link_info *info)
{
  unsigned int lo = (unsigned int) -1;
  unsigned int hi = 0;
  struct elf_segment_map *m;
  unsigned int i;

  for (m = elf_seg_map(info->output_bfd); m != NULL; m = m->next)
  {
    if (m->p_type == PT_LOAD)
    {
      for (i = 0; i < m->count; i++)
        update_load_extents(m->sections[i], &lo, &hi);
    }
  }
  return hi + 1 - lo;
}

static unsigned int calculate_reserved_size(struct bfd_link_info *info, struct spu_link_hash_table *htab)
{
  unsigned int reserved = htab->params->auto_overlay_reserved;
  if (reserved == 0)
  {
    struct _sum_stack_param sum_stack_param;
    sum_stack_param.emit_stack_syms = 0;
    sum_stack_param.overall_stack = 0;
    if (!for_each_node(sum_stack, info, &sum_stack_param, true))
      return (unsigned int) -1;
    reserved = sum_stack_param.overall_stack + htab->params->extra_stack_space;
  }
  return reserved;
}

static struct elf_link_hash_entry *get_overlay_manager_entry(struct spu_link_hash_table *htab)
{
  const char *entry_name = (htab->params->ovly_flavour == ovly_soft_icache) 
    ? ICACHE_BR_HANDLER : OVLY_LOAD_ENTRY;
  return elf_link_hash_lookup(&htab->elf, entry_name, false, false, false);
}

static unsigned int setup_overlay_manager(struct bfd_link_info *info, struct spu_link_hash_table *htab,
                                          struct _uos_param *uos_param)
{
  struct elf_link_hash_entry *h = get_overlay_manager_entry(htab);
  
  if (h != NULL && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) 
      && h->def_regular)
  {
    uos_param->exclude_input_section = h->root.u.def.section;
    return 0;
  }
  return (*htab->params->spu_elf_load_ovl_mgr)();
}

static bool process_overlay_section(asection *sec, unsigned int *count, 
                                    unsigned int *fixed_size, unsigned int *total_overlay_size)
{
  if (sec->linker_mark)
  {
    if ((sec->flags & SEC_CODE) != 0)
      *count += 1;
    *fixed_size -= sec->size;
    *total_overlay_size += sec->size;
    return true;
  }
  
  if ((sec->flags & LOAD_SECTION_FLAGS) == LOAD_SECTION_FLAGS
      && sec->output_section->owner != NULL
      && startswith(sec->output_section->name, OVERLAY_INIT_PREFIX))
  {
    *fixed_size -= sec->size;
  }
  return false;
}

static unsigned int count_overlay_sections(struct bfd_link_info *info, bfd **bfd_arr,
                                           unsigned int *fixed_size, unsigned int *total_overlay_size)
{
  extern const bfd_target spu_elf32_vec;
  unsigned int count = 0;
  unsigned int bfd_count = 0;
  bfd *ibfd;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
  {
    if (ibfd->xvec != &spu_elf32_vec)
      continue;

    unsigned int old_count = count;
    asection *sec;
    
    for (sec = ibfd->sections; sec != NULL; sec = sec->next)
      process_overlay_section(sec, &count, fixed_size, total_overlay_size);
    
    if (count != old_count)
      bfd_arr[bfd_count++] = ibfd;
  }
  return bfd_count;
}

static bool check_duplicate_files(struct bfd_link_info *info, bfd **bfd_arr, unsigned int bfd_count)
{
  unsigned int i;
  bool ok = true;

  if (bfd_count <= 1)
    return true;

  qsort(bfd_arr, bfd_count, sizeof(*bfd_arr), sort_bfds);
  
  for (i = 1; i < bfd_count; ++i)
  {
    if (filename_cmp(bfd_get_filename(bfd_arr[i - 1]), bfd_get_filename(bfd_arr[i])) == 0)
    {
      if (bfd_arr[i - 1]->my_archive == bfd_arr[i]->my_archive)
      {
        if (bfd_arr[i - 1]->my_archive && bfd_arr[i]->my_archive)
          info->callbacks->einfo(_("%s duplicated in %s\n"),
                                bfd_get_filename(bfd_arr[i]),
                                bfd_get_filename(bfd_arr[i]->my_archive));
        else
          info->callbacks->einfo(_("%s duplicated\n"), bfd_get_filename(bfd_arr[i]));
        ok = false;
      }
    }
  }
  
  if (!ok)
  {
    info->callbacks->einfo(_("sorry, no support for duplicate object files in auto-overlay script\n"));
    bfd_set_error(bfd_error_bad_value);
  }
  return ok;
}

static unsigned int calculate_icache_fixed_size(struct spu_link_hash_table *htab, unsigned int base_size)
{
  unsigned int fixed_size = base_size;
  fixed_size += htab->non_ovly_stub * ICACHE_FIXED_SIZE_ADJUSTMENT;
  fixed_size += QUADWORD_SIZE << htab->num_lines_log2;
  fixed_size += QUADWORD_SIZE << htab->num_lines_log2;
  fixed_size += QUADWORD_SIZE << (htab->fromelem_size_log2 + htab->num_lines_log2);
  fixed_size += QUADWORD_SIZE;
  return fixed_size;
}

static unsigned int calculate_overlay_fixed_size(struct spu_link_hash_table *htab, 
                                                 unsigned int base_size, unsigned int total_overlay_size)
{
  unsigned int ovlynum = (total_overlay_size * 2 * htab->params->num_lines
                         / (htab->local_store - base_size));
  return base_size + ovlynum * QUADWORD_SIZE + QUADWORD_SIZE + 4 + QUADWORD_SIZE;
}

static unsigned int adjust_fixed_size(struct bfd_link_info *info, struct spu_link_hash_table *htab,
                                      unsigned int fixed_size, unsigned int max_overlay_size)
{
  if (fixed_size < htab->params->auto_overlay_fixed)
  {
    unsigned int max_fixed = htab->local_store - max_overlay_size;
    if (max_fixed > htab->params->auto_overlay_fixed)
      max_fixed = htab->params->auto_overlay_fixed;
    
    unsigned int lib_size = max_fixed - fixed_size;
    lib_size = auto_ovl_lib_functions(info, lib_size);
    if (lib_size == (unsigned int) -1)
      return (unsigned int) -1;
    return max_fixed - lib_size;
  }
  return fixed_size;
}

static bool add_dummy_calls(struct function_info *dummy_caller, asection *sec)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  struct call_info *pasty = NULL;
  unsigned int k;

  for (k = 0; k < (unsigned) sinfo->num_fun; ++k)
  {
    struct call_info *call;
    for (call = sinfo->fun[k].call_list; call; call = call->next)
    {
      if (call->is_pasted)
      {
        BFD_ASSERT(pasty == NULL);
        pasty = call;
      }
      else if (call->fun->sec->linker_mark)
      {
        if (!copy_callee(dummy_caller, call))
          return false;
      }
    }
  }

  while (pasty != NULL)
  {
    struct function_info *call_fun = pasty->fun;
    pasty = NULL;
    struct call_info *call;
    for (call = call_fun->call_list; call; call = call->next)
    {
      if (call->is_pasted)
      {
        BFD_ASSERT(pasty == NULL);
        pasty = call;
      }
      else if (!copy_callee(dummy_caller, call))
        return false;
    }
  }
  return true;
}

static unsigned int count_call_stubs(struct function_info *dummy_caller, struct spu_link_hash_table *htab,
                                     asection **ovly_sections, unsigned int base, unsigned int end)
{
  unsigned int num_stubs = 0;
  struct call_info *call;
  unsigned int k;

  for (call = dummy_caller->call_list; call; call = call->next)
  {
    unsigned int stub_delta = (htab->params->ovly_flavour == ovly_soft_icache) ? call->count : 1;
    num_stubs += stub_delta;

    for (k = base; k < end; k++)
    {
      if (call->fun->sec == ovly_sections[2 * k])
      {
        num_stubs -= stub_delta;
        break;
      }
    }
  }
  return num_stubs;
}

static void calculate_pasted_sizes(struct call_info *pasty, unsigned int *tmp, unsigned int *rotmp,
                                   unsigned int *roalign)
{
  while (pasty != NULL)
  {
    struct function_info *call_fun = pasty->fun;
    *tmp = align_power(*tmp, call_fun->sec->alignment_power) + call_fun->sec->size;
    
    if (call_fun->rodata)
    {
      *rotmp = align_power(*rotmp, call_fun->rodata->alignment_power) + call_fun->rodata->size;
      if (*roalign < call_fun->rodata->alignment_power)
        *roalign = call_fun->rodata->alignment_power;
    }
    
    for (pasty = call_fun->call_list; pasty; pasty = pasty->next)
      if (pasty->is_pasted)
        break;
  }
}

static void clear_dummy_calls(struct function_info *dummy_caller)
{
  while (dummy_caller->call_list != NULL)
  {
    struct call_info *call = dummy_caller->call_list;
    dummy_caller->call_list = call->next;
    free(call);
  }
}

static int write_icache_overlay_script(FILE *script, struct spu_link_hash_table *htab,
                                       unsigned int count, unsigned int *ovly_map,
                                       asection **ovly_sections, struct bfd_link_info *info)
{
  if (fprintf(script, "SECTIONS\n{\n") <= 0)
    return -1;

  if (fprintf(script,
             " . = ALIGN (%u);\n"
             " .ovl.init : { *(.ovl.init) }\n"
             " . = ABSOLUTE (ADDR (.ovl.init));\n",
             htab->params->line_size) <= 0)
    return -1;

  unsigned int base = 0;
  unsigned int ovlynum = 1;
  
  while (base < count)
  {
    unsigned int indx = ovlynum - 1;
    unsigned int vma = (indx & (htab->params->num_lines - 1)) << htab->line_size_log2;
    unsigned int lma = vma + (((indx >> htab->num_lines_log2) + 1) << 18);

    if (fprintf(script, " .ovly%u ABSOLUTE (ADDR (.ovl.init)) + %u "
                       ": AT (LOADADDR (.ovl.init) + %u) {\n",
               ovlynum, vma, lma) <= 0)
      return -1;

    base = print_one_overlay_section(script, base, count, ovlynum,
                                     ovly_map, ovly_sections, info);
    if (base == (unsigned) -1)
      return -1;

    if (fprintf(script, "  }\n") <= 0)
      return -1;

    ovlynum++;
  }

  if (fprintf(script, " . = ABSOLUTE (ADDR (.ovl.init)) + %u;\n",
             1 << (htab->num_lines_log2 + htab->line_size_log2)) <= 0)
    return -1;

  if (fprintf(script, "}\nINSERT AFTER .toe;\n") <= 0)
    return -1;

  return 0;
}

static int write_regular_overlay_script(FILE *script, struct spu_link_hash_table *htab,
                                        unsigned int count, unsigned int *ovly_map,
                                        asection **ovly_sections, struct bfd_link_info *info)
{
  unsigned int region, base, ovlynum;

  if (fprintf(script, "SECTIONS\n{\n") <= 0)
    return -1;

  if (fprintf(script,
             " . = ALIGN (16);\n"
             " .ovl.init : { *(.ovl.init) }\n"
             " . = ABSOLUTE (ADDR (.ovl.init));\n") <= 0)
    return -1;

  for (region = 1; region <= htab->params->num_lines; region++)
  {
    ovlynum = region;
    base = 0;
    
    while (base < count && ovly_map[base] < ovlynum)
      base++;

    if (base == count)
      break;

    if (region == 1)
    {
      if (fprintf(script,
                 " OVERLAY : AT (ALIGN (LOADADDR (.ovl.init) + SIZEOF (.ovl.init), 16))\n {\n") <= 0)
        return -1;
    }
    else
    {
      if (fprintf(script, " OVERLAY :\n {\n") <= 0)
        return -1;
    }

    while (base < count)
    {
      if (fprintf(script, "  .ovly%u {\n", ovlynum) <= 0)
        return -1;

      base = print_one_overlay_section(script, base, count, ovlynum,
                                       ovly_map, ovly_sections, info);
      if (base == (unsigned) -1)
        return -1;

      if (fprintf(script, "  }\n") <= 0)
        return -1;

      ovlynum += htab->params->num_lines;
      while (base < count && ovly_map[base] < ovlynum)
        base++;
    }

    if (fprintf(script, " }\n") <= 0)
      return -1;
  }

  if (fprintf(script, "}\nINSERT BEFORE .text;\n") <= 0)
    return -1;

  return 0;
}

static void
spu_elf_auto_overlay(struct bfd_link_info *info)
{
  bfd *ibfd;
  bfd **bfd_arr;
  struct elf_segment_map *m;
  unsigned int fixed_size, lo, hi;
  unsigned int reserved;
  struct spu_link_hash_table *htab;
  unsigned int base, i, count, bfd_count;
  unsigned int region, ovlynum;
  asection **ovly_sections, **ovly_p;
  unsigned int *ovly_map;
  FILE *script;
  unsigned int total_overlay_size, overlay_size;
  const char *ovly_mgr_entry;
  struct elf_link_hash_entry *h;
  struct _mos_param mos_param;
  struct _uos_param uos_param;
  struct function_info dummy_caller;

  fixed_size = find_load_extents(info);

  if (!discover_functions(info))
    goto err_exit;

  if (!build_call_tree(info))
    goto err_exit;

  htab = spu_hash_table(info);
  reserved = calculate_reserved_size(info, htab);
  if (reserved == (unsigned int) -1)
    goto err_exit;

  if (fixed_size + reserved <= htab->local_store
      && htab->params->ovly_flavour != ovly_soft_icache)
  {
    htab->params->auto_overlay = 0;
    return;
  }

  uos_param.exclude_input_section = 0;
  uos_param.exclude_output_section = bfd_get_section_by_name(info->output_bfd, ".interrupt");
  fixed_size += setup_overlay_manager(info, htab, &uos_param);

  mos_param.max_overlay_size = 0;
  if (!for_each_node(mark_overlay_section, info, &mos_param, true))
    goto err_exit;

  uos_param.clearing = 0;
  if ((uos_param.exclude_input_section || uos_param.exclude_output_section)
      && !for_each_node(unmark_overlay_section, info, &uos_param, true))
    goto err_exit;

  bfd_count = 0;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    ++bfd_count;
    
  bfd_arr = bfd_malloc(bfd_count * sizeof(*bfd_arr));
  if (bfd_arr == NULL)
    goto err_exit;

  count = 0;
  total_overlay_size = 0;
  bfd_count = count_overlay_sections(info, bfd_arr, &fixed_size, &total_overlay_size);

  if (!check_duplicate_files(info, bfd_arr, bfd_count))
    goto err_exit;
  free(bfd_arr);

  fixed_size += reserved;
  fixed_size += htab->non_ovly_stub * ovl_stub_size(htab->params);
  
  if (fixed_size + mos_param.max_overlay_size <= htab->local_store)
  {
    if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      fixed_size = calculate_icache_fixed_size(htab, fixed_size);
    }
    else
    {
      fixed_size = calculate_overlay_fixed_size(htab, fixed_size, total_overlay_size);
    }
  }

  if (fixed_size + mos_param.max_overlay_size > htab->local_store)
  {
    info->callbacks->einfo(_("non-overlay size of 0x%v plus maximum overlay "
                            "size of 0x%v exceeds local store\n"),
                          (bfd_vma) fixed_size,
                          (bfd_vma) mos_param.max_overlay_size);
  }
  else
  {
    fixed_size = adjust_fixed_size(info, htab, fixed_size, mos_param.max_overlay_size);
    if (fixed_size == (unsigned int) -1)
      goto err_exit;
  }

  ovly_sections = bfd_malloc(2 * count * sizeof(*ovly_sections));
  if (ovly_sections == NULL)
    goto err_exit;
  ovly_p = ovly_sections;
  if (!for_each_node(collect_overlays, info, &ovly_p, true))
    goto err_exit;
  count = (size_t) (ovly_p - ovly_sections) / 2;
  ovly_map = bfd_malloc(count * sizeof(*ovly_map));
  if (ovly_map == NULL)
    goto err_exit;

  memset(&dummy_caller, 0, sizeof(dummy_caller));
  overlay_size = (htab->local_store - fixed_size) / htab->params->num_lines;
  if (htab->params->line_size != 0)
    overlay_size = htab->params->line_size;
  
  base = 0;
  ovlynum = 0;
  while (base < count)
  {
    unsigned int size = 0, rosize = 0, roalign = 0;

    for (i = base; i < count; i++)
    {
      asection *sec = ovly_sections[2 * i];
      unsigned int tmp = align_power(size, sec->alignment_power) + sec->size;
      unsigned int rotmp = rosize;
      asection *rosec = ovly_sections[2 * i + 1];
      
      if (rosec != NULL)
      {
        rotmp = align_power(rotmp, rosec->alignment_power) + rosec->size;
        if (roalign < rosec->alignment_power)
          roalign = rosec->alignment_power;
      }
      
      if (align_power(tmp, roalign) + rotmp > overlay_size)
        break;
        
      if (sec->segment_mark)
      {
        struct call_info *pasty = find_pasted_call(sec);
        calculate_pasted_sizes(pasty, &tmp, &rotmp, &roalign);
      }
      
      if (align_power(tmp, roalign) + rotmp > overlay_size)
        break;

      if (!add_dummy_calls(&dummy_caller, sec))
        goto err_exit;

      unsigned int num_stubs = count_call_stubs(&dummy_caller, htab, ovly_sections, base, i + 1);
      
      if (htab->params->ovly_flavour == ovly_soft_icache && num_stubs > htab->params->max_branch)
        break;
        
      if (align_power(tmp, roalign) + rotmp + num_stubs * ovl_stub_size(htab->params) > overlay_size)
        break;
        
      size = tmp;
      rosize = rotmp;
    }

    if (i == base)
    {
      info->callbacks->einfo(_("%pB:%pA%s exceeds overlay size\n"),
                            ovly_sections[2 * i]->owner,
                            ovly_sections[2 * i],
                            ovly_sections[2 * i + 1] ? " + rodata" : "");
      bfd_set_error(bfd_error_bad_value);
      goto err_exit;
    }

    clear_dummy_calls(&dummy_caller);
    ++ovlynum;
    while (base < i)
      ovly_map[base++] = ovlynum;
  }

  script = htab->params->spu_elf_open_overlay_script();

  int result;
  if (htab->params->ovly_flavour == ovly_soft_icache)
    result = write_icache_overlay_script(script, htab, count, ovly_map, ovly_sections, info);
  else
    result = write_regular_overlay_script(script, htab, count, ovly_map, ovly_sections, info);

  if (result < 0)
    goto file_err;

  free(ovly_map);
  free(ovly_sections);

  if (fclose(script) != 0)
    goto file_err;

  if (htab->params->auto_overlay & AUTO_RELINK)
    (*htab->params->spu_elf_relink)();

  xexit(0);

file_err:
  bfd_set_error(bfd_error_system_call);
err_exit:
  info->callbacks->fatal(_("%P: auto overlay error: %E\n"));
}

/* Provide an estimate of total stack required.  */

static bool
spu_elf_stack_analysis (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab;
  struct _sum_stack_param sum_stack_param;

  if (!discover_functions (info))
    return false;

  if (!build_call_tree (info))
    return false;

  htab = spu_hash_table (info);
  
  if (htab->params->stack_analysis)
    {
      info->callbacks->info (_("Stack size for call graph root nodes.\n"));
      info->callbacks->minfo (_("\nStack size for functions.  "
				"Annotations: '*' max stack, 't' tail call\n"));
    }

  sum_stack_param.emit_stack_syms = htab->params->emit_stack_syms;
  sum_stack_param.overall_stack = 0;
  
  if (!for_each_node (sum_stack, info, &sum_stack_param, true))
    return false;

  if (htab->params->stack_analysis)
    info->callbacks->info (_("Maximum stack required is 0x%v\n"),
			   (bfd_vma) sum_stack_param.overall_stack);
  
  return true;
}

/* Perform a final link.  */

static bool
should_perform_stack_analysis(struct spu_link_hash_table *htab)
{
  return htab->params->stack_analysis ||
         (htab->params->ovly_flavour == ovly_soft_icache &&
          htab->params->lrlive_analysis);
}

static void
handle_stack_analysis_error(struct bfd_link_info *info)
{
  info->callbacks->einfo(_("%X%P: stack/lrlive analysis error: %E\n"));
}

static void
handle_stub_build_error(struct bfd_link_info *info)
{
  info->callbacks->fatal(_("%P: can not build overlay stubs: %E\n"));
}

static bool
spu_elf_final_link(bfd *output_bfd, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table(info);

  if (htab->params->auto_overlay)
    spu_elf_auto_overlay(info);

  if (should_perform_stack_analysis(htab) && !spu_elf_stack_analysis(info))
    handle_stack_analysis_error(info);

  if (!spu_elf_build_stubs(info))
    handle_stub_build_error(info);

  return bfd_elf_final_link(output_bfd, info);
}

/* Called when not normally emitting relocs, ie. !bfd_link_relocatable (info)
   and !info->emitrelocations.  Returns a count of special relocs
   that need to be emitted.  */

static bfd_boolean
is_ppu_relocation(int r_type)
{
  return r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64;
}

static unsigned int
count_ppu_relocations(Elf_Internal_Rela *relocs, size_t reloc_count)
{
  unsigned int count = 0;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend = relocs + reloc_count;

  for (rel = relocs; rel < relend; rel++)
    {
      int r_type = ELF32_R_TYPE (rel->r_info);
      if (is_ppu_relocation(r_type))
        ++count;
    }

  return count;
}

static void
free_relocs_if_needed(asection *sec, Elf_Internal_Rela *relocs)
{
  if (elf_section_data (sec)->relocs != relocs)
    free (relocs);
}

static unsigned int
spu_elf_count_relocs (struct bfd_link_info *info, asection *sec)
{
  Elf_Internal_Rela *relocs;
  unsigned int count = 0;

  relocs = _bfd_elf_link_read_relocs (sec->owner, sec, NULL, NULL,
                                      info->keep_memory);
  if (relocs != NULL)
    {
      count = count_ppu_relocations(relocs, sec->reloc_count);
      free_relocs_if_needed(sec, relocs);
    }

  return count;
}

/* Functions for adding fixup records to .fixup */

#define FIXUP_RECORD_SIZE 4

#define FIXUP_PUT(output_bfd,htab,index,addr) \
	  bfd_put_32 (output_bfd, addr, \
		      htab->sfixup->contents + FIXUP_RECORD_SIZE * (index))
#define FIXUP_GET(output_bfd,htab,index) \
	  bfd_get_32 (output_bfd, \
		      htab->sfixup->contents + FIXUP_RECORD_SIZE * (index))

/* Store OFFSET in .fixup.  This assumes it will be called with an
   increasing OFFSET.  When this OFFSET fits with the last base offset,
   it just sets a bit, otherwise it adds a new fixup record.  */
static bfd_vma calculate_qaddr(bfd_vma offset)
{
    return offset & ~(bfd_vma) 15;
}

static bfd_vma calculate_bit(bfd_vma offset)
{
    return ((bfd_vma) 8) >> ((offset & 15) >> 2);
}

static void add_new_fixup_record(bfd *output_bfd, struct spu_link_hash_table *htab,
                                 asection *sfixup, bfd_vma value)
{
    if ((sfixup->reloc_count + 1) * FIXUP_RECORD_SIZE > sfixup->size)
        _bfd_error_handler(_("fatal error while creating .fixup"));
    
    FIXUP_PUT(output_bfd, htab, sfixup->reloc_count, value);
    sfixup->reloc_count++;
}

static void update_existing_fixup(bfd *output_bfd, struct spu_link_hash_table *htab,
                                  asection *sfixup, bfd_vma base, bfd_vma bit)
{
    FIXUP_PUT(output_bfd, htab, sfixup->reloc_count - 1, base | bit);
}

static void handle_first_fixup(bfd *output_bfd, struct spu_link_hash_table *htab,
                               asection *sfixup, bfd_vma qaddr, bfd_vma bit)
{
    FIXUP_PUT(output_bfd, htab, 0, qaddr | bit);
    sfixup->reloc_count++;
}

static void handle_subsequent_fixup(bfd *output_bfd, struct spu_link_hash_table *htab,
                                   asection *sfixup, bfd_vma qaddr, bfd_vma bit)
{
    bfd_vma base = FIXUP_GET(output_bfd, htab, sfixup->reloc_count - 1);
    
    if (qaddr != calculate_qaddr(base))
        add_new_fixup_record(output_bfd, htab, sfixup, qaddr | bit);
    else
        update_existing_fixup(output_bfd, htab, sfixup, base, bit);
}

static void spu_elf_emit_fixup(bfd *output_bfd, struct bfd_link_info *info,
                               bfd_vma offset)
{
    struct spu_link_hash_table *htab = spu_hash_table(info);
    asection *sfixup = htab->sfixup;
    bfd_vma qaddr = calculate_qaddr(offset);
    bfd_vma bit = calculate_bit(offset);
    
    if (sfixup->reloc_count == 0)
        handle_first_fixup(output_bfd, htab, sfixup, qaddr, bit);
    else
        handle_subsequent_fixup(output_bfd, htab, sfixup, qaddr, bit);
}

/* Apply RELOCS to CONTENTS of INPUT_SECTION from INPUT_BFD.  */

static bool is_local_symbol(unsigned int r_symndx, Elf_Internal_Shdr *symtab_hdr)
{
    return r_symndx < symtab_hdr->sh_info;
}

static bool resolve_local_symbol(bfd *output_bfd, bfd *input_bfd,
                                 Elf_Internal_Shdr *symtab_hdr,
                                 Elf_Internal_Sym *local_syms,
                                 asection **local_sections,
                                 Elf_Internal_Rela *rel,
                                 unsigned int r_symndx,
                                 Elf_Internal_Sym **sym,
                                 asection **sec,
                                 const char **sym_name,
                                 bfd_vma *relocation)
{
    *sym = local_syms + r_symndx;
    *sec = local_sections[r_symndx];
    *sym_name = bfd_elf_sym_name(input_bfd, symtab_hdr, *sym, *sec);
    *relocation = _bfd_elf_rela_local_sym(output_bfd, *sym, sec, rel);
    return true;
}

static struct elf_link_hash_entry *unwrap_hash_entry(struct bfd_link_info *info,
                                                     bfd *input_bfd,
                                                     asection *input_section,
                                                     struct elf_link_hash_entry *h)
{
    if (info->wrap_hash != NULL && (input_section->flags & SEC_DEBUGGING) != 0)
        h = (struct elf_link_hash_entry *)unwrap_hash_lookup(info, input_bfd, &h->root);
    
    while (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning)
        h = (struct elf_link_hash_entry *)h->root.u.i.link;
    
    return h;
}

static bool get_hash_relocation(struct elf_link_hash_entry *h, 
                                asection **sec,
                                bfd_vma *relocation)
{
    bool unresolved = false;
    
    if (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)
    {
        *sec = h->root.u.def.section;
        if (*sec == NULL || (*sec)->output_section == NULL)
        {
            unresolved = true;
        }
        else
        {
            *relocation = h->root.u.def.value + (*sec)->output_section->vma + (*sec)->output_offset;
        }
    }
    
    return unresolved;
}

static void handle_undefined_symbol(struct bfd_link_info *info,
                                   struct elf_link_hash_entry *h,
                                   bfd *input_bfd,
                                   asection *input_section,
                                   Elf_Internal_Rela *rel,
                                   int r_type)
{
    if (h->root.type == bfd_link_hash_undefweak)
        return;
    
    if (info->unresolved_syms_in_objects == RM_IGNORE && 
        ELF_ST_VISIBILITY(h->other) == STV_DEFAULT)
        return;
    
    if (!bfd_link_relocatable(info) && 
        !(r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64))
    {
        bool err = (info->unresolved_syms_in_objects == RM_DIAGNOSE && 
                   !info->warn_unresolved_syms) ||
                   ELF_ST_VISIBILITY(h->other) != STV_DEFAULT;
        
        info->callbacks->undefined_symbol(info, h->root.root.string, input_bfd,
                                         input_section, rel->r_offset, err);
    }
}

static bool resolve_hash_symbol(struct bfd_link_info *info,
                                bfd *input_bfd,
                                asection *input_section,
                                Elf_Internal_Shdr *symtab_hdr,
                                struct elf_link_hash_entry **sym_hashes,
                                Elf_Internal_Rela *rel,
                                unsigned int r_symndx,
                                int r_type,
                                struct elf_link_hash_entry **h,
                                asection **sec,
                                const char **sym_name,
                                bfd_vma *relocation,
                                bool *unresolved_reloc)
{
    if (sym_hashes == NULL)
        return false;
    
    *h = sym_hashes[r_symndx - symtab_hdr->sh_info];
    *h = unwrap_hash_entry(info, input_bfd, input_section, *h);
    
    *relocation = 0;
    *unresolved_reloc = get_hash_relocation(*h, sec, relocation);
    
    handle_undefined_symbol(info, *h, input_bfd, input_section, rel, r_type);
    
    *sym_name = (*h)->root.root.string;
    return true;
}

static void modify_add_pic_instruction(bfd_byte *contents, Elf_Internal_Rela *rel,
                                      struct elf_link_hash_entry *h)
{
    if (h != NULL && !(h->def_regular || ELF_COMMON_DEF_P(h)))
    {
        bfd_byte *loc = contents + rel->r_offset;
        loc[0] = 0x1c;
        loc[1] = 0x00;
        loc[2] &= 0x3f;
    }
}

static struct got_entry *find_got_entry(struct got_entry *head,
                                       struct spu_link_hash_table *htab,
                                       unsigned int ovl,
                                       bfd_vma addend,
                                       Elf_Internal_Rela *rel,
                                       asection *input_section)
{
    struct got_entry *g;
    
    for (g = head; g != NULL; g = g->next)
    {
        if (htab->params->ovly_flavour == ovly_soft_icache)
        {
            if (g->ovl == ovl && 
                g->br_addr == (rel->r_offset + input_section->output_offset + 
                              input_section->output_section->vma))
                break;
        }
        else
        {
            if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
                break;
        }
    }
    
    return g;
}

static void handle_overlay_stub(struct spu_link_hash_table *htab,
                               struct elf_link_hash_entry *h,
                               bfd *input_bfd,
                               asection *input_section,
                               Elf_Internal_Rela *rel,
                               unsigned int r_symndx,
                               enum _stub_type stub_type,
                               unsigned int iovl,
                               bfd_vma *relocation,
                               bfd_vma *addend)
{
    unsigned int ovl = (stub_type != nonovl_stub) ? iovl : 0;
    struct got_entry **head;
    struct got_entry *g;
    
    if (h != NULL)
        head = &h->got.glist;
    else
        head = elf_local_got_ents(input_bfd) + r_symndx;
    
    g = find_got_entry(*head, htab, ovl, *addend, rel, input_section);
    
    if (g == NULL)
        abort();
    
    *relocation = g->stub_addr;
    *addend = 0;
}

static void encode_soft_icache_overlay(struct spu_link_hash_table *htab,
                                      asection *sec,
                                      int r_type,
                                      bool is_ea_sym,
                                      bfd_vma *relocation)
{
    if (htab->params->ovly_flavour != ovly_soft_icache || is_ea_sym)
        return;
    
    if (r_type != R_SPU_ADDR16_HI && r_type != R_SPU_ADDR32 && r_type != R_SPU_REL32)
        return;
    
    unsigned int ovl = overlay_index(sec);
    if (ovl != 0)
    {
        unsigned int set_id = ((ovl - 1) >> htab->num_lines_log2) + 1;
        *relocation += set_id << 18;
    }
}

static void emit_addr32_fixup(struct spu_link_hash_table *htab,
                             bfd *output_bfd,
                             struct bfd_link_info *info,
                             asection *input_section,
                             Elf_Internal_Rela *rel,
                             int r_type)
{
    if (!htab->params->emit_fixups || bfd_link_relocatable(info))
        return;
    
    if ((input_section->flags & SEC_ALLOC) == 0 || r_type != R_SPU_ADDR32)
        return;
    
    bfd_vma offset = rel->r_offset + input_section->output_section->vma +
                     input_section->output_offset;
    spu_elf_emit_fixup(output_bfd, info, offset);
}

static bool handle_ppu_relocation(Elf_Internal_Rela *rel,
                                 int r_type,
                                 bool is_ea_sym,
                                 asection *ea,
                                 bfd_vma relocation)
{
    if (r_type != R_SPU_PPU32 && r_type != R_SPU_PPU64)
        return false;
    
    if (is_ea_sym)
    {
        rel->r_addend += (relocation - ea->vma +
                         elf_section_data(ea)->this_hdr.sh_offset);
        rel->r_info = ELF32_R_INFO(0, r_type);
    }
    
    return true;
}

static void report_unresolved_relocation(bfd *output_bfd,
                                        bfd *input_bfd,
                                        struct bfd_link_info *info,
                                        asection *input_section,
                                        Elf_Internal_Rela *rel,
                                        reloc_howto_type *howto,
                                        const char *sym_name)
{
    if (_bfd_elf_section_offset(output_bfd, info, input_section,
                                rel->r_offset) != (bfd_vma)-1)
    {
        _bfd_error_handler(_("%pB(%s+%#" PRIx64 "): "
                           "unresolvable %s relocation against symbol `%s'"),
                          input_bfd,
                          bfd_section_name(input_section),
                          (uint64_t)rel->r_offset,
                          howto->name,
                          sym_name);
    }
}

static bool handle_relocation_error(struct bfd_link_info *info,
                                   bfd_reloc_status_type r,
                                   struct elf_link_hash_entry *h,
                                   const char *sym_name,
                                   reloc_howto_type *howto,
                                   bfd *input_bfd,
                                   asection *input_section,
                                   Elf_Internal_Rela *rel)
{
    const char *msg = NULL;
    
    switch (r)
    {
    case bfd_reloc_ok:
        return true;
        
    case bfd_reloc_overflow:
        (*info->callbacks->reloc_overflow)
            (info, (h ? &h->root : NULL), sym_name, howto->name,
             (bfd_vma)0, input_bfd, input_section, rel->r_offset);
        return true;
        
    case bfd_reloc_undefined:
        (*info->callbacks->undefined_symbol)
            (info, sym_name, input_bfd, input_section, rel->r_offset, true);
        return true;
        
    case bfd_reloc_outofrange:
        msg = _("internal error: out of range error");
        break;
        
    case bfd_reloc_notsupported:
        msg = _("internal error: unsupported relocation error");
        break;
        
    case bfd_reloc_dangerous:
        msg = _("internal error: dangerous error");
        break;
        
    default:
        msg = _("internal error: unknown error");
        break;
    }
    
    (*info->callbacks->warning)(info, msg, sym_name, input_bfd,
                               input_section, rel->r_offset);
    return false;
}

static int filter_ppu_relocations(Elf_Internal_Rela *relocs,
                                 asection *input_section,
                                 Elf_Internal_Shdr *rel_hdr)
{
    Elf_Internal_Rela *wrel, *rel, *relend;
    
    wrel = rel = relocs;
    relend = relocs + input_section->reloc_count;
    
    for (; rel < relend; rel++)
    {
        int r_type = ELF32_R_TYPE(rel->r_info);
        if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
            *wrel++ = *rel;
    }
    
    input_section->reloc_count = wrel - relocs;
    rel_hdr->sh_size = input_section->reloc_count * rel_hdr->sh_entsize;
    
    return 2;
}

static int spu_elf_relocate_section(bfd *output_bfd,
                                   struct bfd_link_info *info,
                                   bfd *input_bfd,
                                   asection *input_section,
                                   bfd_byte *contents,
                                   Elf_Internal_Rela *relocs,
                                   Elf_Internal_Sym *local_syms,
                                   asection **local_sections)
{
    Elf_Internal_Shdr *symtab_hdr;
    struct elf_link_hash_entry **sym_hashes;
    Elf_Internal_Rela *rel, *relend;
    struct spu_link_hash_table *htab;
    asection *ea;
    int ret = true;
    bool emit_these_relocs = false;
    bool is_ea_sym;
    bool stubs;
    unsigned int iovl = 0;
    
    htab = spu_hash_table(info);
    stubs = (htab->stub_sec != NULL && maybe_needs_stubs(input_section));
    iovl = overlay_index(input_section);
    ea = bfd_get_section_by_name(output_bfd, "._ea");
    symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
    sym_hashes = (struct elf_link_hash_entry **)(elf_sym_hashes(input_bfd));
    
    rel = relocs;
    relend = relocs + input_section->reloc_count;
    
    for (; rel < relend; rel++)
    {
        int r_type;
        reloc_howto_type *howto;
        unsigned int r_symndx;
        Elf_Internal_Sym *sym;
        asection *sec;
        struct elf_link_hash_entry *h;
        const char *sym_name;
        bfd_vma relocation;
        bfd_vma addend;
        bfd_reloc_status_type r;
        bool unresolved_reloc;
        enum _stub_type stub_type;
        
        r_symndx = ELF32_R_SYM(rel->r_info);
        r_type = ELF32_R_TYPE(rel->r_info);
        howto = elf_howto_table + r_type;
        unresolved_reloc = false;
        h = NULL;
        sym = NULL;
        sec = NULL;
        
        if (is_local_symbol(r_symndx, symtab_hdr))
        {
            resolve_local_symbol(output_bfd, input_bfd, symtab_hdr,
                               local_syms, local_sections, rel, r_symndx,
                               &sym, &sec, &sym_name, &relocation);
        }
        else
        {
            if (!resolve_hash_symbol(info, input_bfd, input_section,
                                    symtab_hdr, sym_hashes, rel,
                                    r_symndx, r_type, &h, &sec,
                                    &sym_name, &relocation, &unresolved_reloc))
                return false;
        }
        
        if (sec != NULL && discarded_section(sec))
            RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section,
                                          rel, 1, relend, R_SPU_NONE,
                                          howto, 0, contents);
        
        if (bfd_link_relocatable(info))
            continue;
        
        if (r_type == R_SPU_ADD_PIC)
            modify_add_pic_instruction(contents, rel, h);
        
        is_ea_sym = (ea != NULL && sec != NULL && sec->output_section == ea);
        
        addend = rel->r_addend;
        
        if (stubs && !is_ea_sym &&
            (stub_type = needs_ovl_stub(h, sym, sec, input_section, rel,
                                       contents, info)) != no_stub)
        {
            handle_overlay_stub(htab, h, input_bfd, input_section, rel,
                              r_symndx, stub_type, iovl, &relocation, &addend);
        }
        else
        {
            encode_soft_icache_overlay(htab, sec, r_type, is_ea_sym, &relocation);
        }
        
        emit_addr32_fixup(htab, output_bfd, info, input_section, rel, r_type);
        
        if (unresolved_reloc)
        {
            if (handle_ppu_relocation(rel, r_type, is_ea_sym, ea, relocation))
            {
                emit_these_relocs = true;
                continue;
            }
            else if (!is_ea_sym)
            {
                report_unresolved_relocation(output_bfd, input_bfd, info,
                                            input_section, rel, howto, sym_name);
                ret = false;
            }
        }
        else if (handle_ppu_relocation(rel, r_type, is_ea_sym, ea, relocation))
        {
            emit_these_relocs = true;
            continue;
        }
        else if (is_ea_sym)
        {
            unresolved_reloc = true;
            report_unresolved_relocation(output_bfd, input_bfd, info,
                                        input_section, rel, howto, sym_name);
            ret = false;
        }
        
        r = _bfd_final_link_relocate(howto, input_bfd, input_section,
                                    contents, rel->r_offset, relocation, addend);
        
        if (!handle_relocation_error(info, r, h, sym_name, howto,
                                    input_bfd, input_section, rel))
            ret = false;
    }
    
    if (ret && emit_these_relocs && !info->emitrelocations)
    {
        Elf_Internal_Shdr *rel_hdr = _bfd_elf_single_rel_hdr(input_section);
        ret = filter_ppu_relocations(relocs, input_section, rel_hdr);
    }
    
    return ret;
}

static bool
spu_elf_finish_dynamic_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
				 struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  return true;
}

/* Adjust _SPUEAR_ syms to point at their overlay stubs.  */

static int is_spuear_symbol_eligible(struct bfd_link_info *info,
                                      struct spu_link_hash_table *htab,
                                      struct elf_link_hash_entry *h)
{
    return !bfd_link_relocatable(info)
           && htab->stub_sec != NULL
           && h != NULL
           && (h->root.type == bfd_link_hash_defined
               || h->root.type == bfd_link_hash_defweak)
           && h->def_regular
           && startswith(h->root.root.string, "_SPUEAR_");
}

static int is_got_entry_matching(struct got_entry *g,
                                  struct spu_link_hash_table *htab)
{
    if (htab->params->ovly_flavour == ovly_soft_icache)
        return g->br_addr == g->stub_addr;
    
    return g->addend == 0 && g->ovl == 0;
}

static void update_symbol_info(Elf_Internal_Sym *sym,
                               struct spu_link_hash_table *htab,
                               struct got_entry *g)
{
    sym->st_shndx = _bfd_elf_section_from_bfd_section(
        htab->stub_sec[0]->output_section->owner,
        htab->stub_sec[0]->output_section);
    sym->st_value = g->stub_addr;
}

static void process_got_entries(Elf_Internal_Sym *sym,
                                struct spu_link_hash_table *htab,
                                struct elf_link_hash_entry *h)
{
    struct got_entry *g;
    
    for (g = h->got.glist; g != NULL; g = g->next) {
        if (is_got_entry_matching(g, htab)) {
            update_symbol_info(sym, htab, g);
            break;
        }
    }
}

static int
spu_elf_output_symbol_hook(struct bfd_link_info *info,
                           const char *sym_name ATTRIBUTE_UNUSED,
                           Elf_Internal_Sym *sym,
                           asection *sym_sec ATTRIBUTE_UNUSED,
                           struct elf_link_hash_entry *h)
{
    struct spu_link_hash_table *htab = spu_hash_table(info);
    
    if (is_spuear_symbol_eligible(info, htab, h))
        process_got_entries(sym, htab, h);
    
    return 1;
}

static int spu_plugin = 0;

void spu_elf_plugin(int val)
{
    spu_plugin = val;
}

/* Set ELF header e_type for plugins.  */

static bool
spu_elf_init_file_header (bfd *abfd, struct bfd_link_info *info)
{
  if (!_bfd_elf_init_file_header (abfd, info))
    return false;

  if (spu_plugin)
    {
      elf_elfheader (abfd)->e_type = ET_DYN;
    }
  return true;
}

/* We may add an extra PT_LOAD segment for .toe.  We also need extra
   segments for overlays.  */

static int
spu_elf_additional_program_headers (bfd *abfd, struct bfd_link_info *info)
{
  int extra = 0;

  if (info != NULL)
    {
      struct spu_link_hash_table *htab = spu_hash_table (info);
      extra = htab->num_overlays;
      if (extra)
        ++extra;
    }

  asection *sec = bfd_get_section_by_name (abfd, ".toe");
  if (sec != NULL && (sec->flags & SEC_LOAD) != 0)
    ++extra;

  return extra;
}

/* Remove .toe section from other PT_LOAD segments and put it in
   a segment of its own.  Put overlays in separate segments too.  */

static bool is_overlay_section(asection *s)
{
    return spu_elf_section_data(s)->u.o.ovl_index != 0;
}

static struct elf_segment_map *create_segment_map(bfd *abfd, unsigned int count)
{
    bfd_vma amt = sizeof(struct elf_segment_map);
    if (count > 1)
        amt += (count - 1) * sizeof(asection *);
    return bfd_zalloc(abfd, amt);
}

static struct elf_segment_map *split_segment_after(bfd *abfd, struct elf_segment_map *m, unsigned int index)
{
    if (index + 1 >= m->count)
        return NULL;
    
    unsigned int remaining = m->count - (index + 1);
    struct elf_segment_map *m2 = create_segment_map(abfd, remaining);
    if (m2 == NULL)
        return NULL;
    
    m2->count = remaining;
    memcpy(m2->sections, m->sections + index + 1, remaining * sizeof(m->sections[0]));
    m2->p_type = PT_LOAD;
    m2->next = m->next;
    m->next = m2;
    
    return m2;
}

static struct elf_segment_map *split_segment_before(bfd *abfd, struct elf_segment_map *m, unsigned int index, asection *s)
{
    struct elf_segment_map *m2 = create_segment_map(abfd, 1);
    if (m2 == NULL)
        return NULL;
    
    m2->p_type = PT_LOAD;
    m2->count = 1;
    m2->sections[0] = s;
    m2->next = m->next;
    m->next = m2;
    m->count = index;
    
    return m2;
}

static bool isolate_special_section(bfd *abfd, struct elf_segment_map *m, unsigned int i, asection *s)
{
    if (split_segment_after(abfd, m, i) == NULL && i + 1 < m->count)
        return false;
    
    m->count = 1;
    
    if (i != 0)
    {
        if (split_segment_before(abfd, m, i, s) == NULL)
            return false;
    }
    
    return true;
}

static bool process_load_segments(bfd *abfd, asection *toe)
{
    for (struct elf_segment_map *m = elf_seg_map(abfd); m != NULL; m = m->next)
    {
        if (m->p_type != PT_LOAD || m->count <= 1)
            continue;
        
        for (unsigned int i = 0; i < m->count; i++)
        {
            asection *s = m->sections[i];
            if (s == toe || is_overlay_section(s))
            {
                if (!isolate_special_section(abfd, m, i, s))
                    return false;
                break;
            }
        }
    }
    return true;
}

static void move_overlay_segments(struct elf_segment_map **p, struct elf_segment_map **p_overlay, struct elf_segment_map **first_load)
{
    while (*p != NULL)
    {
        if ((*p)->p_type == PT_LOAD)
        {
            if (!*first_load)
                *first_load = p;
            
            if ((*p)->count == 1 && is_overlay_section((*p)->sections[0]))
            {
                struct elf_segment_map *m = *p;
                m->no_sort_lma = 1;
                *p = m->next;
                *p_overlay = m;
                p_overlay = &m->next;
                continue;
            }
        }
        p = &((*p)->next);
    }
}

static void reinsert_overlay_segments(struct elf_segment_map **first_load, struct elf_segment_map *m_overlay)
{
    struct elf_segment_map **p = first_load;
    
    if (*p != NULL && (*p)->p_type == PT_LOAD && (*p)->includes_filehdr)
        p = &(*p)->next;
    
    struct elf_segment_map **p_overlay = &m_overlay;
    while (*p_overlay && (*p_overlay)->next)
        p_overlay = &(*p_overlay)->next;
    
    *p_overlay = *p;
    *p = m_overlay;
}

static bool
spu_elf_modify_segment_map (bfd *abfd, struct bfd_link_info *info)
{
    if (info == NULL)
        return true;
    
    asection *toe = bfd_get_section_by_name(abfd, ".toe");
    
    if (!process_load_segments(abfd, toe))
        return false;
    
    struct elf_segment_map **p = &elf_seg_map(abfd);
    struct elf_segment_map *m_overlay = NULL;
    struct elf_segment_map **p_overlay = &m_overlay;
    struct elf_segment_map **first_load = NULL;
    
    move_overlay_segments(p, p_overlay, &first_load);
    
    if (m_overlay != NULL)
        reinsert_overlay_segments(first_load, m_overlay);
    
    return true;
}

/* Tweak the section type of .note.spu_name.  */

static bool
spu_elf_fake_sections (bfd *obfd ATTRIBUTE_UNUSED,
		       Elf_Internal_Shdr *hdr,
		       asection *sec)
{
  if (strcmp (sec->name, SPU_PTNOTE_SPUNAME) == 0)
    hdr->sh_type = SHT_NOTE;
  return true;
}

/* Tweak phdrs before writing them out.  */

static bool
spu_elf_modify_headers (bfd *abfd, struct bfd_link_info *info)
{
  if (info != NULL)
    {
      process_spu_headers(abfd, info);
    }

  return _bfd_elf_modify_headers (abfd, info);
}

static void
process_spu_headers(bfd *abfd, struct bfd_link_info *info)
{
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf_obj_tdata *tdata = elf_tdata (abfd);
  Elf_Internal_Phdr *phdr = tdata->phdr;
  unsigned int count = elf_program_header_size (abfd) / bed->s->sizeof_phdr;
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (htab->num_overlays != 0)
    {
      process_overlays(abfd, htab, phdr);
    }

  adjust_load_segments(phdr, count);
}

static void
process_overlays(bfd *abfd, struct spu_link_hash_table *htab, Elf_Internal_Phdr *phdr)
{
  struct elf_segment_map *m;
  unsigned int i = 0;

  for (m = elf_seg_map (abfd); m; m = m->next, ++i)
    {
      if (should_mark_overlay(m))
        {
          mark_overlay_header(htab, phdr, i, m);
        }
    }

  update_soft_icache_offset(htab);
}

static bool
should_mark_overlay(struct elf_segment_map *m)
{
  if (m->count == 0)
    return false;
  
  unsigned int ovl_index = spu_elf_section_data (m->sections[0])->u.o.ovl_index;
  return ovl_index != 0;
}

static void
mark_overlay_header(struct spu_link_hash_table *htab, Elf_Internal_Phdr *phdr, 
                   unsigned int i, struct elf_segment_map *m)
{
  phdr[i].p_flags |= PF_OVERLAY;
  
  if (should_write_ovly_table(htab))
    {
      write_ovly_table_offset(htab, phdr[i].p_offset, m);
    }
}

static bool
should_write_ovly_table(struct spu_link_hash_table *htab)
{
  return htab->ovtab != NULL && 
         htab->ovtab->size != 0 &&
         htab->params->ovly_flavour != ovly_soft_icache;
}

static void
write_ovly_table_offset(struct spu_link_hash_table *htab, bfd_vma offset,
                        struct elf_segment_map *m)
{
  unsigned int ovl_index = spu_elf_section_data (m->sections[0])->u.o.ovl_index;
  bfd_byte *p = htab->ovtab->contents;
  unsigned int off = ovl_index * 16 + 8;
  
  bfd_put_32 (htab->ovtab->owner, offset, p + off);
}

static void
update_soft_icache_offset(struct spu_link_hash_table *htab)
{
  if (htab->init != NULL && htab->init->size != 0)
    {
      bfd_vma val = elf_section_data (htab->ovl_sec[0])->this_hdr.sh_offset;
      bfd_put_32 (htab->init->owner, val, htab->init->contents + 4);
    }
}

#define ALIGNMENT_MASK 15

static void
adjust_load_segments(Elf_Internal_Phdr *phdr, unsigned int count)
{
  if (!can_safely_adjust_segments(phdr, count))
    return;
  
  apply_segment_adjustments(phdr, count);
}

static bool
can_safely_adjust_segments(Elf_Internal_Phdr *phdr, unsigned int count)
{
  Elf_Internal_Phdr *last = NULL;
  
  for (unsigned int i = count; i-- != 0; )
    {
      if (phdr[i].p_type != PT_LOAD)
        continue;
        
      if (!check_filesz_adjustment(&phdr[i], last))
        return false;
        
      if (!check_memsz_adjustment(&phdr[i], last))
        return false;
        
      if (phdr[i].p_filesz != 0)
        last = &phdr[i];
    }
  
  return true;
}

static bool
check_filesz_adjustment(Elf_Internal_Phdr *current, Elf_Internal_Phdr *last)
{
  unsigned adjust = -current->p_filesz & ALIGNMENT_MASK;
  
  if (adjust == 0 || last == NULL)
    return true;
    
  return (current->p_offset + current->p_filesz <= last->p_offset - adjust);
}

static bool
check_memsz_adjustment(Elf_Internal_Phdr *current, Elf_Internal_Phdr *last)
{
  unsigned adjust = -current->p_memsz & ALIGNMENT_MASK;
  
  if (adjust == 0 || last == NULL || current->p_filesz == 0)
    return true;
    
  bfd_vma current_end = current->p_vaddr + current->p_memsz;
  bfd_vma last_adjusted = last->p_vaddr - adjust;
  
  return !(current_end > last_adjusted && current_end <= last->p_vaddr);
}

static void
apply_segment_adjustments(Elf_Internal_Phdr *phdr, unsigned int count)
{
  for (unsigned int i = count; i-- != 0; )
    {
      if (phdr[i].p_type == PT_LOAD)
        {
          apply_single_segment_adjustment(&phdr[i]);
        }
    }
}

static void
apply_single_segment_adjustment(Elf_Internal_Phdr *segment)
{
  unsigned filesz_adjust = -segment->p_filesz & ALIGNMENT_MASK;
  segment->p_filesz += filesz_adjust;
  
  unsigned memsz_adjust = -segment->p_memsz & ALIGNMENT_MASK;
  segment->p_memsz += memsz_adjust;
}

#define FIXUP_ALIGNMENT 16
#define ADDR32_QUADWORD_MASK (~(bfd_vma) 15)

static bool
should_process_section(asection *isec)
{
    return (isec->flags & SEC_ALLOC) != 0
        && (isec->flags & SEC_RELOC) != 0
        && isec->reloc_count != 0;
}

static int
count_addr32_fixups(Elf_Internal_Rela *internal_relocs, size_t reloc_count)
{
    int fixup_count = 0;
    bfd_vma base_end = 0;
    Elf_Internal_Rela *irela = internal_relocs;
    Elf_Internal_Rela *irelaend = irela + reloc_count;
    
    for (; irela < irelaend; irela++)
    {
        if (ELF32_R_TYPE(irela->r_info) == R_SPU_ADDR32
            && irela->r_offset >= base_end)
        {
            base_end = (irela->r_offset & ADDR32_QUADWORD_MASK) + FIXUP_ALIGNMENT;
            fixup_count++;
        }
    }
    
    return fixup_count;
}

static int
count_fixups_in_section(bfd *ibfd, asection *isec, struct bfd_link_info *info)
{
    Elf_Internal_Rela *internal_relocs;
    int fixup_count;
    
    if (!should_process_section(isec))
        return 0;
    
    internal_relocs = _bfd_elf_link_read_relocs(ibfd, isec, NULL, NULL,
                                                info->keep_memory);
    if (internal_relocs == NULL)
        return -1;
    
    fixup_count = count_addr32_fixups(internal_relocs, isec->reloc_count);
    
    return fixup_count;
}

static int
count_fixups_in_bfd(bfd *ibfd, struct bfd_link_info *info)
{
    asection *isec;
    int total_fixups = 0;
    
    if (bfd_get_flavour(ibfd) != bfd_target_elf_flavour)
        return 0;
    
    for (isec = ibfd->sections; isec != NULL; isec = isec->next)
    {
        int section_fixups = count_fixups_in_section(ibfd, isec, info);
        if (section_fixups < 0)
            return -1;
        total_fixups += section_fixups;
    }
    
    return total_fixups;
}

static int
count_all_fixups(struct bfd_link_info *info)
{
    bfd *ibfd;
    int fixup_count = 0;
    
    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
        int bfd_fixups = count_fixups_in_bfd(ibfd, info);
        if (bfd_fixups < 0)
            return -1;
        fixup_count += bfd_fixups;
    }
    
    return fixup_count;
}

static bool
allocate_fixup_section(asection *sfixup, int fixup_count, struct bfd_link_info *info)
{
    size_t size = (fixup_count + 1) * FIXUP_RECORD_SIZE;
    
    if (!bfd_set_section_size(sfixup, size))
        return false;
    
    sfixup->contents = (bfd_byte *) bfd_zalloc(info->input_bfds, size);
    if (sfixup->contents == NULL)
        return false;
    
    sfixup->alloced = 1;
    return true;
}

bool
spu_elf_size_sections(bfd *obfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
    struct spu_link_hash_table *htab = spu_hash_table(info);
    
    if (!htab->params->emit_fixups)
        return true;
    
    int fixup_count = count_all_fixups(info);
    if (fixup_count < 0)
        return false;
    
    return allocate_fixup_section(htab->sfixup, fixup_count, info);
}

#define TARGET_BIG_SYM		spu_elf32_vec
#define TARGET_BIG_NAME		"elf32-spu"
#define ELF_ARCH		bfd_arch_spu
#define ELF_TARGET_ID		SPU_ELF_DATA
#define ELF_MACHINE_CODE	EM_SPU
/* This matches the alignment need for DMA.  */
#define ELF_MAXPAGESIZE		0x80
#define elf_backend_rela_normal		1
#define elf_backend_can_gc_sections	1

#define bfd_elf32_bfd_reloc_type_lookup		spu_elf_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup		spu_elf_reloc_name_lookup
#define elf_info_to_howto			spu_elf_info_to_howto
#define elf_backend_count_relocs		spu_elf_count_relocs
#define elf_backend_relocate_section		spu_elf_relocate_section
#define elf_backend_finish_dynamic_sections	spu_elf_finish_dynamic_sections
#define elf_backend_symbol_processing		spu_elf_backend_symbol_processing
#define elf_backend_link_output_symbol_hook	spu_elf_output_symbol_hook
#define elf_backend_object_p			spu_elf_object_p
#define bfd_elf32_new_section_hook		spu_elf_new_section_hook
#define bfd_elf32_bfd_link_hash_table_create	spu_elf_link_hash_table_create

#define elf_backend_additional_program_headers	spu_elf_additional_program_headers
#define elf_backend_modify_segment_map		spu_elf_modify_segment_map
#define elf_backend_modify_headers		spu_elf_modify_headers
#define elf_backend_init_file_header		spu_elf_init_file_header
#define elf_backend_fake_sections		spu_elf_fake_sections
#define elf_backend_special_sections		spu_elf_special_sections
#define bfd_elf32_bfd_final_link		spu_elf_final_link

#include "elf32-target.h"
