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

static enum elf_spu_reloc_type spu_elf_bfd_to_reloc_type (bfd_reloc_code_real_type code) {
  switch (code) {
    case BFD_RELOC_NONE: return R_SPU_NONE;
    case BFD_RELOC_SPU_IMM10W: return R_SPU_ADDR10;
    case BFD_RELOC_SPU_IMM16W: return R_SPU_ADDR16;
    case BFD_RELOC_SPU_LO16: return R_SPU_ADDR16_LO;
    case BFD_RELOC_SPU_HI16: return R_SPU_ADDR16_HI;
    case BFD_RELOC_SPU_IMM18: return R_SPU_ADDR18;
    case BFD_RELOC_SPU_PCREL16: return R_SPU_REL16;
    case BFD_RELOC_SPU_IMM7: return R_SPU_ADDR7;
    case BFD_RELOC_SPU_IMM8: return R_SPU_NONE;
    case BFD_RELOC_SPU_PCREL9a: return R_SPU_REL9;
    case BFD_RELOC_SPU_PCREL9b: return R_SPU_REL9I;
    case BFD_RELOC_SPU_IMM10: return R_SPU_ADDR10I;
    case BFD_RELOC_SPU_IMM16: return R_SPU_ADDR16I;
    case BFD_RELOC_32: return R_SPU_ADDR32;
    case BFD_RELOC_32_PCREL: return R_SPU_REL32;
    case BFD_RELOC_SPU_PPU32: return R_SPU_PPU32;
    case BFD_RELOC_SPU_PPU64: return R_SPU_PPU64;
    case BFD_RELOC_SPU_ADD_PIC: return R_SPU_ADD_PIC;
    default: return (enum elf_spu_reloc_type) -1;
  }
}

typedef enum {
  /* Assuming R_SPU_0 to R_SPU_N are defined here */
  R_SPU_max
} elf_spu_reloc_type;

static bool spu_elf_info_to_howto(bfd *abfd, arelent *cache_ptr, Elf_Internal_Rela *dst) {
  elf_spu_reloc_type r_type = (elf_spu_reloc_type) ELF32_R_TYPE(dst->r_info);

  if (r_type >= R_SPU_max) {
    _bfd_error_handler(_("%pB: unsupported relocation type %#x"), abfd, r_type);
    bfd_set_error(bfd_error_bad_value);
    return false;
  }

  cache_ptr->howto = &elf_howto_table[r_type];
  return true;
}

static reloc_howto_type *spu_elf_reloc_type_lookup(bfd *abfd ATTRIBUTE_UNUSED, bfd_reloc_code_real_type code) {
    enum elf_spu_reloc_type r_type = spu_elf_bfd_to_reloc_type(code);
    return (r_type == (enum elf_spu_reloc_type) -1) ? NULL : (elf_howto_table + r_type);
}

static reloc_howto_type *spu_elf_reloc_name_lookup(bfd *abfd ATTRIBUTE_UNUSED, const char *r_name) {
  size_t table_size = sizeof(elf_howto_table) / sizeof(elf_howto_table[0]);
  for (size_t i = 0; i < table_size; i++) {
    if (elf_howto_table[i].name && strcasecmp(elf_howto_table[i].name, r_name) == 0) {
      return &elf_howto_table[i];
    }
  }
  return NULL;
}

/* Apply R_SPU_REL9 and R_SPU_REL9I relocs.  */

static bfd_reloc_status_type spu_elf_rel9(bfd *abfd, arelent *reloc_entry, asymbol *symbol,
                                          void *data, asection *input_section,
                                          bfd *output_bfd, char **error_message) {
    if (output_bfd != NULL) {
        return bfd_elf_generic_reloc(abfd, reloc_entry, symbol, data, 
                                     input_section, output_bfd, error_message);
    }

    if (reloc_entry->address > bfd_get_section_limit(abfd, input_section)) {
        return bfd_reloc_outofrange;
    }

    bfd_size_type octets = reloc_entry->address * OCTETS_PER_BYTE(abfd, input_section);
    bfd_vma val = 0;

    if (!bfd_is_com_section(symbol->section)) {
        val = symbol->value;
    }

    if (symbol->section->output_section) {
        val += symbol->section->output_section->vma;
    }

    val += reloc_entry->addend;
    val -= (input_section->output_section->vma + input_section->output_offset);
    val >>= 2;

    if (val + 256 >= 512) {
        return bfd_reloc_overflow;
    }

    long insn = bfd_get_32(abfd, (bfd_byte *)data + octets);
    val = (val & 0x7f) | ((val & 0x180) << 7) | ((val & 0x180) << 16);

    insn &= ~reloc_entry->howto->dst_mask;
    insn |= val & reloc_entry->howto->dst_mask;

    bfd_put_32(abfd, insn, (bfd_byte *)data + octets);
    
    return bfd_reloc_ok;
}

#include <stdbool.h>

static bool spu_elf_new_section_hook(bfd *abfd, asection *sec) {
    struct _spu_elf_section_data *sdata = bfd_zalloc(abfd, sizeof(*sdata));

    if (!sdata) {
        return false;
    }

    sec->used_by_bfd = sdata;
    return _bfd_elf_new_section_hook(abfd, sec);
}

/* Set up overlay info for executables.  */

static bool spu_elf_object_p(bfd *abfd) {
    if ((abfd->flags & (EXEC_P | DYNAMIC)) == 0) {
        return true;
    }

    unsigned int num_buf = 0, num_ovl = 0;
    Elf_Internal_Phdr *phdr = elf_tdata(abfd)->phdr;
    Elf_Internal_Ehdr *ehdr = elf_elfheader(abfd);
    Elf_Internal_Phdr *last_phdr = NULL;

    for (unsigned int i = 0; i < ehdr->e_phnum; i++, phdr++) {
        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_OVERLAY) == 0) {
            continue;
        }

        num_ovl++;
        if (!last_phdr || ((last_phdr->p_vaddr ^ phdr->p_vaddr) & 0x3FFFF) != 0) {
            num_buf++;
        }
        last_phdr = phdr;

        unsigned int num_sections = elf_numsections(abfd);
        Elf_Internal_Shdr **sections = elf_elfsections(abfd);

        for (unsigned int j = 0; j < num_sections; j++) {
            Elf_Internal_Shdr *shdr = sections[j];
            asection *sec = shdr->bfd_section;

            if (sec && ELF_SECTION_SIZE(shdr, phdr) && ELF_SECTION_IN_SEGMENT(shdr, phdr)) {
                spu_elf_section_data(sec)->u.o.ovl_index = num_ovl;
                spu_elf_section_data(sec)->u.o.ovl_buf = num_buf;
            }
        }
    }
    return true;
}

/* Specially mark defined symbols named _EAR_* with BSF_KEEP so that
   strip --strip-unneeded will not remove them.  */

static void spu_elf_backend_symbol_processing(bfd *abfd, asymbol *sym) {
    if (sym != NULL && sym->name != NULL && sym->section != bfd_abs_section_ptr && strncmp(sym->name, "_EAR_", 5) == 0) {
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

static struct bfd_link_hash_table *spu_elf_link_hash_table_create(bfd *abfd) {
    struct spu_link_hash_table *htab = bfd_zmalloc(sizeof(*htab));
    if (!htab) return NULL;

    if (!_bfd_elf_link_hash_table_init(&htab->elf, abfd, _bfd_elf_link_hash_newfunc, sizeof(struct elf_link_hash_entry))) {
        free(htab);
        return NULL;
    }

    htab->elf.init_got_refcount = (struct got_refcount){0, NULL};
    htab->elf.init_got_offset = (struct got_offset){0, NULL};

    return &htab->elf.root;
}

void spu_elf_setup(struct bfd_link_info *info, struct spu_elf_params *params) {
    struct spu_link_hash_table *htab = spu_hash_table(info);

    if (htab == NULL || params == NULL) {
        return; // Handle error condition
    }

    htab->params = params;
    htab->line_size_log2 = bfd_log2(params->line_size);
    htab->num_lines_log2 = bfd_log2(params->num_lines);

    bfd_vma max_branch_log2 = bfd_log2(params->max_branch);
    htab->fromelem_size_log2 = (max_branch_log2 > 4) ? (max_branch_log2 - 4) : 0;
}

/* Find the symbol for the given R_SYMNDX in IBFD and set *HP and *SYMP
   to (hash, NULL) for global symbols, and (NULL, sym) for locals.  Set
   *SYMSECP to the symbol's section.  *LOCSYMSP caches local syms.  */

bool get_sym_h(struct elf_link_hash_entry **hp, Elf_Internal_Sym **symp, asection **symsecp, Elf_Internal_Sym **locsymsp, unsigned long r_symndx, bfd *ibfd) {
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;

    if (r_symndx >= symtab_hdr->sh_info) {
        struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(ibfd);
        struct elf_link_hash_entry *h = sym_hashes[r_symndx - symtab_hdr->sh_info];

        while (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning) {
            h = (struct elf_link_hash_entry *)h->root.u.i.link;
        }
        
        if (hp) *hp = h;
        if (symp) *symp = NULL;
        
        if (symsecp) {
            *symsecp = (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) ? h->root.u.def.section : NULL;
        }
    } else {
        if (!*locsymsp) {
            *locsymsp = (Elf_Internal_Sym *)symtab_hdr->contents ? (Elf_Internal_Sym *)symtab_hdr->contents : bfd_elf_get_elf_syms(ibfd, symtab_hdr, symtab_hdr->sh_info, 0, NULL, NULL, NULL);
            if (!*locsymsp) return false;
        }
        Elf_Internal_Sym *sym = *locsymsp + r_symndx;

        if (hp) *hp = NULL;
        if (symp) *symp = sym;
        if (symsecp) *symsecp = bfd_section_from_elf_index(ibfd, sym->st_shndx);
    }
    return true;
}

/* Create the note section if not already present.  This is done early so
   that the linker maps the sections to the right place in the output.  */

#include <stdbool.h>
#include <string.h>
#include "spu_elf.h" // Assuming necessary includes and definitions are in these headers
#include "bfd.h"

// Function to safely create and initialize a section with proper error handling
static asection *create_section(bfd *ibfd, const char *name, flagword flags, unsigned int alignment, size_t size) {
    asection *s = bfd_make_section_anyway_with_flags(ibfd, name, flags);
    if (s == NULL || !bfd_set_section_alignment(s, alignment) || !bfd_set_section_size(s, size)) {
        return NULL;
    }
    return s;
}

bool spu_elf_create_sections(struct bfd_link_info *info) {
    struct spu_link_hash_table *htab = spu_hash_table(info);
    bfd *ibfd = info->input_bfds;

    // Check if the SPU_PTNOTE_SPUNAME section exists
    while (ibfd != NULL && bfd_get_section_by_name(ibfd, SPU_PTNOTE_SPUNAME) == NULL) {
        ibfd = ibfd->link.next;
    }

    // If section doesn't exist, create it
    if (ibfd == NULL) {
        ibfd = info->input_bfds;
        flagword flags = SEC_LOAD | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
        size_t name_len = strlen(bfd_get_filename(info->output_bfd)) + 1;
        size_t size = 12 + ((sizeof(SPU_PLUGIN_NAME) + 3) & -4);
        size += (name_len + 3) & -4;

        asection *s = create_section(ibfd, SPU_PTNOTE_SPUNAME, flags, 4, size);
        if (s == NULL) return false;

        bfd_byte *data = bfd_zalloc(ibfd, size);
        if (data == NULL) return false;

        bfd_put_32(ibfd, sizeof(SPU_PLUGIN_NAME), data);
        bfd_put_32(ibfd, name_len, data + 4);
        bfd_put_32(ibfd, 1, data + 8);
        memcpy(data + 12, SPU_PLUGIN_NAME, sizeof(SPU_PLUGIN_NAME));
        memcpy(data + 12 + ((sizeof(SPU_PLUGIN_NAME) + 3) & -4), bfd_get_filename(info->output_bfd), name_len);
        s->contents = data;
        s->alloced = 1;

        elf_section_type(s) = SHT_NOTE;
    }

    if (htab->params->emit_fixups) {
        if (htab->elf.dynobj == NULL) {
            htab->elf.dynobj = ibfd;
        }
        ibfd = htab->elf.dynobj;
        flagword fixup_flags = SEC_LOAD | SEC_ALLOC | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY | SEC_LINKER_CREATED;
        htab->sfixup = create_section(ibfd, ".fixup", fixup_flags, 2, 0);
        if (htab->sfixup == NULL) return false;
    }

    return true;
}

/* qsort predicate to sort sections by vma.  */

static int sort_sections(const void *a, const void *b) {
    const asection *const *s1 = a;
    const asection *const *s2 = b;

    if ((*s1)->vma != (*s2)->vma) {
        return (*s1)->vma < (*s2)->vma ? -1 : 1;
    }
    
    return ((*s1)->index < (*s2)->index) ? -1 : ((*s1)->index > (*s2)->index) ? 1 : 0;
}

/* Identify overlays in the output bfd, and number them.
   Returns 0 on error, 1 if no overlays, 2 if overlays.  */

int spu_elf_find_overlays(struct bfd_link_info *info) {
    struct spu_link_hash_table *htab = spu_hash_table(info);
    unsigned int section_count = info->output_bfd->section_count;
    if (section_count < 2) return 1;

    asection **alloc_sec = bfd_malloc(section_count * sizeof(*alloc_sec));
    if (!alloc_sec) return 0;

    unsigned int n = 0;
    for (asection *s = info->output_bfd->sections; s; s = s->next) {
        if ((s->flags & SEC_ALLOC) && (s->flags & (SEC_LOAD | SEC_THREAD_LOCAL)) != SEC_THREAD_LOCAL && s->size != 0) {
            alloc_sec[n++] = s;
        }
    }

    if (n == 0) {
        free(alloc_sec);
        return 1;
    }

    qsort(alloc_sec, n, sizeof(*alloc_sec), sort_sections);

    bfd_vma ovl_end = alloc_sec[0]->vma + alloc_sec[0]->size;
    if (htab->params->ovly_flavour == ovly_soft_icache) {
        unsigned int prev_buf = 0, set_id = 0;
        bfd_vma vma_start = 0;

        unsigned int i = 1;
        for (; i < n; i++) {
            if (alloc_sec[i]->vma < ovl_end) {
                vma_start = alloc_sec[i - 1]->vma;
                ovl_end = vma_start + ((bfd_vma)1 << (htab->num_lines_log2 + htab->line_size_log2));
                i--;
                break;
            }
            ovl_end = alloc_sec[i]->vma + alloc_sec[i]->size;
        }

        unsigned int ovl_index = 0, num_buf = 0;
        for (; i < n; i++) {
            asection *s = alloc_sec[i];
            if (s->vma >= ovl_end) break;
            if (!startswith(s->name, ".ovl.init")) {
                num_buf = ((s->vma - vma_start) >> htab->line_size_log2) + 1;
                set_id = (num_buf == prev_buf) ? set_id + 1 : 0;
                prev_buf = num_buf;

                if ((s->vma - vma_start) & (htab->params->line_size - 1)) {
                    info->callbacks->einfo(_("%X%P: overlay section %pA does not start on a cache line\n"), s);
                    bfd_set_error(bfd_error_bad_value);
                    return 0;
                }
                if (s->size > htab->params->line_size) {
                    info->callbacks->einfo(_("%X%P: overlay section %pA is larger than a cache line\n"), s);
                    bfd_set_error(bfd_error_bad_value);
                    return 0;
                }

                alloc_sec[ovl_index++] = s;
                spu_elf_section_data(s)->u.o.ovl_index = (set_id << htab->num_lines_log2) + num_buf;
                spu_elf_section_data(s)->u.o.ovl_buf = num_buf;
            }
        }

        for (; i < n; i++) {
            if (alloc_sec[i]->vma < ovl_end) {
                info->callbacks->einfo(_("%X%P: overlay section %pA is not in cache area\n"), alloc_sec[i - 1]);
                bfd_set_error(bfd_error_bad_value);
                return 0;
            }
            ovl_end = alloc_sec[i]->vma + alloc_sec[i]->size;
        }
    } else {
        unsigned int ovl_index = 0, num_buf = 0;
        for (unsigned int i = 1; i < n; i++) {
            asection *s = alloc_sec[i];
            if (s->vma < ovl_end) {
                asection *s0 = alloc_sec[i - 1];
                if (spu_elf_section_data(s0)->u.o.ovl_index == 0) {
                    num_buf++;
                    if (!startswith(s0->name, ".ovl.init")) {
                        alloc_sec[ovl_index] = s0;
                        spu_elf_section_data(s0)->u.o.ovl_index = ++ovl_index;
                        spu_elf_section_data(s0)->u.o.ovl_buf = num_buf;
                    } else {
                        ovl_end = s->vma + s->size;
                    }
                }
                if (!startswith(s->name, ".ovl.init")) {
                    alloc_sec[ovl_index] = s;
                    spu_elf_section_data(s)->u.o.ovl_index = ++ovl_index;
                    spu_elf_section_data(s)->u.o.ovl_buf = num_buf;
                    if (s0->vma != s->vma) {
                        info->callbacks->einfo(_("%X%P: overlay sections %pA and %pA do not start at the same address\n"), s0, s);
                        bfd_set_error(bfd_error_bad_value);
                        return 0;
                    }
                    if (ovl_end < s->vma + s->size) ovl_end = s->vma + s->size;
                }
            } else {
                ovl_end = s->vma + s->size;
            }
        }
    }

    htab->num_overlays = ovl_index;
    htab->num_buf = num_buf;
    htab->ovl_sec = alloc_sec;

    if (ovl_index == 0) return 1;

    static const char *const entry_names[2][2] = {{"__ovly_load", "__icache_br_handler"}, {"__ovly_return", "__icache_call_handler"}};
    for (unsigned int i = 0; i < 2; i++) {
        const char *name = entry_names[i][htab->params->ovly_flavour];
        struct elf_link_hash_entry *h = elf_link_hash_lookup(&htab->elf, name, true, false, false);
        if (!h) return 0;

        if (h->root.type == bfd_link_hash_new) {
            h->root.type = bfd_link_hash_undefined;
            h->ref_regular = 1;
            h->ref_regular_nonweak = 1;
            h->non_elf = 0;
        }
        htab->ovly_entry[i] = h;
    }
    
    return 2;
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

#include <stdbool.h>

static bool is_branch(const unsigned char *insn) {
    if (insn == NULL) {
        return false;
    }
    return (insn[0] & 0xEC) == 0x20 && (insn[1] & 0x80) == 0;
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

#include <stdbool.h>

static bool is_indirect_branch(const unsigned char *insn) {
    return insn != NULL && (insn[0] & 0xEF) == 0x25 && (insn[1] & 0x80) == 0;
}

/* Return true for branch hint instructions.
   hbra  0001000..
   hbrr  0001001..  */

static bool is_hint(const unsigned char *insn) {
    if (insn == NULL) {
        return false;
    }
    return (insn[0] & 0xFC) == 0x10;
}

/* True if INPUT_SECTION might need overlay stubs.  */

static bool maybe_needs_stubs(asection *input_section) {
  if ((input_section->flags & SEC_ALLOC) == 0) {
    return false;
  }

  if (input_section->output_section == bfd_abs_section_ptr) {
    return false;
  }

  return strcmp(input_section->name, ".eh_frame") != 0;
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

static enum _stub_type determine_stub_type(
    struct elf_link_hash_entry *h,
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
    bool branch, hint, call;
    enum _stub_type ret = no_stub;
    bfd_byte insn[4];

    if (!sym_sec || sym_sec->output_section == bfd_abs_section_ptr ||
        !spu_elf_section_data(sym_sec->output_section))
        return ret;

    if (h && (h == htab->ovly_entry[0] || h == htab->ovly_entry[1]))
        return ret;

    if (h && startswith(h->root.root.string, "setjmp") &&
        (h->root.root.string[6] == '\0' || h->root.root.string[6] == '@'))
        ret = call_ovl_stub;

    sym_type = h ? h->type : ELF_ST_TYPE(sym->st_info);
    r_type = ELF32_R_TYPE(irela->r_info);

    if (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16) {
        if (!contents) {
            contents = insn;
            if (!bfd_get_section_contents(input_section->owner, input_section, contents, irela->r_offset, sizeof(insn)))
                return stub_error;
        } else {
            contents += irela->r_offset;
        }

        branch = is_branch(contents);
        hint = is_hint(contents);
        
        if (branch || hint) {
            call = (contents[0] & 0xfd) == 0x31;

            if (call && sym_type != STT_FUNC && contents != insn) {
                const char *sym_name = h ? h->root.root.string : bfd_elf_sym_name(input_section->owner,
                    &elf_tdata(input_section->owner)->symtab_hdr, sym, sym_sec);
                _bfd_error_handler(_("warning: call to non-function symbol %s defined in %pB"), sym_name, sym_sec->owner);
            }
        }
    } else {
        branch = hint = call = false;
    }

    if ((!branch && htab->params->ovly_flavour == ovly_soft_icache) ||
        (sym_type != STT_FUNC && !(branch || hint) && !(sym_sec->flags & SEC_CODE)))
        return no_stub;

    if (spu_elf_section_data(sym_sec->output_section)->u.o.ovl_index == 0 &&
        !htab->params->non_overlay_stubs)
        return ret;

    if (spu_elf_section_data(sym_sec->output_section)->u.o.ovl_index !=
        spu_elf_section_data(input_section->output_section)->u.o.ovl_index) {
        unsigned int lrlive = branch ? ((contents[1] & 0x70) >> 4) : 0;

        if (!lrlive && (call || sym_type == STT_FUNC))
            ret = call_ovl_stub;
        else
            ret = br000_ovl_stub + lrlive;
    }

    if (!(branch || hint) && sym_type == STT_FUNC && htab->params->ovly_flavour != ovly_soft_icache)
        ret = nonovl_stub;

    return ret;
}

#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>

static bool count_stub(struct spu_link_hash_table *htab, bfd *ibfd, asection *isec, enum _stub_type stub_type, struct elf_link_hash_entry *h, const Elf_Internal_Rela *irela) {
    unsigned int ovl = 0;
    struct got_entry *g, **head;
    bfd_vma addend = (irela != NULL) ? irela->r_addend : 0;

    if (stub_type != nonovl_stub) {
        ovl = spu_elf_section_data(isec->output_section)->u.o.ovl_index;
    }

    if (h != NULL) {
        head = &h->got.glist;
    } else {
        if (elf_local_got_ents(ibfd) == NULL) {
            bfd_size_type amt = (elf_tdata(ibfd)->symtab_hdr.sh_info * sizeof(*elf_local_got_ents(ibfd)));
            elf_local_got_ents(ibfd) = bfd_zmalloc(amt);
            if (elf_local_got_ents(ibfd) == NULL) {
                return false;
            }
        }
        head = elf_local_got_ents(ibfd) + ELF32_R_SYM(irela->r_info);
    }

    if (htab->params->ovly_flavour == ovly_soft_icache) {
        htab->stub_count[ovl]++;
        return true;
    }

    if (ovl == 0) {
        struct got_entry *gnext;
        for (g = *head; g != NULL; g = g->next) {
            if (g->addend == addend && g->ovl == 0)
                break;
        }
        if (g == NULL) {
            for (g = *head; g != NULL; g = gnext) {
                gnext = g->next;
                if (g->addend == addend) {
                    htab->stub_count[g->ovl]--;
                    free(g);
                }
            }
        }
    } else {
        for (g = *head; g != NULL; g = g->next) {
            if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
                break;
        }
    }

    if (g == NULL) {
        g = bfd_malloc(sizeof(*g));
        if (g == NULL) {
            return false;
        }
        g->ovl = ovl;
        g->addend = addend;
        g->stub_addr = (bfd_vma)-1;
        g->next = *head;
        *head = g;
        htab->stub_count[ovl]++;
    }

    return true;
}

/* Support two sizes of overlay stubs, a slower more compact stub of two
   instructions, and a faster stub of four instructions.
   Soft-icache stubs are four or eight words.  */

#include <limits.h>

static unsigned int ovl_stub_size (struct spu_elf_params *params) {
    if (!params) return 0;

    if (params->ovly_flavour >= sizeof(unsigned int) * CHAR_BIT - 4) return 0;
    if (params->compact_stub >= sizeof(unsigned int) * CHAR_BIT) return 0;

    unsigned int res = 16U << params->ovly_flavour;
    return res >> params->compact_stub;
}

static unsigned int ovl_stub_size_log2(struct spu_elf_params *params) {
    if (params == NULL) {
        // Handle null pointer error
        return 0;
    }
    unsigned int result = 4;
    if (params->ovly_flavour > params->compact_stub) {
        result += params->ovly_flavour - params->compact_stub;
    }
    return result;
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

static bool build_stub(struct bfd_link_info *info, bfd *ibfd, asection *isec, enum _stub_type stub_type, struct elf_link_hash_entry *h, const Elf_Internal_Rela *irela, bfd_vma dest, asection *dest_sec) {
    struct spu_link_hash_table *htab = spu_hash_table(info);
    unsigned int ovl = (stub_type != nonovl_stub) ? spu_elf_section_data(isec->output_section)->u.o.ovl_index : 0;
    struct got_entry **head = (h != NULL) ? &h->got.glist : elf_local_got_ents(ibfd) + ELF32_R_SYM(irela->r_info);
    bfd_vma addend = (irela != NULL) ? irela->r_addend : 0;
    struct got_entry *g;

    if (htab->params->ovly_flavour == ovly_soft_icache) {
        g = bfd_malloc(sizeof(*g));
        if (g == NULL) return false;
        g->ovl = ovl;
        g->br_addr = (irela != NULL) ? (irela->r_offset + isec->output_offset + isec->output_section->vma) : 0;
        g->next = *head;
        *head = g;
    } else {
        for (g = *head; g != NULL; g = g->next)
            if (g->addend == addend && (g->ovl == ovl || g->ovl == 0)) break;
        if (g == NULL) abort();
        if (g->ovl == 0 && ovl != 0) return true;
        if (g->stub_addr != (bfd_vma)-1) return true;
    }

    asection *sec = htab->stub_sec[ovl];
    dest += dest_sec->output_offset + dest_sec->output_section->vma;
    bfd_vma from = sec->size + sec->output_offset + sec->output_section->vma;
    g->stub_addr = from;
    bfd_vma to = htab->ovly_entry[0]->root.u.def.value + htab->ovly_entry[0]->root.u.def.section->output_offset + htab->ovly_entry[0]->root.u.def.section->output_section->vma;

    if (((dest | to | from) & 3) != 0) {
        htab->stub_err = 1;
        return false;
    }

    unsigned int dest_ovl = spu_elf_section_data(dest_sec->output_section)->u.o.ovl_index;

    if (htab->params->ovly_flavour == ovly_normal) {
        if (!htab->params->compact_stub) {
            bfd_put_32(sec->owner, ILA + ((dest_ovl << 7) & 0x01ffff80) + 78, sec->contents + sec->size);
            bfd_put_32(sec->owner, LNOP, sec->contents + sec->size + 4);
            bfd_put_32(sec->owner, ILA + ((dest << 7) & 0x01ffff80) + 79, sec->contents + sec->size + 8);
            if (!BRA_STUBS)
                bfd_put_32(sec->owner, BR + (((to - (from + 12)) << 5) & 0x007fff80), sec->contents + sec->size + 12);
            else
                bfd_put_32(sec->owner, BRA + ((to << 5) & 0x007fff80), sec->contents + sec->size + 12);
        } else {
            if (!BRA_STUBS)
                bfd_put_32(sec->owner, BRSL + ((to - from) << 5 & 0x007fff80) + 75, sec->contents + sec->size);
            else
                bfd_put_32(sec->owner, BRASL + ((to << 5) & 0x007fff80) + 75, sec->contents + sec->size);
            bfd_put_32(sec->owner, (dest & 0x3ffff) | (dest_ovl << 18), sec->contents + sec->size + 4);
        }
    } else if (htab->params->ovly_flavour == ovly_soft_icache && htab->params->compact_stub) {
        unsigned int lrlive = 0;
        if (stub_type != nonovl_stub) {
            if (stub_type == call_ovl_stub) lrlive = 5;
            else if (!htab->params->lrlive_analysis) lrlive = 1;
            else if (irela != NULL) {
                struct function_info *caller = find_function(isec, irela->r_offset, info);
                bfd_vma off = (caller->start == NULL) ? irela->r_offset : (bfd_vma)-1;
                struct function_info *found = NULL;
                if (caller->start != NULL) {
                    if (caller->lr_store != (bfd_vma)-1 || caller->sp_adjust != (bfd_vma)-1)
                        found = caller;
                    while (caller->start != NULL) {
                        caller = caller->start;
                        if (caller->lr_store != (bfd_vma)-1 || caller->sp_adjust != (bfd_vma)-1)
                            found = caller;
                    }
                    if (found != NULL) caller = found;
                }
                if (off > caller->sp_adjust) {
                    if (off > caller->lr_store) lrlive = 1;
                    else lrlive = 4;
                } else if (off > caller->lr_store)
                    lrlive = 3;
                else lrlive = 5;
                if (stub_type != br000_ovl_stub && lrlive != stub_type - br000_ovl_stub)
                    info->callbacks->einfo(_("%pA:0x%v lrlive .brinfo (%u) differs from analysis (%u)\n"), isec, irela->r_offset, lrlive, stub_type - br000_ovl_stub);
            }
            if (stub_type > br000_ovl_stub) lrlive = stub_type - br000_ovl_stub;
        }
        if (ovl == 0) {
            to = htab->ovly_entry[1]->root.u.def.value + htab->ovly_entry[1]->root.u.def.section->output_offset + htab->ovly_entry[1]->root.u.def.section->output_section->vma;
        }
        g->stub_addr += 4;
        bfd_vma br_dest = (irela == NULL && stub_type == nonovl_stub) ? to : g->stub_addr;
        if (irela == NULL && stub_type == nonovl_stub) g->br_addr = g->stub_addr;
        unsigned int set_id = ((dest_ovl - 1) >> htab->num_lines_log2) + 1;
        bfd_put_32(sec->owner, (set_id << 18) | (dest & 0x3ffff), sec->contents + sec->size);
        bfd_put_32(sec->owner, BRASL + ((to << 5) & 0x007fff80) + 75, sec->contents + sec->size + 4);
        bfd_put_32(sec->owner, (lrlive << 29) | (g->br_addr & 0x3ffff), sec->contents + sec->size + 8);
        bfd_vma patt = (irela != NULL && ELF32_R_TYPE(irela->r_info) == R_SPU_REL16) ? (dest - g->br_addr) ^ (br_dest - g->br_addr) : dest ^ br_dest;
        bfd_put_32(sec->owner, (patt << 5) & 0x007fff80, sec->contents + sec->size + 12);
        if (ovl == 0) sec->size += 16;
    } else {
        abort();
    }

    sec->size += ovl_stub_size(htab->params);

    if (htab->params->emit_stub_syms) {
        char *name = malloc(9 + sizeof(".ovl_call.") - 1 + (h != NULL ? strlen(h->root.root.string) : 9 + 1 + 9) + (irela != NULL ? (int)irela->r_addend & 0xffffffff ? 1 + 9 : 0 : 0) + 1);
        if (name == NULL) return false;
        sprintf(name, "%08x.ovl_call.", g->ovl);
        if (h != NULL) strcpy(name + 8 + sizeof(".ovl_call.") - 1, h->root.root.string);
        else sprintf(name + 8 + sizeof(".ovl_call.") - 1, "%x:%x", dest_sec->id & 0xffffffff, (int)ELF32_R_SYM(irela->r_info) & 0xffffffff);
        if (irela != NULL && (int)irela->r_addend & 0xffffffff) sprintf(name + strlen(name), "+%x", (int)irela->r_addend & 0xffffffff);
        h = elf_link_hash_lookup(&htab->elf, name, true, true, false);
        free(name);
        if (h == NULL) return false;
        if (h->root.type == bfd_link_hash_new) {
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
    }

    return true;
}

/* Called via elf_link_hash_traverse to allocate stubs for any _SPUEAR_
   symbols.  */

bool allocate_spuear_stubs(struct elf_link_hash_entry *h, void *inf) {
    struct bfd_link_info *info = inf;
    struct spu_link_hash_table *htab = spu_hash_table(info);
    asection *sym_sec;

    if ((h->root.type != bfd_link_hash_defined &&
         h->root.type != bfd_link_hash_defweak) ||
        !h->def_regular ||
        !startswith(h->root.root.string, "_SPUEAR_")) {
        return true;
    }

    sym_sec = h->root.u.def.section;
    if (sym_sec == NULL || sym_sec->output_section == bfd_abs_section_ptr) {
        return true;
    }

    struct spu_elf_section_data *sec_data = spu_elf_section_data(sym_sec->output_section);
    if (sec_data == NULL || 
        (sec_data->u.o.ovl_index == 0 && !htab->params->non_overlay_stubs)) {
        return true;
    }

    return count_stub(htab, NULL, NULL, nonovl_stub, h, NULL);
}

#include <stdbool.h>

static bool build_spuear_stubs(struct elf_link_hash_entry *h, void *inf) {
    struct bfd_link_info *info = inf;
    struct spu_link_hash_table *htab = spu_hash_table(info);

    if ((h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) &&
        h->def_regular &&
        startswith(h->root.root.string, "_SPUEAR_")) {
        
        asection *sym_sec = h->root.u.def.section;
        
        if (sym_sec && sym_sec->output_section != bfd_abs_section_ptr) {
            struct spu_elf_section_data *sec_data = spu_elf_section_data(sym_sec->output_section);

            if (sec_data && (sec_data->u.o.ovl_index != 0 || htab->params->non_overlay_stubs)) {
                return build_stub(info, NULL, NULL, nonovl_stub, h, NULL, h->root.u.def.value, sym_sec);
            }
        }
    }

    return true;
}

/* Size or build stubs.  */

static bool process_stubs(struct bfd_link_info *info, bool build) {
    struct spu_link_hash_table *htab = spu_hash_table(info);
    bfd *ibfd;

    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
        extern const bfd_target spu_elf32_vec;
        Elf_Internal_Shdr *symtab_hdr;
        asection *isec;
        Elf_Internal_Sym *local_syms = NULL;

        if (ibfd->xvec != &spu_elf32_vec) continue;

        symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
        if (symtab_hdr->sh_info == 0) continue;

        for (isec = ibfd->sections; isec != NULL; isec = isec->next) {
            if ((isec->flags & SEC_RELOC) == 0 || isec->reloc_count == 0 || !maybe_needs_stubs(isec)) continue;

            Elf_Internal_Rela *internal_relocs = _bfd_elf_link_read_relocs(ibfd, isec, NULL, NULL, info->keep_memory);
            if (internal_relocs == NULL) return false;

            for (Elf_Internal_Rela *irela = internal_relocs, *irelaend = irela + isec->reloc_count; irela < irelaend; irela++) {
                enum elf_spu_reloc_type r_type = ELF32_R_TYPE(irela->r_info);
                unsigned int r_indx = ELF32_R_SYM(irela->r_info);

                if (r_type >= R_SPU_max) {
                    bfd_set_error(bfd_error_bad_value);
                    free_resources(internal_relocs, local_syms, symtab_hdr->contents);
                    return false;
                }

                struct elf_link_hash_entry *h;
                Elf_Internal_Sym *sym;
                asection *sym_sec;
                if (!get_sym_h(&h, &sym, &sym_sec, &local_syms, r_indx, ibfd)) {
                    free_resources(internal_relocs, local_syms, symtab_hdr->contents);
                    return false;
                }

                enum _stub_type stub_type = needs_ovl_stub(h, sym, sym_sec, isec, irela, NULL, info);
                if (stub_type == stub_error || (stub_type != no_stub && !process_stub(htab, ibfd, isec, stub_type, h, irela, build, info))) {
                    free_resources(internal_relocs, local_syms, symtab_hdr->contents);
                    return false;
                }
            }
            free_relocs_if_needed(internal_relocs, isec);
        }
        finalize_local_symbols(local_syms, symtab_hdr, info->keep_memory);
    }
    return true;
}

static bool process_stub(struct spu_link_hash_table *htab, bfd *ibfd, asection *isec, enum _stub_type stub_type, struct elf_link_hash_entry *h, Elf_Internal_Rela *irela, bool build, struct bfd_link_info *info) {
    if (htab->stub_count == NULL) {
        bfd_size_type amt = (htab->num_overlays + 1) * sizeof(*htab->stub_count);
        htab->stub_count = bfd_zmalloc(amt);
        if (htab->stub_count == NULL) return false;
    }

    if (!build) {
        return count_stub(htab, ibfd, isec, stub_type, h, irela);
    } else {
        bfd_vma dest = (h != NULL ? h->root.u.def.value : 0) + irela->r_addend;
        return build_stub(info, ibfd, isec, stub_type, h, irela, dest, sym_sec);
    }
}

static void free_resources(Elf_Internal_Rela *internal_relocs, Elf_Internal_Sym *local_syms, const unsigned char *symtab_contents) {
    if (internal_relocs != NULL) free(internal_relocs);
    if (symtab_contents != (unsigned char *)local_syms) free(local_syms);
}

static void free_relocs_if_needed(Elf_Internal_Rela *internal_relocs, asection *isec) {
    if (elf_section_data(isec)->relocs != internal_relocs) free(internal_relocs);
}

static void finalize_local_symbols(Elf_Internal_Sym *local_syms, Elf_Internal_Shdr *symtab_hdr, bool keep_memory) {
    if (local_syms != NULL && symtab_hdr->contents != (unsigned char *)local_syms) {
        if (!keep_memory)
            free(local_syms);
        else
            symtab_hdr->contents = (unsigned char *)local_syms;
    }
}

/* Allocate space for overlay call and return stubs.
   Return 0 on error, 1 if no overlays, 2 otherwise.  */

int spu_elf_size_stubs(struct bfd_link_info *info) {
    struct spu_link_hash_table *htab;
    bfd *ibfd;
    bfd_size_type amt;
    flagword flags;
    unsigned int i;
    asection *stub;

    if (!process_stubs(info, false)) return 0;

    htab = spu_hash_table(info);
    elf_link_hash_traverse(&htab->elf, allocate_spuear_stubs, info);
    if (htab->stub_err) return 0;

    ibfd = info->input_bfds;
    if (htab->stub_count) {
        amt = (htab->num_overlays + 1) * sizeof(*htab->stub_sec);
        htab->stub_sec = bfd_zmalloc(amt);
        if (!htab->stub_sec) return 0;

        flags = SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
        stub = bfd_make_section_anyway_with_flags(ibfd, ".stub", flags);
        if (!stub || !bfd_set_section_alignment(stub, ovl_stub_size_log2(htab->params))) return 0;

        htab->stub_sec[0] = stub;
        stub->size = htab->stub_count[0] * ovl_stub_size(htab->params);
        if (htab->params->ovly_flavour == ovly_soft_icache) {
            stub->size += htab->stub_count[0] * 16;
        }

        for (i = 0; i < htab->num_overlays; ++i) {
            asection *osec = htab->ovl_sec[i];
            unsigned int ovl = spu_elf_section_data(osec)->u.o.ovl_index;
            stub = bfd_make_section_anyway_with_flags(ibfd, ".stub", flags);
            if (!stub || !bfd_set_section_alignment(stub, ovl_stub_size_log2(htab->params))) return 0;

            htab->stub_sec[ovl] = stub;
            stub->size = htab->stub_count[ovl] * ovl_stub_size(htab->params);
        }
    }

    if (htab->params->ovly_flavour == ovly_soft_icache) {
        flags = SEC_ALLOC;
        htab->ovtab = bfd_make_section_anyway_with_flags(ibfd, ".ovtab", flags);
        if (!htab->ovtab || !bfd_set_section_alignment(htab->ovtab, 4)) return 0;

        htab->ovtab->size = (16 + 16 + (16 << htab->fromelem_size_log2)) << htab->num_lines_log2;

        flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
        htab->init = bfd_make_section_anyway_with_flags(ibfd, ".ovini", flags);
        if (!htab->init || !bfd_set_section_alignment(htab->init, 4)) return 0;

        htab->init->size = 16;
    } else if (!htab->stub_count) {
        return 1;
    } else {
        flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
        htab->ovtab = bfd_make_section_anyway_with_flags(ibfd, ".ovtab", flags);
        if (!htab->ovtab || !bfd_set_section_alignment(htab->ovtab, 4)) return 0;

        htab->ovtab->size = htab->num_overlays * 16 + 16 + htab->num_buf * 4;
    }

    htab->toe = bfd_make_section_anyway_with_flags(ibfd, ".toe", SEC_ALLOC);
    if (!htab->toe || !bfd_set_section_alignment(htab->toe, 4)) return 0;

    htab->toe->size = 16;
    return 2;
}

/* Called from ld to place overlay manager data sections.  This is done
   after the overlay manager itself is loaded, mainly so that the
   linker's htab->init section is placed after any other .ovl.init
   sections.  */

void spu_elf_place_overlay_data(struct bfd_link_info *info) {
    struct spu_link_hash_table *htab = spu_hash_table(info);
    
    if (!htab->params) return;

    if (htab->stub_sec != NULL) {
        htab->params->place_spu_section(htab->stub_sec[0], NULL, ".text");

        for (unsigned int i = 0; i < htab->num_overlays; ++i) {
            asection *osec = htab->ovl_sec[i];
            unsigned int ovl = spu_elf_section_data(osec)->u.o.ovl_index;
            htab->params->place_spu_section(htab->stub_sec[ovl], osec, NULL);
        }
    }

    if (htab->params->ovly_flavour == ovly_soft_icache) {
        htab->params->place_spu_section(htab->init, NULL, ".ovl.init");
    }

    if (htab->ovtab != NULL) {
        const char *ovout = (htab->params->ovly_flavour == ovly_soft_icache) ? ".bss" : ".data";
        htab->params->place_spu_section(htab->ovtab, NULL, ovout);
    }

    if (htab->toe != NULL) {
        htab->params->place_spu_section(htab->toe, NULL, ".toe");
    }
}

/* Functions to handle embedded spu_ovl.o object.  */

static void *ovl_mgr_open(struct bfd *nbfd, void *stream) {
  (void)nbfd; // Explicitly mark nbfd as unused
  return stream;
}

static file_ptr ovl_mgr_pread(struct bfd *abfd ATTRIBUTE_UNUSED, void *stream, void *buf, file_ptr nbytes, file_ptr offset) {
    struct _ovl_stream *os = (struct _ovl_stream *)stream;
    size_t max = (const char *)os->end - (const char *)os->start;

    if (offset >= max) {
        return 0;
    }

    size_t count = (offset + nbytes > max) ? max - offset : nbytes;
    memcpy(buf, (const char *)os->start + offset, count);
    return count;
}

#include <string.h>
#include <sys/stat.h>

static int ovl_mgr_stat(struct bfd *abfd, void *stream, struct stat *sb) {
    if (stream == NULL || sb == NULL) {
        return -1;
    }

    struct _ovl_stream *os = (struct _ovl_stream *)stream;

    memset(sb, 0, sizeof(*sb));
    sb->st_size = (const char *)os->end - (const char *)os->start;
    return 0;
}

#include <stdbool.h>
#include <stddef.h>

bool spu_elf_open_builtin_lib(bfd **ovl_bfd, const struct _ovl_stream *stream) {
    if (ovl_bfd == NULL || stream == NULL) {
        return false;
    }
    
    *ovl_bfd = bfd_openr_iovec("builtin ovl_mgr", "elf32-spu", ovl_mgr_open, (void *)stream, ovl_mgr_pread, NULL, ovl_mgr_stat);
    return *ovl_bfd != NULL;
}

static unsigned int overlay_index(asection *sec) {
    if (sec == NULL || sec->output_section == bfd_abs_section_ptr) {
        return 0;
    }
    
    spu_elf_section_data *section_data = spu_elf_section_data(sec->output_section);
    if (section_data == NULL) {
        return 0;
    }
    
    return section_data->u.o.ovl_index;
}

/* Define an STT_OBJECT symbol.  */

static struct elf_link_hash_entry *define_ovtab_symbol(struct spu_link_hash_table *htab, const char *name) {
    struct elf_link_hash_entry *h = elf_link_hash_lookup(&htab->elf, name, true, false, false);

    if (!h) {
        return NULL;
    }

    if (h->root.type == bfd_link_hash_defined && h->def_regular) {
        if (h->root.u.def.section->owner) {
            _bfd_error_handler(_("%pB is not allowed to define %s"), h->root.u.def.section->owner, h->root.root.string);
        } else {
            _bfd_error_handler(_("you are not allowed to define %s in a script"), h->root.root.string);
        }
        bfd_set_error(bfd_error_bad_value);
        return NULL;
    }

    h->root.type = bfd_link_hash_defined;
    h->root.u.def.section = htab->ovtab;
    h->type = STT_OBJECT;
    h->ref_regular = 1;
    h->def_regular = 1;
    h->ref_regular_nonweak = 1;
    h->non_elf = 0;

    return h;
}

/* Fill in all stubs and the overlay tables.  */

static bool spu_elf_build_stubs(struct bfd_link_info *info) {
    struct spu_link_hash_table *htab = spu_hash_table(info);
    bfd_byte *p;

    if (htab->num_overlays != 0) {
        for (unsigned int i = 0; i < 2; i++) {
            struct elf_link_hash_entry *h = htab->ovly_entry[i];
            if (h && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) && h->def_regular) {
                asection *s = h->root.u.def.section->output_section;
                if (spu_elf_section_data(s)->u.o.ovl_index) {
                    _bfd_error_handler(_("%s in overlay section"), h->root.root.string);
                    bfd_set_error(bfd_error_bad_value);
                    return false;
                }
            }
        }
    }

    if (htab->stub_sec != NULL) {
        for (unsigned int i = 0; i <= htab->num_overlays; i++) {
            if (htab->stub_sec[i]->size != 0) {
                htab->stub_sec[i]->contents = bfd_zalloc(htab->stub_sec[i]->owner, htab->stub_sec[i]->size);
                if (htab->stub_sec[i]->contents == NULL)
                    return false;
                
                htab->stub_sec[i]->alloced = 1;
                htab->stub_sec[i]->rawsize = htab->stub_sec[i]->size;
                htab->stub_sec[i]->size = 0;
            }
        }

        process_stubs(info, true);
        if (!htab->stub_err)
            elf_link_hash_traverse(&htab->elf, build_spuear_stubs, info);

        if (htab->stub_err) {
            _bfd_error_handler(_("overlay stub relocation overflow"));
            bfd_set_error(bfd_error_bad_value);
            return false;
        }

        for (unsigned int i = 0; i <= htab->num_overlays; i++) {
            if (htab->stub_sec[i]->size != htab->stub_sec[i]->rawsize) {
                _bfd_error_handler(_("stubs don't match calculated size"));
                bfd_set_error(bfd_error_bad_value);
                return false;
            }
            htab->stub_sec[i]->rawsize = 0;
        }
    }

    if (htab->ovtab == NULL || htab->ovtab->size == 0)
        return true;

    htab->ovtab->contents = bfd_zalloc(htab->ovtab->owner, htab->ovtab->size);
    if (htab->ovtab->contents == NULL)
        return false;
    
    htab->ovtab->alloced = 1;
    p = htab->ovtab->contents;

    if (htab->params->ovly_flavour == ovly_soft_icache) {
        bfd_vma off = 0;

        if (!define_and_set_ovtab_symbols(htab, &off))
            return false;

        if (htab->init != NULL && htab->init->size != 0) {
            htab->init->contents = bfd_zalloc(htab->init->owner, htab->init->size);
            if (htab->init->contents == NULL)
                return false;
            
            htab->init->alloced = 1;

            struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "__icache_fileoff");
            if (h == NULL)
                return false;

            h->root.u.def.value = 0;
            h->root.u.def.section = htab->init;
            h->size = 8;
        }
    } else {
        if (!write_ovly_table(htab, p))
            return false;
    }

    struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "_EAR_");
    if (h == NULL)
        return false;
    
    h->root.u.def.section = htab->toe;
    h->root.u.def.value = 0;
    h->size = 16;

    return true;
}

static bool define_and_set_ovtab_symbols(struct spu_link_hash_table *htab, bfd_vma *off) {
    unsigned long size_factor = 16 << htab->num_lines_log2;

    struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "__icache_tag_array");
    if (h == NULL)
        return false;

    h->root.u.def.value = 0;
    h->size = size_factor;
    *off = size_factor;

    h = define_ovtab_symbol(htab, "__icache_tag_array_size");
    if (h == NULL)
        return false;

    h->root.u.def.value = size_factor;
    h->root.u.def.section = bfd_abs_section_ptr;

    if (!setup_icache_symbols(htab, off))
        return false;

    return true;
}

static bool setup_icache_symbols(struct spu_link_hash_table *htab, bfd_vma *off) {
    unsigned long rewrite_size = 16 << (htab->fromelem_size_log2 + htab->num_lines_log2);

    struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "__icache_rewrite_to");
    if (h == NULL)
        return false;

    h->root.u.def.value = *off;
    h->size = 16 << htab->num_lines_log2;
    *off += h->size;

    if (!define_rewrite_symbols(htab))
        return false;

    h = define_ovtab_symbol(htab, "__icache_rewrite_from");
    if (h == NULL)
        return false;

    h->root.u.def.value = *off;
    h->size = rewrite_size;
    *off += rewrite_size;

    if (!define_from_symbols(htab))
        return false;

    return true;
}

static bool define_rewrite_symbols(struct spu_link_hash_table *htab) {
    unsigned long rewrite_size = 16 << htab->num_lines_log2;

    struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "__icache_rewrite_to_size");
    if (h == NULL)
        return false;

    h->root.u.def.value = rewrite_size;
    h->root.u.def.section = bfd_abs_section_ptr;

    return true;
}

static bool define_from_symbols(struct spu_link_hash_table *htab) {
    unsigned long from_size = 16 << (htab->fromelem_size_log2 + htab->num_lines_log2);

    struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "__icache_rewrite_from_size");
    if (h == NULL)
        return false;

    h->root.u.def.value = from_size;
    h->root.u.def.section = bfd_abs_section_ptr;

    if (define_auxiliary_symbols(htab))
        return true;

    return false;
}

static bool define_auxiliary_symbols(struct spu_link_hash_table *htab) {
    struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "__icache_log2_fromelemsize");
    if (h == NULL)
        return false;
    
    h->root.u.def.value = htab->fromelem_size_log2;
    h->root.u.def.section = bfd_abs_section_ptr;

    if (!define_cache_base_symbols(htab))
        return false;

    h = define_ovtab_symbol(htab, "__icache_log2_cachesize");
    if (h == NULL)
        return false;

    h->root.u.def.value = htab->num_lines_log2 + htab->line_size_log2;
    h->root.u.def.section = bfd_abs_section_ptr;

    h = define_ovtab_symbol(htab, "__icache_neg_log2_cachesize");
    if (h == NULL)
        return false;

    h->root.u.def.value = -(htab->num_lines_log2 + htab->line_size_log2);
    h->root.u.def.section = bfd_abs_section_ptr;

    return true;
}

static bool define_cache_base_symbols(struct spu_link_hash_table *htab) {
    struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "__icache_base");
    if (h == NULL)
        return false;
    
    h->root.u.def.value = htab->ovl_sec[0]->vma;
    h->root.u.def.section = bfd_abs_section_ptr;
    h->size = htab->num_buf << htab->line_size_log2;

    if (!define_cache_line_symbols(htab))
        return false;

    return true;
}

static bool define_cache_line_symbols(struct spu_link_hash_table *htab) {
    struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "__icache_linesize");
    if (h == NULL)
        return false;

    h->root.u.def.value = 1 << htab->line_size_log2;
    h->root.u.def.section = bfd_abs_section_ptr;

    h = define_ovtab_symbol(htab, "__icache_log2_linesize");
    if (h == NULL)
        return false;

    h->root.u.def.value = htab->line_size_log2;
    h->root.u.def.section = bfd_abs_section_ptr;

    h = define_ovtab_symbol(htab, "__icache_neg_log2_linesize");
    if (h == NULL)
        return false;

    h->root.u.def.value = -htab->line_size_log2;
    h->root.u.def.section = bfd_abs_section_ptr;

    h = define_ovtab_symbol(htab, "__icache_cachesize");
    if (h == NULL)
        return false;

    h->root.u.def.value = 1 << (htab->num_lines_log2 + htab->line_size_log2);
    h->root.u.def.section = bfd_abs_section_ptr;

    return true;
}

static bool write_ovly_table(struct spu_link_hash_table *htab, bfd_byte *p) {
    asection *s;
    bfd *obfd = htab->ovtab->output_section->owner;
    
    for (s = obfd->sections; s != NULL; s = s->next) {
        unsigned int ovl_index = spu_elf_section_data(s)->u.o.ovl_index;
        if (ovl_index != 0) {
            unsigned long off = ovl_index * 16;
            unsigned int ovl_buf = spu_elf_section_data(s)->u.o.ovl_buf;

            bfd_put_32(htab->ovtab->owner, s->vma, p + off);
            bfd_put_32(htab->ovtab->owner, (s->size + 15) & -16, p + off + 4);
            bfd_put_32(htab->ovtab->owner, ovl_buf, p + off + 12);
        }
    }

    if (!define_ovly_symbols(htab))
        return false;

    return true;
}

static bool define_ovly_symbols(struct spu_link_hash_table *htab) {
    struct elf_link_hash_entry *h = define_ovtab_symbol(htab, "_ovly_table");
    if (h == NULL)
        return false;

    h->root.u.def.value = 16;
    h->size = htab->num_overlays * 16;

    h = define_ovtab_symbol(htab, "_ovly_table_end");
    if (h == NULL)
        return false;

    h->root.u.def.value = htab->num_overlays * 16 + 16;
    h->size = 0;

    h = define_ovtab_symbol(htab, "_ovly_buf_table");
    if (h == NULL)
        return false;

    h->root.u.def.value = htab->num_overlays * 16 + 16;
    h->size = htab->num_buf * 4;

    h = define_ovtab_symbol(htab, "_ovly_buf_table_end");
    if (h == NULL)
        return false;

    h->root.u.def.value = htab->num_overlays * 16 + 16 + htab->num_buf * 4;
    h->size = 0;

    return true;
}

/* Check that all loadable section VMAs lie in the range
   LO .. HI inclusive, and stash some parameters for --auto-overlay.  */

asection *spu_elf_check_vma(struct bfd_link_info *info) {
    struct elf_segment_map *m;
    struct spu_link_hash_table *htab = spu_hash_table(info);
    bfd *abfd = info->output_bfd;
    bfd_vma hi = htab->params->local_store_hi;
    bfd_vma lo = htab->params->local_store_lo;

    htab->local_store = hi + 1 - lo;

    for (m = elf_seg_map(abfd); m != NULL; m = m->next) {
        if (m->p_type != PT_LOAD) {
            continue;
        }
        for (unsigned int i = 0; i < m->count; i++) {
            asection *section = m->sections[i];
            if (section->size == 0) {
                continue;
            }
            bfd_vma vma_end = section->vma + section->size - 1;
            if (section->vma < lo || section->vma > hi || vma_end > hi) {
                return section;
            }
        }
    }
    return NULL;
}

/* OFFSET in SEC (presumably) is the beginning of a function prologue.
   Search for stack adjusting insns, and return the sp delta.
   If a store of lr is found save the instruction offset to *LR_STORE.
   If a stack adjusting instruction is found, save that offset to
   *SP_ADJUST.  */

static int find_function_stack_adjust(asection *sec, bfd_vma offset, bfd_vma *lr_store, bfd_vma *sp_adjust) {
    int32_t reg[128] = {0};
    while (offset + 4 <= sec->size) {
        unsigned char buf[4];
        int rt, ra;
        uint32_t imm;

        if (!bfd_get_section_contents(sec->owner, sec, buf, offset, 4))
            break;

        rt = buf[3] & 0x7f;
        ra = ((buf[2] & 0x3f) << 1) | (buf[3] >> 7);
        imm = (buf[1] << 9) | (buf[2] << 1) | (buf[3] >> 7);

        switch (buf[0]) {
            case 0x24: // stqd
                if (rt == 0 && ra == 1)
                    *lr_store = offset;
                break;

            case 0x1c: // ai
                imm = ((imm >> 7) ^ 0x200) - 0x200;
                reg[rt] = reg[ra] + imm;
                if (rt == 1) {
                    if (reg[rt] > 0)
                        return 0;
                    *sp_adjust = offset;
                    return reg[rt];
                }
                break;

            case 0x18: // a
                if ((buf[1] & 0xe0) == 0) {
                    int rb = ((buf[1] & 0x1f) << 2) | ((buf[2] & 0xc0) >> 6);
                    reg[rt] = reg[ra] + reg[rb];
                    if (rt == 1) {
                        if (reg[rt] > 0)
                            return 0;
                        *sp_adjust = offset;
                        return reg[rt];
                    }
                }
                break;
                
            case 0x08: // sf
                if ((buf[1] & 0xe0) == 0) {
                    int rb = ((buf[1] & 0x1f) << 2) | ((buf[2] & 0xc0) >> 6);
                    reg[rt] = reg[rb] - reg[ra];
                    if (rt == 1) {
                        if (reg[rt] > 0)
                            return 0;
                        *sp_adjust = offset;
                        return reg[rt];
                    }
                }
                break;
                
            case 0x04: // ori
                reg[rt] = reg[ra] | (((imm >> 7) ^ 0x200) - 0x200);
                break;

            case 0x40: case 0x41: case 0x42: // il, ilh, ilhu, ila
                if (buf[0] >= 0x42)
                    imm |= (buf[0] & 1) << 17;
                else {
                    imm &= 0xffff;
                    if (buf[0] == 0x40) {
                        if (!(buf[1] & 0x80))
                            break;
                        imm = (imm ^ 0x8000) - 0x8000;
                    }
                    else if (!(buf[1] & 0x80))
                        imm <<= 16;
                }
                reg[rt] = imm;
                break;

            case 0x60: // iohl
                if (buf[1] & 0x80)
                    reg[rt] |= imm & 0xffff;
                break;

            case 0x32: // fsmbi
                if (buf[1] & 0x80)
                    reg[rt] = ((imm & 0x8000) ? 0xff000000 : 0) | ((imm & 0x4000) ? 0x00ff0000 : 0) |
                              ((imm & 0x2000) ? 0x0000ff00 : 0) | ((imm & 0x1000) ? 0x000000ff : 0);
                break;

            case 0x16: // andbi
                reg[rt] = reg[ra] & (imm = (imm >> 7) & 0xff | ((imm & 0xff) << 8) | ((imm & 0xff) << 16));
                break;

            case 0x33: // brsl .+4
                if (imm == 1)
                    reg[rt] = 0;
                break;

            default:
                if (is_branch(buf) || is_indirect_branch(buf))
                    return 0;
                continue;
        }
        offset += 4;
    }
    return 0;
}

/* qsort predicate to sort symbols by section and value.  */

static Elf_Internal_Sym *sort_syms_syms;
static asection **sort_syms_psecs;

int sort_syms(const void *a, const void *b) {
    Elf_Internal_Sym *const *s1 = a;
    Elf_Internal_Sym *const *s2 = b;
    asection *sec1 = sort_syms_psecs[*s1 - sort_syms_syms];
    asection *sec2 = sort_syms_psecs[*s2 - sort_syms_syms];

    if (sec1 != sec2) {
        return (sec1->index > sec2->index) - (sec1->index < sec2->index);
    }

    if ((*s1)->st_value != (*s2)->st_value) {
        return ((*s1)->st_value > (*s2)->st_value) - ((*s1)->st_value < (*s2)->st_value);
    }

    if ((*s2)->st_size != (*s1)->st_size) {
        return ((*s2)->st_size > (*s1)->st_size) - ((*s2)->st_size < (*s1)->st_size);
    }

    return (*s1 > *s2) - (*s1 < *s2);
}

/* Allocate a struct spu_elf_stack_info with MAX_FUN struct function_info
   entries for section SEC.  */

static struct spu_elf_stack_info *alloc_stack_info(asection *sec, int max_fun) {
    if (sec == NULL || max_fun <= 0) {
        return NULL;
    }

    struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
    if (sec_data == NULL) {
        return NULL;
    }

    bfd_size_type amt = sizeof(struct spu_elf_stack_info) + (max_fun - 1) * sizeof(struct function_info);
    sec_data->u.i.stack_info = bfd_zmalloc(amt);

    if (sec_data->u.i.stack_info) {
        sec_data->u.i.stack_info->max_fun = max_fun;
    }

    return sec_data->u.i.stack_info;
}

/* Add a new struct function_info describing a (part of a) function
   starting at SYM_H.  Keep the array sorted by address.  */

static struct function_info *maybe_insert_function(asection *sec, void *sym_h, bool global, bool is_func) {
    struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
    struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
    int i;
    bfd_vma off, size;

    if (!sinfo && (sinfo = alloc_stack_info(sec, 20)) == NULL) {
        return NULL;
    }

    if (global) {
        struct elf_link_hash_entry *h = sym_h;
        off = h->root.u.def.value;
        size = h->size;
    } else {
        Elf_Internal_Sym *sym = sym_h;
        off = sym->st_value;
        size = sym->st_size;
    }

    for (i = sinfo->num_fun - 1; i >= 0; i--) {
        if (sinfo->fun[i].lo <= off) {
            break;
        }
    }

    if (i >= 0) {
        if (sinfo->fun[i].lo == off) {
            if (global && !sinfo->fun[i].global) {
                sinfo->fun[i].global = true;
                sinfo->fun[i].u.h = sym_h;
            }
            if (is_func) {
                sinfo->fun[i].is_func = true;
            }
            return &sinfo->fun[i];
        } else if (sinfo->fun[i].hi > off && size == 0) {
            return &sinfo->fun[i];
        }
    }

    if (sinfo->num_fun >= sinfo->max_fun) {
        bfd_size_type old_size = sizeof(struct spu_elf_stack_info) + 
                                 (sinfo->max_fun - 1) * sizeof(struct function_info);
        sinfo->max_fun += 20 + (sinfo->max_fun >> 1);
        bfd_size_type new_size = sizeof(struct spu_elf_stack_info) +
                                 (sinfo->max_fun - 1) * sizeof(struct function_info);
        
        struct spu_elf_stack_info *new_sinfo = bfd_realloc(sinfo, new_size);
        if (!new_sinfo) return NULL;

        memset((char *)new_sinfo + old_size, 0, new_size - old_size);
        sec_data->u.i.stack_info = new_sinfo;
        sinfo = new_sinfo;
    }

    if (++i < sinfo->num_fun) {
        memmove(&sinfo->fun[i + 1], &sinfo->fun[i], (sinfo->num_fun - i) * sizeof(sinfo->fun[i]));
    }

    sinfo->fun[i] = (struct function_info){
        .is_func = is_func,
        .global = global,
        .sec = sec,
        .u.h = global ? sym_h : NULL,
        .u.sym = !global ? sym_h : NULL,
        .lo = off,
        .hi = off + size,
        .lr_store = -1,
        .sp_adjust = -1,
        .stack = -find_function_stack_adjust(sec, off, &sinfo->fun[i].lr_store, &sinfo->fun[i].sp_adjust)
    };

    sinfo->num_fun++;
    return &sinfo->fun[i];
}

/* Return the name of FUN.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *func_name(struct function_info *fun) {
    if (!fun) return "(null)";

    while (fun->start != NULL) {
        fun = fun->start;
    }

    if (fun->global) {
        return fun->u.h->root.root.string;
    }

    asection *sec = fun->sec;
    if (!sec || !fun->u.sym) return "(null)";

    if (fun->u.sym->st_name == 0) {
        size_t len = strlen(sec->name);
        char *name = bfd_malloc(len + 10);
        if (name == NULL) {
            return "(null)";
        }
        snprintf(name, len + 10, "%s+%lx", sec->name, 
                 (unsigned long)fun->u.sym->st_value & 0xffffffff);
        return name;
    }

    bfd *ibfd = sec->owner;
    if (!ibfd) return "(null)";

    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
    if (!symtab_hdr) return "(null)";

    return bfd_elf_sym_name(ibfd, symtab_hdr, fun->u.sym, sec);
}

/* Read the instruction at OFF in SEC.  Return true iff the instruction
   is a nop, lnop, or stop 0 (all zero insn).  */

bool is_nop(asection *sec, bfd_vma off) {
  unsigned char insn[4];
  
  if (off + 4 > sec->size) {
    return false;
  }

  if (!bfd_get_section_contents(sec->owner, sec, insn, off, 4)) {
    return false;
  }
  
  if ((insn[0] & 0xBF) == 0 && (insn[1] & 0xE0) == 0x20) {
    return true;
  }
  
  if (*(uint32_t *)insn == 0) {
    return true;
  }
  
  return false;
}

/* Extend the range of FUN to cover nop padding up to LIMIT.
   Return TRUE iff some instruction other than a NOP was found.  */

static bool insns_at_end(struct function_info *fun, bfd_vma limit) {
    bfd_vma off = (fun->hi + 3) & ~3;

    while (off < limit) {
        if (!is_nop(fun->sec, off)) {
            fun->hi = off;
            return true;
        }
        off += 4;
    }

    fun->hi = limit;
    return false;
}

/* Check and fix overlapping function ranges.  Return TRUE iff there
   are gaps in the current info we have about functions in SEC.  */

static bool check_function_ranges(asection *sec, struct bfd_link_info *info) {
    struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
    if (!sec_data || !sec_data->u.i.stack_info) return false;
    
    struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
    bool gaps = false;

    for (int i = 1; i < sinfo->num_fun; i++) {
        if (sinfo->fun[i - 1].hi > sinfo->fun[i].lo) {
            const char *f1 = func_name(&sinfo->fun[i - 1]);
            const char *f2 = func_name(&sinfo->fun[i]);
            info->callbacks->einfo(_("warning: %s overlaps %s\n"), f1, f2);
            sinfo->fun[i - 1].hi = sinfo->fun[i].lo;
        } else if (insns_at_end(&sinfo->fun[i - 1], sinfo->fun[i].lo)) {
            gaps = true;
        }
    }

    if (sinfo->num_fun == 0 || sinfo->fun[0].lo != 0) {
        gaps = true;
    }

    if (sinfo->num_fun > 0) {
        if (sinfo->fun[sinfo->num_fun - 1].hi > sec->size) {
            const char *f1 = func_name(&sinfo->fun[sinfo->num_fun - 1]);
            info->callbacks->einfo(_("warning: %s exceeds section size\n"), f1);
            sinfo->fun[sinfo->num_fun - 1].hi = sec->size;
        } else if (insns_at_end(&sinfo->fun[sinfo->num_fun - 1], sec->size)) {
            gaps = true;
        }
    }

    return gaps;
}

/* Search current function info for a function that contains address
   OFFSET in section SEC.  */

#include <stdbool.h>

static struct function_info *find_function(asection *sec, bfd_vma offset, struct bfd_link_info *info) {
    struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
    struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
    int lo = 0, hi = sinfo->num_fun;

    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        bfd_vma current_lo = sinfo->fun[mid].lo;
        bfd_vma current_hi = sinfo->fun[mid].hi;

        if (offset < current_lo) {
            hi = mid;
        } else if (offset >= current_hi) {
            lo = mid + 1;
        } else {
            return &sinfo->fun[mid];
        }
    }

    if (info && info->callbacks && info->callbacks->einfo) {
        info->callbacks->einfo(_("%pA:0x%v not found in function table\n"), sec, offset);
    }
    bfd_set_error(bfd_error_bad_value);
    return NULL;
}

/* Add CALLEE to CALLER call list if not already present.  Return TRUE
   if CALLEE was new.  If this function return FALSE, CALLEE should
   be freed.  */

static bool insert_callee(struct function_info *caller, struct call_info *callee) {
    struct call_info **pp = &caller->call_list;
    struct call_info *current;

    while ((current = *pp) != NULL) {
        if (current->fun == callee->fun) {
            current->is_tail &= callee->is_tail;
            if (!current->is_tail) {
                current->fun->start = NULL;
                current->fun->is_func = true;
            }
            current->count += callee->count;
            *pp = current->next;
            current->next = caller->call_list;
            caller->call_list = current;
            return false;
        }
        pp = &current->next;
    }

    callee->next = caller->call_list;
    caller->call_list = callee;
    return true;
}

/* Copy CALL and insert the copy into CALLER.  */

bool copy_callee(struct function_info *caller, const struct call_info *call) {
    struct call_info *callee = bfd_malloc(sizeof(*callee));
    if (callee == NULL) {
        return false;
    }
    *callee = *call;
    if (!insert_callee(caller, callee)) {
        free(callee);
        return false;
    }
    return true;
}

/* We're only interested in code sections.  Testing SEC_IN_MEMORY excludes
   overlay stub sections.  */

static bool interesting_section(asection *s) {
    if (s == NULL) return false;
    if (s->output_section == bfd_abs_section_ptr) return false;
    const unsigned int required_flags = SEC_ALLOC | SEC_LOAD | SEC_CODE;
    if ((s->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_IN_MEMORY)) != required_flags) return false;
    return s->size != 0;
}

/* Rummage through the relocs for SEC, looking for function calls.
   If CALL_TREE is true, fill in call graph.  If CALL_TREE is false,
   mark destination symbols on calls as being functions.  Also
   look at branches, which may be tail calls or go to hot/cold
   section part of same function.  */

static bool mark_functions_via_relocs(asection *sec, struct bfd_link_info *info, int call_tree) {
    if (!interesting_section(sec) || sec->reloc_count == 0) return true;

    Elf_Internal_Rela *internal_relocs = _bfd_elf_link_read_relocs(sec->owner, sec, NULL, NULL, info->keep_memory);
    if (internal_relocs == NULL) return false;

    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(sec->owner)->symtab_hdr;
    void *psyms = &symtab_hdr->contents;

    for (Elf_Internal_Rela *irela = internal_relocs, *irelaend = internal_relocs + sec->reloc_count; irela < irelaend; irela++) {
        enum elf_spu_reloc_type r_type = ELF32_R_TYPE(irela->r_info);
        bool nonbranch = (r_type != R_SPU_REL16 && r_type != R_SPU_ADDR16);

        unsigned int r_indx = ELF32_R_SYM(irela->r_info);
        struct elf_link_hash_entry *h = NULL;
        Elf_Internal_Sym *sym = NULL;
        asection *sym_sec = NULL;
        if (!get_sym_h(&h, &sym, &sym_sec, psyms, r_indx, sec->owner)) return false;

        if (sym_sec == NULL || sym_sec->output_section == bfd_abs_section_ptr) continue;

        bool is_call = false;
        unsigned int priority = 0;
        static bool warned;

        if (!nonbranch) {
            unsigned char insn[4];
            if (!bfd_get_section_contents(sec->owner, sec, insn, irela->r_offset, 4)) return false;
            if (is_branch(insn)) {
                is_call = (insn[0] & 0xfd) == 0x31;
                priority = ((insn[1] & 0x0f) << 16) | (insn[2] << 8) | insn[3];
                priority >>= 7;
                if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE)) != (SEC_ALLOC | SEC_LOAD | SEC_CODE)) {
                    if (!warned) {
                        info->callbacks->einfo(_("%pB(%pA+0x%v): call to non-code section %pB(%pA), analysis incomplete\n"),
                                               sec->owner, sec, irela->r_offset, sym_sec->owner, sym_sec);
                        warned = true;
                    }
                    continue;
                }
            } else if (is_hint(insn)) continue;
            else nonbranch = true;
        }

        if (nonbranch) {
            unsigned int sym_type = h ? h->type : ELF_ST_TYPE(sym->st_info);
            if (sym_type == STT_FUNC) {
                if (call_tree && spu_hash_table(info)->params->auto_overlay) {
                    spu_hash_table(info)->non_ovly_stub += 1;
                }
                continue;
            }
            if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE)) != (SEC_ALLOC | SEC_LOAD | SEC_CODE)) continue;
        }

        bfd_vma val = h ? h->root.u.def.value : sym->st_value;
        val += irela->r_addend;

        if (!call_tree) {
            struct function_info *fun;
            if (irela->r_addend != 0) {
                Elf_Internal_Sym *fake = bfd_zmalloc(sizeof(*fake));
                if (fake == NULL) return false;
                fake->st_value = val;
                fake->st_shndx = _bfd_elf_section_from_bfd_section(sym_sec->owner, sym_sec);
                sym = fake;
            }
            fun = sym ? maybe_insert_function(sym_sec, sym, false, is_call) : maybe_insert_function(sym_sec, h, true, is_call);
            if (fun == NULL) return false;
            if (irela->r_addend != 0 && fun->u.sym != sym) free(sym);
            continue;
        }

        struct function_info *caller = find_function(sec, irela->r_offset, info);
        if (caller == NULL) return false;
        
        struct call_info *callee = bfd_malloc(sizeof *callee);
        if (callee == NULL) return false;

        callee->fun = find_function(sym_sec, val, info);
        if (callee->fun == NULL) return false;
        callee->is_tail = !is_call;
        callee->is_pasted = false;
        callee->broken_cycle = false;
        callee->priority = priority;
        callee->count = nonbranch ? 0 : 1;
        if (callee->fun->last_caller != sec) {
            callee->fun->last_caller = sec;
            callee->fun->call_count += 1;
        }
        if (!insert_callee(caller, callee)) free(callee);
        else if (!is_call && !callee->fun->is_func && callee->fun->stack == 0) {
            if (sec->owner != sym_sec->owner) {
                callee->fun->start = NULL;
                callee->fun->is_func = true;
            } else if (callee->fun->start == NULL) {
                struct function_info *caller_start = caller;
                while (caller_start->start) caller_start = caller_start->start;
                if (caller_start != callee->fun) callee->fun->start = caller_start;
            } else {
                struct function_info *callee_start = callee->fun;
                while (callee_start->start) callee_start = callee_start->start;
                struct function_info *caller_start = caller;
                while (caller_start->start) caller_start = caller_start->start;
                if (caller_start != callee_start) {
                    callee->fun->start = NULL;
                    callee->fun->is_func = true;
                }
            }
        }
    }
    return true;
}

/* Handle something like .init or .fini, which has a piece of a function.
   These sections are pasted together to form a single function.  */

static bool pasted_function(asection *sec) {
    struct bfd_link_order *l;
    struct _spu_elf_section_data *sec_data;
    struct spu_elf_stack_info *sinfo;
    Elf_Internal_Sym *fake = bfd_zmalloc(sizeof(*fake));
    if (!fake) return false;

    fake->st_value = 0;
    fake->st_size = sec->size;
    fake->st_shndx = _bfd_elf_section_from_bfd_section(sec->owner, sec);
    struct function_info *fun = maybe_insert_function(sec, fake, false, false);

    if (!fun) {
        free(fake);
        return false;
    }

    struct function_info *fun_start = NULL;
    for (l = sec->output_section->map_head.link_order; l; l = l->next) {
        if (l->u.indirect.section == sec) {
            if (fun_start) {
                struct call_info *callee = bfd_malloc(sizeof(*callee));
                if (!callee) return false;

                fun->start = fun_start;
                callee->fun = fun;
                callee->is_tail = true;
                callee->is_pasted = true;
                callee->broken_cycle = false;
                callee->priority = 0;
                callee->count = 1;
                if (!insert_callee(fun_start, callee)) free(callee);
                return true;
            }
            break;
        }
        if (l->type == bfd_indirect_link_order) {
            sec_data = spu_elf_section_data(l->u.indirect.section);
            if (sec_data) {
                sinfo = sec_data->u.i.stack_info;
                if (sinfo && sinfo->num_fun) {
                    fun_start = &sinfo->fun[sinfo->num_fun - 1];
                }
            }
        }
    }
    return true;
}

/* Map address ranges in code sections to functions.  */

#include <stdbool.h>
#include <stdlib.h>

static bool discover_functions(struct bfd_link_info *info) {
    bfd *ibfd;
    int bfd_idx;
    Elf_Internal_Sym ***psym_arr = NULL;
    asection ***sec_arr = NULL;
    bool gaps = false;

    bfd_idx = 0;
    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
        bfd_idx++;
    }

    psym_arr = bfd_zmalloc(bfd_idx * sizeof(*psym_arr));
    if (psym_arr == NULL) goto cleanup;
    sec_arr = bfd_zmalloc(bfd_idx * sizeof(*sec_arr));
    if (sec_arr == NULL) goto cleanup;

    for (ibfd = info->input_bfds, bfd_idx = 0;
         ibfd != NULL; ibfd = ibfd->link.next, bfd_idx++) {

        if (ibfd->xvec != &spu_elf32_vec) continue;

        Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
        size_t symcount = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
        if (symcount == 0) {
            if (!gaps) {
                for (asection *sec = ibfd->sections; sec != NULL && !gaps; sec = sec->next) {
                    if (interesting_section(sec)) {
                        gaps = true;
                        break;
                    }
                }
            }
            continue;
        }

        free(symtab_hdr->contents);
        symtab_hdr->contents = NULL;
        Elf_Internal_Sym *syms = bfd_elf_get_elf_syms(ibfd, symtab_hdr, symcount, 0, NULL, NULL, NULL);
        if (syms == NULL) goto cleanup;
        symtab_hdr->contents = (void *)syms;

        Elf_Internal_Sym **psyms = bfd_malloc((symcount + 1) * sizeof(*psyms));
        if (psyms == NULL) goto cleanup;
        psym_arr[bfd_idx] = psyms;
        asection **psecs = bfd_malloc(symcount * sizeof(*psecs));
        if (psecs == NULL) goto cleanup;
        sec_arr[bfd_idx] = psecs;

        Elf_Internal_Sym *sy;
        asection **p;
        Elf_Internal_Sym **psy;
        for (psy = psyms, p = psecs, sy = syms; sy < syms + symcount; ++p, ++sy) {
            if (ELF_ST_TYPE(sy->st_info) == STT_NOTYPE || ELF_ST_TYPE(sy->st_info) == STT_FUNC) {
                asection *s = bfd_section_from_elf_index(ibfd, sy->st_shndx);
                if (s != NULL && interesting_section(s)) {
                    *psy++ = sy;
                }
            }
        }
        symcount = psy - psyms;
        *psy = NULL;

        sort_syms_syms = syms;
        sort_syms_psecs = psecs;
        qsort(psyms, symcount, sizeof(*psyms), sort_syms);

        for (psy = psyms; psy < psyms + symcount;) {
            asection *s = psecs[*psy - syms];
            Elf_Internal_Sym **psy2;

            for (psy2 = psy; ++psy2 < psyms + symcount;) {
                if (psecs[*psy2 - syms] != s) break;
            }

            if (!alloc_stack_info(s, psy2 - psy)) goto cleanup;
            psy = psy2;
        }

        for (psy = psyms; psy < psyms + symcount; ++psy) {
            sy = *psy;
            if (ELF_ST_TYPE(sy->st_info) == STT_FUNC) {
                asection *s = psecs[sy - syms];
                if (!maybe_insert_function(s, sy, false, true)) goto cleanup;
            }
        }

        for (asection *sec = ibfd->sections; sec != NULL && !gaps; sec = sec->next) {
            if (interesting_section(sec)) {
                gaps |= check_function_ranges(sec, info);
            }
        }
    }

    if (gaps) {
        for (ibfd = info->input_bfds, bfd_idx = 0;
             ibfd != NULL; ibfd = ibfd->link.next, bfd_idx++) {

            asection *sec;
            if (psym_arr[bfd_idx] == NULL) continue;

            for (sec = ibfd->sections; sec != NULL; sec = sec->next) {
                if (!mark_functions_via_relocs(sec, info, false)) goto cleanup;
            }
        }

        for (ibfd = info->input_bfds, bfd_idx = 0;
             ibfd != NULL; ibfd = ibfd->link.next, bfd_idx++) {

            Elf_Internal_Sym **psyms = psym_arr[bfd_idx];
            if (psyms == NULL) continue;

            asection **psecs = sec_arr[bfd_idx];
            Elf_Internal_Shdr *symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
            Elf_Internal_Sym *syms = (Elf_Internal_Sym *)symtab_hdr->contents;

            gaps = false;
            for (asection *sec = ibfd->sections; sec != NULL && !gaps; sec = sec->next) {
                if (interesting_section(sec)) {
                    gaps |= check_function_ranges(sec, info);
                }
            }
            if (!gaps) continue;

            for (Elf_Internal_Sym **psy = psyms; (sy = *psy) != NULL; ++psy) {
                asection *s = psecs[sy - syms];
                if (ELF_ST_TYPE(sy->st_info) != STT_FUNC && ELF_ST_BIND(sy->st_info) == STB_GLOBAL) {
                    if (!maybe_insert_function(s, sy, false, false)) goto cleanup;
                }
            }
        }

        for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
            if (ibfd->xvec != &spu_elf32_vec) continue;

            for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next) {
                if (interesting_section(sec)) {
                    struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
                    struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
                    if (sinfo != NULL && sinfo->num_fun != 0) {
                        int fun_idx;
                        bfd_vma hi = sec->size;
                        for (fun_idx = sinfo->num_fun; --fun_idx >= 0;) {
                            sinfo->fun[fun_idx].hi = hi;
                            hi = sinfo->fun[fun_idx].lo;
                        }
                        sinfo->fun[0].lo = 0;
                    } else if (!pasted_function(sec)) goto cleanup;
                }
            }
        }
    }

    for (ibfd = info->input_bfds, bfd_idx = 0; ibfd != NULL; ibfd = ibfd->link.next, bfd_idx++) {
        if (psym_arr[bfd_idx] != NULL) {
            free(psym_arr[bfd_idx]);
            free(sec_arr[bfd_idx]);
        }
    }

    free(psym_arr);
    free(sec_arr);

    return true;

cleanup:
    if (psym_arr != NULL) {
        for (int i = 0; i < bfd_idx; i++) {
            free(psym_arr[i]);
        }
        free(psym_arr);
    }

    if (sec_arr != NULL) {
        for (int i = 0; i < bfd_idx; i++) {
            free(sec_arr[i]);
        }
        free(sec_arr);
    }
    
    return false;
}

/* Iterate over all function_info we have collected, calling DOIT on
   each node if ROOT_ONLY is false.  Only call DOIT on root nodes
   if ROOT_ONLY.  */

static bool for_each_node(bool (*doit)(struct function_info *, struct bfd_link_info *, void *), 
                          struct bfd_link_info *info, 
                          void *param, 
                          int root_only) 
{
    extern const bfd_target spu_elf32_vec;
    for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
        if (ibfd->xvec != &spu_elf32_vec) {
            continue;
        }
        
        for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next) {
            struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
            if (sec_data == NULL) {
                continue;
            }
            
            struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
            if (sinfo == NULL) {
                continue;
            }
            
            for (int i = 0; i < sinfo->num_fun; ++i) {
                if (root_only && sinfo->fun[i].non_root) {
                    continue;
                }
                
                if (!doit(&sinfo->fun[i], info, param)) {
                    return false;
                }
            }
        }
    }
    return true;
}

/* Transfer call info attached to struct function_info entries for
   all of a given function's sections to the first entry.  */

static bool transfer_calls(struct function_info *fun) {
    if (!fun || !fun->start) {
        return true;
    }

    struct function_info *start = fun->start;
    while (start->start) {
        start = start->start;
    }
  
    struct call_info *call = fun->call_list;
    while (call) {
        struct call_info *call_next = call->next;
        if (!insert_callee(start, call)) {
            free(call);
        }
        call = call_next;
    }
  
    fun->call_list = NULL;
    return true;
}

/* Mark nodes in the call graph that are called by some other node.  */

static bool mark_non_root(struct function_info *fun) {
    if (!fun || fun->visit1) return true;

    fun->visit1 = true;
    struct call_info *call = fun->call_list;
    while (call) {
        if (call->fun) {
            call->fun->non_root = true;
            mark_non_root(call->fun);
        }
        call = call->next;
    }
    return true;
}

/* Remove cycles from the call graph.  Set depth of nodes.  */

bool remove_cycles(struct function_info *fun, struct bfd_link_info *info, void *param) {
    struct call_info *call;
    unsigned int *depth_param = (unsigned int *)param;
    unsigned int max_depth = *depth_param;

    fun->depth = *depth_param;
    fun->visit2 = true;
    fun->marking = true;

    for (call = fun->call_list; call != NULL; call = call->next) {
        unsigned int call_max_depth = max_depth + !call->is_pasted;
        call->max_depth = call_max_depth;

        if (!call->fun->visit2) {
            if (!remove_cycles(call->fun, info, &call->max_depth)) {
                fun->marking = false;
                return false;
            }
            if (max_depth < call->max_depth) {
                max_depth = call->max_depth;
            }
        } else if (call->fun->marking) {
            struct spu_link_hash_table *htab = spu_hash_table(info);

            if (!htab->params->auto_overlay && htab->params->stack_analysis) {
                const char *f1 = func_name(fun);
                const char *f2 = func_name(call->fun);
                info->callbacks->info(_("stack analysis will ignore the call from %s to %s\n"), f1, f2);
            }

            call->broken_cycle = true;
        }
    }
    fun->marking = false;
    *depth_param = max_depth;
    return true;
}

/* Check that we actually visited all nodes in remove_cycles.  If we
   didn't, then there is some cycle in the call graph not attached to
   any root node.  Arbitrarily choose a node in the cycle as a new
   root and break the cycle.  */

bool mark_detached_root(struct function_info *fun, struct bfd_link_info *info, void *param) {
    if (fun->visit2) 
        return true;
    fun->non_root = false;
    
    if (!param) 
        return false;
    
    *(unsigned int *)param = 0;
    return remove_cycles(fun, info, param);
}

/* Populate call_list for each function.  */

bool build_call_tree(struct bfd_link_info *info) {
    for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
        extern const bfd_target spu_elf32_vec;
        if (ibfd->xvec == &spu_elf32_vec) {
            for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next) {
                if (!mark_functions_via_relocs(sec, info, true)) {
                    return false;
                }
            }
        }
    }

    if (!spu_hash_table(info)->params->auto_overlay &&
        !for_each_node(transfer_calls, info, 0, false)) {
        return false;
    }

    if (!for_each_node(mark_non_root, info, 0, false)) {
        return false;
    }

    unsigned int depth = 0;
    if (!for_each_node(remove_cycles, info, &depth, true)) {
        return false;
    }

    return for_each_node(mark_detached_root, info, &depth, false);
}

/* qsort predicate to sort calls by priority, max_depth then count.  */

int sort_calls(const void *a, const void *b) {
    const struct call_info *c1 = *((const struct call_info **)a);
    const struct call_info *c2 = *((const struct call_info **)b);
    
    if (c2->priority != c1->priority) {
        return c2->priority - c1->priority;
    }
    if (c2->max_depth != c1->max_depth) {
        return c2->max_depth - c1->max_depth;
    }
    if (c2->count != c1->count) {
        return c2->count - c1->count;
    }
    
    return (char *) a - (char *) b;
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

static bool mark_overlay_section(struct function_info *fun, struct bfd_link_info *info, void *param) {
    struct call_info *call;
    unsigned int count = 0;
    struct _mos_param *mos_param = param;
    struct spu_link_hash_table *htab = spu_hash_table(info);

    if (fun->visit4) return true;

    fun->visit4 = true;

    if (!fun->sec->linker_mark && 
        (htab->params->ovly_flavour != ovly_soft_icache || 
         htab->params->non_ia_text || 
         startswith(fun->sec->name, ".text.ia.") || 
         strcmp(fun->sec->name, ".init") == 0 || 
         strcmp(fun->sec->name, ".fini") == 0)) {

        unsigned int size = fun->sec->size;
        fun->sec->linker_mark = 1;
        fun->sec->gc_mark = 1;
        fun->sec->segment_mark = 0;
        fun->sec->flags |= SEC_CODE;

        if (htab->params->auto_overlay & OVERLAY_RODATA) {
            const char *suffix = NULL;
            size_t len = 0;
            
            if (strcmp(fun->sec->name, ".text") == 0) {
                suffix = ".rodata";
            } else if (startswith(fun->sec->name, ".text.")) {
                len = strlen(fun->sec->name);
                suffix = ".rodata";
            } else if (startswith(fun->sec->name, ".gnu.linkonce.t.")) {
                len = strlen(fun->sec->name) + 1;
            }

            if (suffix) {
                char *name = bfd_malloc((len ? len : strlen(suffix)) + 1);
                if (!name) return false;

                if (len) {
                    memcpy(name, fun->sec->name, len);
                    name[14] = 'r';
                } else {
                    memcpy(name, suffix, strlen(suffix) + 1);
                }

                asection *rodata = NULL;
                asection *group_sec = elf_section_data(fun->sec)->next_in_group;

                retieve_rodata:
                while (group_sec && group_sec != fun->sec) {
                    if (strcmp(group_sec->name, name) == 0) {
                        rodata = group_sec;
                        break;
                    }
                    group_sec = elf_section_data(group_sec)->next_in_group;
                }

                if (!group_sec || !rodata) {
                    rodata = bfd_get_section_by_name(fun->sec->owner, name);
                }

                fun->rodata = rodata;
                if (fun->rodata && (!htab->params->line_size || size <= htab->params->line_size)) {
                    size += fun->rodata->size;
                    fun->rodata->linker_mark = 1;
                    fun->rodata->gc_mark = 1;
                    fun->rodata->flags &= ~SEC_CODE;
                }
                free(name);
            }
        }

        if (mos_param->max_overlay_size < size) mos_param->max_overlay_size = size;
    }

    for (call = fun->call_list; call; call = call->next) count++;

    if (count > 1) {
        struct call_info **calls = bfd_malloc(count * sizeof(*calls));
        if (!calls) return false;

        for (count = 0, call = fun->call_list; call; call = call->next) calls[count++] = call;
        qsort(calls, count, sizeof(*calls), sort_calls);

        fun->call_list = NULL;
        while (count--) {
            calls[count]->next = fun->call_list;
            fun->call_list = calls[count];
        }
        free(calls);
    }

    for (call = fun->call_list; call; call = call->next) {
        if (call->is_pasted) fun->sec->segment_mark = 1;
        if (!call->broken_cycle && !mark_overlay_section(call->fun, info, param)) return false;
    }

    if (fun->lo + fun->sec->output_offset + fun->sec->output_section->vma == info->output_bfd->start_address
        || startswith(fun->sec->output_section->name, ".ovl.init")) {
        fun->sec->linker_mark = 0;
        if (fun->rodata) fun->rodata->linker_mark = 0;
    }

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

static bool unmark_overlay_section(struct function_info *fun, struct bfd_link_info *info, void *param) {
    struct call_info *call;
    struct _uos_param *uos_param = param;
    unsigned int excluded = 0;

    if (fun->visit5) {
        return true;
    }

    fun->visit5 = true;

    if (fun->sec == uos_param->exclude_input_section || fun->sec->output_section == uos_param->exclude_output_section) {
        excluded = 1;
    }

    if (RECURSE_UNMARK) {
        uos_param->clearing += excluded;
    }

    if ((RECURSE_UNMARK && uos_param->clearing) || excluded) {
        fun->sec->linker_mark = 0;
        if (fun->rodata) {
            fun->rodata->linker_mark = 0;
        }
    }

    for (call = fun->call_list; call != NULL; call = call->next) {
        if (!call->broken_cycle && !unmark_overlay_section(call->fun, info, param)) {
            return false;
        }
    }

    if (RECURSE_UNMARK) {
        uos_param->clearing -= excluded;
    }
    return true;
}

struct _cl_param {
  unsigned int lib_size;
  asection **lib_sections;
};

/* Add sections we have marked as belonging to overlays to an array
   for consideration as non-overlay sections.  The array consist of
   pairs of sections, (text,rodata), for functions in the call graph.  */

static bool
collect_lib_sections(struct function_info *fun,
                     struct bfd_link_info *info,
                     void *param)
{
    struct _cl_param *lib_param = param;

    if (fun->visit6 || !fun->sec->linker_mark || !fun->sec->gc_mark || fun->sec->segment_mark) {
        return true;
    }

    fun->visit6 = true;

    unsigned int total_size = fun->sec->size + (fun->rodata ? fun->rodata->size : 0);

    if (total_size <= lib_param->lib_size) {
        *lib_param->lib_sections++ = fun->sec;
        fun->sec->gc_mark = 0;

        if (fun->rodata && fun->rodata->linker_mark && fun->rodata->gc_mark) {
            *lib_param->lib_sections++ = fun->rodata;
            fun->rodata->gc_mark = 0;
        } else {
            *lib_param->lib_sections++ = NULL;
        }
    }

    for (struct call_info *call = fun->call_list; call != NULL; call = call->next) {
        if (!call->broken_cycle) {
            collect_lib_sections(call->fun, info, param);
        }
    }

    return true;
}

/* qsort predicate to sort sections by call count.  */

static int sort_lib(const void *a, const void *b) {
    asection *const *s1 = a;
    asection *const *s2 = b;

    int delta = calculate_delta(*s1) - calculate_delta(*s2);

    return delta != 0 ? delta : compare_pointers(s1, s2);
}

static int calculate_delta(asection *section) {
    struct _spu_elf_section_data *sec_data = spu_elf_section_data(section);
    if (sec_data == NULL) {
        return 0;
    }

    struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
    if (sinfo == NULL) {
        return 0;
    }
    
    int total_call_count = 0;
    for (int i = 0; i < sinfo->num_fun; ++i) {
        total_call_count += sinfo->fun[i].call_count;
    }

    return total_call_count;
}

static int compare_pointers(const asection *const *s1, const asection *const *s2) {
    return s1 < s2 ? -1 : (s1 > s2 ? 1 : 0);
}

/* Remove some sections from those marked to be in overlays.  Choose
   those that are called from many places, likely library functions.  */

#include <stdlib.h>
#include <string.h>

static unsigned int auto_ovl_lib_functions(struct bfd_link_info *info, unsigned int lib_size) {
    bfd *ibfd;
    asection **lib_sections;
    unsigned int lib_count = 0;
    struct _cl_param collect_lib_param;
    struct function_info dummy_caller = {0};
    struct spu_link_hash_table *htab = spu_hash_table(info);

    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
        extern const bfd_target spu_elf32_vec;
        if (ibfd->xvec != &spu_elf32_vec) continue;
        for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next) {
            if (sec->linker_mark && sec->size < lib_size && (sec->flags & SEC_CODE)) {
                lib_count++;
            }
        }
    }

    if (!(lib_sections = malloc(lib_count * 2 * sizeof(*lib_sections)))) return (unsigned int)-1;

    collect_lib_param.lib_size = lib_size;
    collect_lib_param.lib_sections = lib_sections;
    if (!for_each_node(collect_lib_sections, info, &collect_lib_param, true)) {
        free(lib_sections);
        return (unsigned int)-1;
    }

    lib_count = (collect_lib_param.lib_sections - lib_sections) / 2;
    if (lib_count > 1) qsort(lib_sections, lib_count, 2 * sizeof(*lib_sections), sort_lib);

    for (unsigned int i = 0; i < lib_count; i++) {
        asection *sec = lib_sections[2 * i];
        unsigned int tmp = sec->size;
        if (lib_sections[2 * i + 1]) tmp += lib_sections[2 * i + 1]->size;

        struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
        struct spu_elf_stack_info *sinfo = sec_data ? sec_data->u.i.stack_info : NULL;

        unsigned int stub_size = 0;
        if (tmp < lib_size && sinfo) {
            for (int k = 0; k < sinfo->num_fun; ++k) {
                for (struct call_info *call = sinfo->fun[k].call_list; call; call = call->next) {
                    if (call->fun->sec->linker_mark) {
                        for (struct call_info *p = dummy_caller.call_list; p; p = p->next) {
                            if (p->fun == call->fun) break;
                        }
                        if (!p) stub_size += ovl_stub_size(htab->params);
                    }
                }
            }
        }

        if (tmp + stub_size < lib_size) {
            sec->linker_mark = 0;
            if (lib_sections[2 * i + 1]) lib_sections[2 * i + 1]->linker_mark = 0;
            lib_size -= tmp + stub_size;

            for (struct call_info **pp = &dummy_caller.call_list, *p; (p = *pp) != NULL;) {
                if (!p->fun->sec->linker_mark) {
                    lib_size += ovl_stub_size(htab->params);
                    *pp = p->next;
                    free(p);
                } else {
                    pp = &p->next;
                }
            }

            if (sinfo) {
                for (int k = 0; k < sinfo->num_fun; ++k) {
                    for (struct call_info *call = sinfo->fun[k].call_list; call; call = call->next) {
                        if (call->fun->sec->linker_mark) {
                            struct call_info *callee = malloc(sizeof(*callee));
                            if (!callee) {
                                free(lib_sections);
                                return (unsigned int)-1;
                            }
                            *callee = *call;
                            if (!insert_callee(&dummy_caller, callee)) free(callee);
                        }
                    }
                }
            }
        }
    }

    while (dummy_caller.call_list) {
        struct call_info *call = dummy_caller.call_list;
        dummy_caller.call_list = call->next;
        free(call);
    }

    for (unsigned int i = 0; i < 2 * lib_count; i++) {
        if (lib_sections[i]) lib_sections[i]->gc_mark = 1;
    }

    free(lib_sections);
    return lib_size;
}

/* Build an array of overlay sections.  The deepest node's section is
   added first, then its parent node's section, then everything called
   from the parent section.  The idea being to group sections to
   minimise calls between different overlays.  */

static bool collect_overlays(struct function_info *fun, struct bfd_link_info *info, void *param) {
    struct call_info *call;
    asection ***ovly_sections = param;

    if (fun->visit7) {
        return true;
    }

    fun->visit7 = true;

    for (call = fun->call_list; call != NULL; call = call->next) {
        if (!call->is_pasted && !call->broken_cycle) {
            if (!collect_overlays(call->fun, info, ovly_sections)) {
                return false;
            }
            break; // Break after first relevant call to simplify logic
        }
    }

    bool should_add = (fun->sec->linker_mark && fun->sec->gc_mark);
    if (should_add) {
        fun->sec->gc_mark = 0;
        *(*ovly_sections)++ = fun->sec;
        if (fun->rodata && fun->rodata->linker_mark && fun->rodata->gc_mark) {
            fun->rodata->gc_mark = 0;
            *(*ovly_sections)++ = fun->rodata;
        } else {
            *(*ovly_sections)++ = NULL;
        }

        if (fun->sec->segment_mark) {
            struct function_info *call_fun = fun;
            do {
                bool found_pasted = false;
                for (call = call_fun->call_list; call != NULL; call = call->next) {
                    if (call->is_pasted) {
                        call_fun = call->fun;
                        call_fun->sec->gc_mark = 0;
                        if (call_fun->rodata) {
                            call_fun->rodata->gc_mark = 0;
                        }
                        found_pasted = true;
                        break;
                    }
                }
                if (!found_pasted) {
                    return false; // Replace 'abort' with a clean return
                }
            } while (call_fun->sec->segment_mark);
        }
    }

    for (call = fun->call_list; call != NULL; call = call->next) {
        if (!call->broken_cycle && !collect_overlays(call->fun, info, ovly_sections)) {
            return false;
        }
    }

    if (should_add) {
        struct _spu_elf_section_data *sec_data = spu_elf_section_data(fun->sec);
        if (sec_data) {
            struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
            if (sinfo) {
                for (int i = 0; i < sinfo->num_fun; ++i) {
                    if (!collect_overlays(&sinfo->fun[i], info, ovly_sections)) {
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

struct _sum_stack_param {
  size_t cum_stack;
  size_t overall_stack;
  bool emit_stack_syms;
};

/* Descend the call graph for FUN, accumulating total stack required.  */

static bool sum_stack(struct function_info *fun, struct bfd_link_info *info, void *param) {
    struct call_info *call;
    struct function_info *max = NULL;
    size_t stack, cum_stack = fun->stack;
    const char *f1;
    bool has_call = false;
    struct _sum_stack_param *sum_stack_param = param;
    struct spu_link_hash_table *htab = spu_hash_table(info);

    sum_stack_param->cum_stack = cum_stack;
    if (fun->visit3) {
        return true;
    }

    for (call = fun->call_list; call; call = call->next) {
        if (call->broken_cycle) {
            continue;
        }

        if (!call->is_pasted) {
            has_call = true;
        }

        if (!sum_stack(call->fun, info, sum_stack_param)) {
            return false;
        }

        stack = sum_stack_param->cum_stack;
        if (!call->is_tail || call->is_pasted || call->fun->start != NULL) {
            stack += fun->stack;
        }

        if (cum_stack < stack) {
            cum_stack = stack;
            max = call->fun;
        }
    }

    fun->stack = cum_stack;
    fun->visit3 = true;

    if (!fun->non_root && sum_stack_param->overall_stack < cum_stack) {
        sum_stack_param->overall_stack = cum_stack;
    }

    if (htab->params->auto_overlay) {
        return true;
    }

    f1 = func_name(fun);
    if (htab->params->stack_analysis) {
        if (!fun->non_root) {
            info->callbacks->info("  %s: 0x%lx\n", f1, (unsigned long)cum_stack);
        }
        info->callbacks->minfo("%s: 0x%lx 0x%lx\n", f1, (unsigned long)fun->stack, (unsigned long)cum_stack);

        if (has_call) {
            info->callbacks->minfo(_("  calls:\n"));
            for (call = fun->call_list; call; call = call->next) {
                if (!call->is_pasted && !call->broken_cycle) {
                    const char *f2 = func_name(call->fun);
                    const char *ann1 = call->fun == max ? "*" : " ";
                    const char *ann2 = call->is_tail ? "t" : " ";
                    info->callbacks->minfo("   %s%s %s\n", ann1, ann2, f2);
                }
            }
        }
    }

    if (sum_stack_param->emit_stack_syms) {
        char *name = bfd_malloc(18 + strlen(f1));
        struct elf_link_hash_entry *h;

        if (name == NULL) {
            return false;
        }

        sprintf(name, fun->global || ELF_ST_BIND(fun->u.sym->st_info) == STB_GLOBAL ? "__stack_%s" : "__stack_%x_%s",
                (fun->global || ELF_ST_BIND(fun->u.sym->st_info) == STB_GLOBAL ? "" : fun->sec->id & 0xffffffff), f1);

        h = elf_link_hash_lookup(&htab->elf, name, true, true, false);
        free(name);

        if (h != NULL && (h->root.type == bfd_link_hash_new || h->root.type == bfd_link_hash_undefined || h->root.type == bfd_link_hash_undefweak)) {
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
    }

    return true;
}

/* SEC is part of a pasted function.  Return the call_info for the
   next section of this function.  */

static struct call_info *find_pasted_call(asection *sec) {
    struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
    struct spu_elf_stack_info *sinfo = sec_data ? sec_data->u.i.stack_info : NULL;
    if (!sinfo) {
        return NULL;
    }

    for (int k = 0; k < sinfo->num_fun; ++k) {
        struct call_info *call = sinfo->fun[k].call_list;
        while (call) {
            if (call->is_pasted) {
                return call;
            }
            call = call->next;
        }
    }
    return NULL;
}

/* qsort predicate to sort bfds by file name.  */

#include <stdlib.h>

static int compare_bfds(const void *a, const void *b) {
    const bfd *abfd1 = *((const bfd **)a);
    const bfd *abfd2 = *((const bfd **)b);
    return filename_cmp(bfd_get_filename(abfd1), bfd_get_filename(abfd2));
}

static int sort_bfds(const void *a, const void *b) {
    return compare_bfds(a, b);
}

static unsigned int print_one_overlay_section(FILE *script, unsigned int base, unsigned int count, unsigned int ovlynum, unsigned int *ovly_map, asection **ovly_sections, struct bfd_link_info *info) {
    unsigned int j;

    for (j = base; j < count && ovly_map[j] == ovlynum; j++) {
        asection *sec = ovly_sections[2 * j];

        if (fprintf(script, "   %s%c%s (%s)\n",
                    (sec->owner->my_archive != NULL ? bfd_get_filename(sec->owner->my_archive) : ""),
                    info->path_separator, bfd_get_filename(sec->owner), sec->name) <= 0) {
            return -1;
        }

        if (sec->segment_mark) {
            struct call_info *call = find_pasted_call(sec);
            while (call != NULL) {
                struct function_info *call_fun = call->fun;
                sec = call_fun->sec;
                if (fprintf(script, "   %s%c%s (%s)\n",
                            (sec->owner->my_archive != NULL ? bfd_get_filename(sec->owner->my_archive) : ""),
                            info->path_separator, bfd_get_filename(sec->owner), sec->name) <= 0) {
                    return -1;
                }
                for (call = call_fun->call_list; call; call = call->next) {
                    if (call->is_pasted) {
                        break;
                    }
                }
            }
        }
    }

    for (j = base; j < count && ovly_map[j] == ovlynum; j++) {
        asection *sec_rodata = ovly_sections[2 * j + 1];
        if (sec_rodata != NULL && fprintf(script, "   %s%c%s (%s)\n",
                                          (sec_rodata->owner->my_archive != NULL ? bfd_get_filename(sec_rodata->owner->my_archive) : ""),
                                          info->path_separator, bfd_get_filename(sec_rodata->owner), sec_rodata->name) <= 0) {
            return -1;
        }

        asection *sec = ovly_sections[2 * j];
        if (sec->segment_mark) {
            struct call_info *call = find_pasted_call(sec);
            while (call != NULL) {
                struct function_info *call_fun = call->fun;
                sec_rodata = call_fun->rodata;
                if (sec_rodata != NULL && fprintf(script, "   %s%c%s (%s)\n",
                                                  (sec_rodata->owner->my_archive != NULL ? bfd_get_filename(sec_rodata->owner->my_archive) : ""),
                                                  info->path_separator, bfd_get_filename(sec_rodata->owner), sec_rodata->name) <= 0) {
                    return -1;
                }
                for (call = call_fun->call_list; call; call = call->next) {
                    if (call->is_pasted) {
                        break;
                    }
                }
            }
        }
    }

    return j;
}

/* Handle --auto-overlay.  */

static void spu_elf_auto_overlay(struct bfd_link_info *info) {
    bfd *ibfd;
    bfd **bfd_arr;
    struct elf_segment_map *m;
    unsigned int fixed_size = 0, lo = (unsigned int)-1, hi = 0;
    unsigned int reserved, base = 0, i = 0, count = 0, bfd_count = 0;
    unsigned int ovlynum = 0;
    asection **ovly_sections, **ovly_p;
    unsigned int *ovly_map;
    FILE *script;
    unsigned int total_overlay_size = 0, overlay_size = 0;
    const char *ovly_mgr_entry;
    struct elf_link_hash_entry *h;
    struct _mos_param mos_param = {0};
    struct _uos_param uos_param = {0};
    struct function_info dummy_caller = {0};

    for (m = elf_seg_map(info->output_bfd); m != NULL; m = m->next) {
        if (m->p_type == PT_LOAD) {
            for (i = 0; i < m->count; i++) {
                if (m->sections[i]->size != 0) {
                    if (m->sections[i]->vma < lo) lo = m->sections[i]->vma;
                    if (m->sections[i]->vma + m->sections[i]->size - 1 > hi) hi = m->sections[i]->vma + m->sections[i]->size - 1;
                }
            }
        }
    }
    fixed_size = hi + 1 - lo;

    if (!discover_functions(info) || !build_call_tree(info))
        goto err_exit;

    struct spu_link_hash_table *htab = spu_hash_table(info);
    reserved = htab->params->auto_overlay_reserved;
    if (reserved == 0) {
        struct _sum_stack_param sum_stack_param = {0};
        if (!for_each_node(sum_stack, info, &sum_stack_param, true)) goto err_exit;
        reserved = (sum_stack_param.overall_stack + htab->params->extra_stack_space);
    }

    if (fixed_size + reserved <= htab->local_store && htab->params->ovly_flavour != ovly_soft_icache) {
        htab->params->auto_overlay = 0;
        return;
    }

    uos_param.exclude_output_section = bfd_get_section_by_name(info->output_bfd, ".interrupt");
    ovly_mgr_entry = (htab->params->ovly_flavour == ovly_soft_icache) ? "__icache_br_handler" : "__ovly_load";
    h = elf_link_hash_lookup(&htab->elf, ovly_mgr_entry, false, false, false);
    
    if (h && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) && h->def_regular) {
        uos_param.exclude_input_section = h->root.u.def.section;
    } else {
        fixed_size += (*htab->params->spu_elf_load_ovl_mgr)();
    }

    if (!for_each_node(mark_overlay_section, info, &mos_param, true)) goto err_exit;

    uos_param.clearing = 0;
    if ((uos_param.exclude_input_section || uos_param.exclude_output_section) && !for_each_node(unmark_overlay_section, info, &uos_param, true))
        goto err_exit;

    bfd_count = 0;
    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) bfd_count++;
    bfd_arr = bfd_malloc(bfd_count * sizeof(*bfd_arr));
    if (bfd_arr == NULL) goto err_exit;

    count = 0;
    bfd_count = 0;
    total_overlay_size = 0;
    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
        extern const bfd_target spu_elf32_vec;
        if (ibfd->xvec != &spu_elf32_vec) continue;
        unsigned int old_count = count;
        asection *sec;
        for (sec = ibfd->sections; sec != NULL; sec = sec->next) {
            if (sec->linker_mark) {
                if ((sec->flags & SEC_CODE) != 0) count += 1;
                fixed_size -= sec->size;
                total_overlay_size += sec->size;
            } else if ((sec->flags & (SEC_ALLOC | SEC_LOAD)) == (SEC_ALLOC | SEC_LOAD)
                && sec->output_section->owner == info->output_bfd
                && startswith(sec->output_section->name, ".ovl.init")) {
                fixed_size -= sec->size;
            }
        }
        if (count != old_count) bfd_arr[bfd_count++] = ibfd;
    }

    if (bfd_count > 1) {
        qsort(bfd_arr, bfd_count, sizeof(*bfd_arr), sort_bfds);
        bool ok = true;
        for (i = 1; i < bfd_count; ++i) {
            if (filename_cmp(bfd_get_filename(bfd_arr[i - 1]), bfd_get_filename(bfd_arr[i])) == 0) {
                if (bfd_arr[i - 1]->my_archive == bfd_arr[i]->my_archive) {
                    info->callbacks->einfo(_("%s duplicated in %s\n"), bfd_get_filename(bfd_arr[i]), bfd_get_filename(bfd_arr[i]->my_archive));
                } else {
                    info->callbacks->einfo(_("%s duplicated\n"), bfd_get_filename(bfd_arr[i]));
                }
                ok = false;
            }
        }
        if (!ok) {
            info->callbacks->einfo(_("sorry, no support for duplicate object files in auto-overlay script\n"));
            bfd_set_error(bfd_error_bad_value);
            goto err_exit;
        }
    }
    free(bfd_arr);

    fixed_size += reserved;
    fixed_size += htab->non_ovly_stub * ovl_stub_size(htab->params);
    if (fixed_size + mos_param.max_overlay_size <= htab->local_store) {
        if (htab->params->ovly_flavour == ovly_soft_icache) {
            fixed_size += htab->non_ovly_stub * 16;
            fixed_size += 16 << htab->num_lines_log2;
            fixed_size += 16 << htab->num_lines_log2;
            fixed_size += 16 << (htab->fromelem_size_log2 + htab->num_lines_log2);
            fixed_size += 16;
        } else {
            ovlynum = (total_overlay_size * 2 * htab->params->num_lines / (htab->local_store - fixed_size));
            fixed_size += ovlynum * 16 + 16 + 4 + 16;
        }
    }

    if (fixed_size + mos_param.max_overlay_size > htab->local_store) {
        info->callbacks->einfo(_("non-overlay size of 0x%v plus maximum overlay size of 0x%v exceeds local store\n"), 
            (bfd_vma)fixed_size, (bfd_vma)mos_param.max_overlay_size);
    } else if (fixed_size < htab->params->auto_overlay_fixed) {
        unsigned int max_fixed = htab->local_store - mos_param.max_overlay_size;
        if (max_fixed > htab->params->auto_overlay_fixed) max_fixed = htab->params->auto_overlay_fixed;
        unsigned int lib_size = max_fixed - fixed_size;
        lib_size = auto_ovl_lib_functions(info, lib_size);
        if (lib_size == (unsigned int)-1) goto err_exit;
        fixed_size = max_fixed - lib_size;
    }

    ovly_sections = bfd_malloc(2 * count * sizeof(*ovly_sections));
    if (ovly_sections == NULL) goto err_exit;
    ovly_p = ovly_sections;
    if (!for_each_node(collect_overlays, info, &ovly_p, true)) goto err_exit;
    count = (size_t)(ovly_p - ovly_sections) / 2;

    ovly_map = bfd_malloc(count * sizeof(*ovly_map));
    if (ovly_map == NULL) goto err_exit;

    overlay_size = (htab->local_store - fixed_size) / htab->params->num_lines;
    if (htab->params->line_size != 0) overlay_size = htab->params->line_size;

    base = 0;
    ovlynum = 0;
    while (base < count) {
        unsigned int size = 0, rosize = 0, roalign = 0;

        for (i = base; i < count; i++) {
            asection *sec = ovly_sections[2 * i];
            unsigned int tmp = align_power(size, sec->alignment_power) + sec->size;

            unsigned int rotmp = rosize;
            asection *rosec = ovly_sections[2 * i + 1];
            if (rosec != NULL) {
                rotmp = align_power(rotmp, rosec->alignment_power) + rosec->size;
                if (roalign < rosec->alignment_power) roalign = rosec->alignment_power;
            }

            if (align_power(tmp, roalign) + rotmp > overlay_size) break;

            if (sec->segment_mark) {
                struct call_info *pasty = find_pasted_call(sec);
                while (pasty != NULL) {
                    struct function_info *call_fun = pasty->fun;
                    tmp = align_power(tmp, call_fun->sec->alignment_power) + call_fun->sec->size;
                    if (call_fun->rodata) {
                        rotmp = align_power(rotmp, call_fun->rodata->alignment_power) + call_fun->rodata->size;
                        if (roalign < rosec->alignment_power) roalign = rosec->alignment_power;
                    }
                    pasty = NULL; // Reset pasty to find next call
                    for (pasty = call_fun->call_list; pasty && pasty->is_pasted; pasty = pasty->next);
                }
            }
            if (align_power(tmp, roalign) + rotmp > overlay_size) break;

            struct call_info *call = NULL, *pasty = NULL;
            struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
            struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
            unsigned int k;
            for (k = 0; k < (unsigned)sinfo->num_fun; ++k) {
                for (call = sinfo->fun[k].call_list; call; call = call->next) {
                    if (call->is_pasted) pasty = call;
                    else if (call->fun->sec->linker_mark && !copy_callee(&dummy_caller, call)) goto err_exit;
                }
                while (pasty != NULL) {
                    struct function_info *call_fun = pasty->fun;
                    pasty = NULL;
                    for (call = call_fun->call_list; call; call = call->next) {
                        if (call->is_pasted) pasty = call;
                        else if (!copy_callee(&dummy_caller, call)) goto err_exit;
                    }
                }
            }

            unsigned int num_stubs = 0;
            for (call = dummy_caller.call_list; call; call = call->next) {
                unsigned int stub_delta = 1;
                if (htab->params->ovly_flavour == ovly_soft_icache) stub_delta = call->count;
                num_stubs += stub_delta;
                for (k = base; k < i + 1; k++) {
                    if (call->fun->sec == ovly_sections[2 * k]) {
                        num_stubs -= stub_delta;
                        break;
                    }
                }
            }

            if (htab->params->ovly_flavour == ovly_soft_icache && num_stubs > htab->params->max_branch) break;
            if (align_power(tmp, roalign) + rotmp + num_stubs * ovl_stub_size(htab->params) > overlay_size) break;

            size = tmp;
            rosize = rotmp;
        }

        if (i == base) {
            info->callbacks->einfo(_("%pB:%pA%s exceeds overlay size\n"),
                ovly_sections[2 * i]->owner, ovly_sections[2 * i], ovly_sections[2 * i + 1] ? " + rodata" : "");
            bfd_set_error(bfd_error_bad_value);
            goto err_exit;
        }

        while (dummy_caller.call_list != NULL) {
            struct call_info *call = dummy_caller.call_list;
            dummy_caller.call_list = call->next;
            free(call);
        }

        ++ovlynum;
        while (base < i) ovly_map[base++] = ovlynum;
    }

    script = htab->params->spu_elf_open_overlay_script();
    if (htab->params->ovly_flavour == ovly_soft_icache) {
        if (fprintf(script, "SECTIONS\n{\n") <= 0) goto file_err;
        if (fprintf(script, " . = ALIGN (%u);\n .ovl.init : { *(.ovl.init) }\n . = ABSOLUTE (ADDR (.ovl.init));\n", 
            htab->params->line_size) <= 0) goto file_err;

        base = 0;
        ovlynum = 1;
        while (base < count) {
            unsigned int indx = ovlynum - 1;
            unsigned int vma = (indx & (htab->params->num_lines - 1)) << htab->line_size_log2;
            unsigned int lma = vma + (((indx >> htab->num_lines_log2) + 1) << 18);

            if (fprintf(script, " .ovly%u ABSOLUTE (ADDR (.ovl.init)) + %u : AT (LOADADDR (.ovl.init) + %u) {\n", 
                ovlynum, vma, lma) <= 0) goto file_err;

            base = print_one_overlay_section(script, base, count, ovlynum, ovly_map, ovly_sections, info);
            if (base == (unsigned) -1) goto file_err;
            if (fprintf(script, "  }\n") <= 0) goto file_err;

            ovlynum++;
        }
        if (fprintf(script, " . = ABSOLUTE (ADDR (.ovl.init)) + %u;\n", 1 << (htab->num_lines_log2 + htab->line_size_log2)) <= 0) goto file_err;
        if (fprintf(script, "}\nINSERT AFTER .toe;\n") <= 0) goto file_err;
    } else {
        if (fprintf(script, "SECTIONS\n{\n") <= 0) goto file_err;
        if (fprintf(script, " . = ALIGN (16);\n .ovl.init : { *(.ovl.init) }\n . = ABSOLUTE (ADDR (.ovl.init));\n") <= 0) goto file_err;

        unsigned int region = 1;
        while (region <= htab->params->num_lines) {
            ovlynum = region;
            base = 0;
            while (base < count && ovly_map[base] < ovlynum) base++;
            if (base == count) break;

            if (region == 1) {
                if (fprintf(script, " OVERLAY : AT (ALIGN (LOADADDR (.ovl.init) + SIZEOF (.ovl.init), 16))\n {\n") <= 0) goto file_err;
            } else {
                if (fprintf(script, " OVERLAY :\n {\n") <= 0) goto file_err;
            }

            while (base < count) {
                if (fprintf(script, "  .ovly%u {\n", ovlynum) <= 0) goto file_err;
                base = print_one_overlay_section(script, base, count, ovlynum, ovly_map, ovly_sections, info);
                if (base == (unsigned) -1) goto file_err;
                if (fprintf(script, "  }\n") <= 0) goto file_err;
                ovlynum += htab->params->num_lines;
                while (base < count && ovly_map[base] < ovlynum) base++;
            }
            if (fprintf(script, " }\n") <= 0) goto file_err;
        }
        if (fprintf(script, "}\nINSERT BEFORE .text;\n") <= 0) goto file_err;
    }

    free(ovly_map);
    free(ovly_sections);

    if (fclose(script) != 0) goto file_err;

    if (htab->params->auto_overlay & AUTO_RELINK) (*htab->params->spu_elf_relink)();
    xexit(0);

file_err:
    bfd_set_error(bfd_error_system_call);
err_exit:
    info->callbacks->fatal(_("%P: auto overlay error: %E\n"));
}

/* Provide an estimate of total stack required.  */

bool spu_elf_stack_analysis(struct bfd_link_info *info) {
    struct _sum_stack_param sum_stack_param = { 0 };
    struct spu_link_hash_table *htab = spu_hash_table(info);

    if (!discover_functions(info) || !build_call_tree(info)) {
        return false;
    }

    if (htab->params->stack_analysis) {
        info->callbacks->info("Stack size for call graph root nodes.\n");
        info->callbacks->minfo("\nStack size for functions.  Annotations: '*' max stack, 't' tail call\n");
    }
    
    sum_stack_param.emit_stack_syms = htab->params->emit_stack_syms;

    if (!for_each_node(sum_stack, info, &sum_stack_param, true)) {
        return false;
    }

    if (htab->params->stack_analysis) {
        info->callbacks->info("Maximum stack required is 0x%v\n", (bfd_vma)sum_stack_param.overall_stack);
    }

    return true;
}

/* Perform a final link.  */

static bool spu_elf_final_link(bfd *output_bfd, struct bfd_link_info *info) {
    struct spu_link_hash_table *htab = spu_hash_table(info);

    if (htab->params->auto_overlay) {
        spu_elf_auto_overlay(info);
    }

    bool need_stack_analysis = htab->params->stack_analysis || 
                               (htab->params->ovly_flavour == ovly_soft_icache && 
                                htab->params->lrlive_analysis);

    if (need_stack_analysis && !spu_elf_stack_analysis(info)) {
        info->callbacks->einfo(_("%X%P: stack/lrlive analysis error: %E\n"));
    } else if (!spu_elf_build_stubs(info)) {
        info->callbacks->fatal(_("%P: can not build overlay stubs: %E\n"));
        return false;
    }

    return bfd_elf_final_link(output_bfd, info);
}

/* Called when not normally emitting relocs, ie. !bfd_link_relocatable (info)
   and !info->emitrelocations.  Returns a count of special relocs
   that need to be emitted.  */

#include <stdbool.h>

static unsigned int spu_elf_count_relocs(struct bfd_link_info *info, asection *sec) {
    Elf_Internal_Rela *relocs = _bfd_elf_link_read_relocs(sec->owner, sec, NULL, NULL, info->keep_memory);
    unsigned int count = 0;

    if (!relocs) {
        return count;
    }

    Elf_Internal_Rela *relend = relocs + sec->reloc_count;
    for (Elf_Internal_Rela *rel = relocs; rel < relend; rel++) {
        int r_type = ELF32_R_TYPE(rel->r_info);
        if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64) {
            ++count;
        }
    }

    if (elf_section_data(sec)->relocs != relocs) {
        free(relocs);
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
static void spu_elf_emit_fixup(bfd *output_bfd, struct bfd_link_info *info, bfd_vma offset) {
    struct spu_link_hash_table *htab = spu_hash_table(info);
    asection *sfixup = htab->sfixup;
    bfd_vma qaddr = offset & ~(bfd_vma)15;
    bfd_vma bit = ((bfd_vma)8) >> ((offset & 15) >> 2);
    
    if (sfixup->reloc_count == 0) {
        FIXUP_PUT(output_bfd, htab, 0, qaddr | bit);
        sfixup->reloc_count++;
        return;
    }

    bfd_vma base = FIXUP_GET(output_bfd, htab, sfixup->reloc_count - 1);
    if (qaddr != (base & ~(bfd_vma)15)) {
        if ((sfixup->reloc_count + 1) * FIXUP_RECORD_SIZE > sfixup->size) {
            _bfd_error_handler(_("fatal error while creating .fixup"));
            return;
        }
        FIXUP_PUT(output_bfd, htab, sfixup->reloc_count, qaddr | bit);
        sfixup->reloc_count++;
    } else {
        FIXUP_PUT(output_bfd, htab, sfixup->reloc_count - 1, base | bit);
    }
}

/* Apply RELOCS to CONTENTS of INPUT_SECTION from INPUT_BFD.  */

static int spu_elf_relocate_section (bfd *output_bfd,
                                     struct bfd_link_info *info,
                                     bfd *input_bfd,
                                     asection *input_section,
                                     bfd_byte *contents,
                                     Elf_Internal_Rela *relocs,
                                     Elf_Internal_Sym *local_syms,
                                     asection **local_sections)
{
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
    struct elf_link_hash_entry **sym_hashes = (struct elf_link_hash_entry **) (elf_sym_hashes(input_bfd));
    struct spu_link_hash_table *htab = spu_hash_table(info);
    asection *ea = bfd_get_section_by_name(output_bfd, "._ea");

    bool stubs = (htab->stub_sec != NULL && maybe_needs_stubs(input_section));
    unsigned int iovl = overlay_index(input_section);
    bool emit_these_relocs = false;
    bool ret = true;
  
    for (Elf_Internal_Rela *rel = relocs, *relend = relocs + input_section->reloc_count; rel < relend; ++rel) {
        unsigned int r_symndx = ELF32_R_SYM(rel->r_info);
        int r_type = ELF32_R_TYPE(rel->r_info);
        reloc_howto_type *howto = elf_howto_table + r_type;
        asection *sec = NULL;
        struct elf_link_hash_entry *h = NULL;
        const char *sym_name = NULL;
        bfd_vma relocation = 0;
        bfd_vma addend = rel->r_addend;
        bool unresolved_reloc = false;
        bool is_ea_sym = false;

        if (r_symndx < symtab_hdr->sh_info) {
            Elf_Internal_Sym *sym = local_syms + r_symndx;
            sec = local_sections[r_symndx];
            sym_name = bfd_elf_sym_name(input_bfd, symtab_hdr, sym, sec);
            relocation = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);
        } else {
            if (!sym_hashes) return false;
            h = sym_hashes[r_symndx - symtab_hdr->sh_info];

            if (info->wrap_hash && (input_section->flags & SEC_DEBUGGING)) {
                h = (struct elf_link_hash_entry *)unwrap_hash_lookup(info, input_bfd, &h->root);
            }

            while (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning) {
                h = (struct elf_link_hash_entry *)h->root.u.i.link;
            }

            if (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) {
                sec = h->root.u.def.section;
                if (sec && sec->output_section) {
                    relocation = h->root.u.def.value + sec->output_section->vma + sec->output_offset;
                } else {
                    unresolved_reloc = true;
                }
            } else if (h->root.type == bfd_link_hash_undefweak) {
                // Do nothing
            } else if (!(info->unresolved_syms_in_objects == RM_IGNORE && ELF_ST_VISIBILITY(h->other) == STV_DEFAULT)) {
                if(!bfd_link_relocatable(info) && r_type != R_SPU_PPU32 && r_type != R_SPU_PPU64) {
                    info->callbacks->undefined_symbol(info, h->root.root.string, input_bfd, input_section, rel->r_offset, 
                        (info->unresolved_syms_in_objects == RM_DIAGNOSE && !info->warn_unresolved_syms) || 
                        ELF_ST_VISIBILITY(h->other) != STV_DEFAULT);
                }
            }
            sym_name = h->root.root.string;
        }
      
        if (sec && discarded_section(sec)) {
            RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section, rel, 1, relend, R_SPU_NONE, howto, 0, contents);
        }

        if (bfd_link_relocatable(info)) continue;

        if (r_type == R_SPU_ADD_PIC && h && !(h->def_regular || ELF_COMMON_DEF_P(h))) {
            bfd_byte *loc = contents + rel->r_offset;
            loc[0] = 0x1c;
            loc[1] = 0x00;
            loc[2] &= 0x3f;
        }

        is_ea_sym = (ea && sec && sec->output_section == ea);

        if (stubs && !is_ea_sym) {
            enum _stub_type stub_type = needs_ovl_stub(h, local_syms + r_symndx, sec, input_section, rel, contents, info);
            if (stub_type != no_stub) {
                unsigned int ovl = (stub_type != nonovl_stub) ? iovl : 0;
                struct got_entry **head = (h) ? &h->got.glist : elf_local_got_ents(input_bfd) + r_symndx;
                struct got_entry *g = *head;
                while (g) {
                    if ((htab->params->ovly_flavour == ovly_soft_icache && g->ovl == ovl && 
                        g->br_addr == (rel->r_offset + input_section->output_offset + input_section->output_section->vma)) ||
                        (g->addend == addend && (g->ovl == ovl || g->ovl == 0))) {
                        break;
                    }
                    g = g->next;
                }
                if (!g) abort();
                relocation = g->stub_addr;
                addend = 0;
            }
        } else if (htab->params->ovly_flavour == ovly_soft_icache && (r_type == R_SPU_ADDR16_HI || 
                  r_type == R_SPU_ADDR32 || r_type == R_SPU_REL32) && !is_ea_sym) {
            unsigned int ovl = overlay_index(sec);
            if (ovl) {
                unsigned int set_id = ((ovl - 1) >> htab->num_lines_log2) + 1;
                relocation += set_id << 18;
            }
        }

        if (htab->params->emit_fixups && !bfd_link_relocatable(info) && (input_section->flags & SEC_ALLOC) && r_type == R_SPU_ADDR32) {
            bfd_vma offset = rel->r_offset + input_section->output_section->vma + input_section->output_offset;
            spu_elf_emit_fixup(output_bfd, info, offset);
        }

        if (unresolved_reloc) {
            // Do nothing
        } else if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64) {
            if (is_ea_sym) {
                rel->r_addend += (relocation - ea->vma + elf_section_data(ea)->this_hdr.sh_offset);
                rel->r_info = ELF32_R_INFO(0, r_type);
            }
            emit_these_relocs = true;
            continue;
        } else if (is_ea_sym) {
            unresolved_reloc = true;
        }

        if (unresolved_reloc && _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset) != (bfd_vma)-1) {
            _bfd_error_handler(_("%pB(%s+%#" PRIx64 "): unresolvable %s relocation against symbol `%s'"),
                               input_bfd, bfd_section_name(input_section), (uint64_t)rel->r_offset, howto->name, sym_name);
            ret = false;
        }

        bfd_reloc_status_type r = _bfd_final_link_relocate(howto, input_bfd, input_section, contents, rel->r_offset, relocation, addend);

        if (r != bfd_reloc_ok) {
            const char *msg = NULL;
            switch (r) {
                case bfd_reloc_overflow:
                    info->callbacks->reloc_overflow(info, h ? &h->root : NULL, sym_name, howto->name, 
                                                    0, input_bfd, input_section, rel->r_offset);
                    break;
                case bfd_reloc_undefined:
                    info->callbacks->undefined_symbol(info, sym_name, input_bfd, input_section, rel->r_offset, true);
                    break;
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
            }
            if (msg) {
                ret = false;
                info->callbacks->warning(info, msg, sym_name, input_bfd, input_section, rel->r_offset);
            }
        }
    }

    if (ret && emit_these_relocs && !info->emitrelocations) {
        Elf_Internal_Rela *wrel = relocs;
        for (Elf_Internal_Rela *rel = relocs, *relend = relocs + input_section->reloc_count; rel < relend; ++rel) {
            if (ELF32_R_TYPE(rel->r_info) == R_SPU_PPU32 || ELF32_R_TYPE(rel->r_info) == R_SPU_PPU64) {
                *wrel++ = *rel;
            }
        }
        input_section->reloc_count = wrel - relocs;
        Elf_Internal_Shdr *rel_hdr = _bfd_elf_single_rel_hdr(input_section);
        rel_hdr->sh_size = input_section->reloc_count * rel_hdr->sh_entsize;
        ret = 2;
    }

    return ret;
}

static bool spu_elf_finish_dynamic_sections(void)
{
    return true;
}

/* Adjust _SPUEAR_ syms to point at their overlay stubs.  */

static int spu_elf_output_symbol_hook(struct bfd_link_info *info, const char *sym_name, Elf_Internal_Sym *sym, asection *sym_sec, struct elf_link_hash_entry *h) {
    struct spu_link_hash_table *htab = spu_hash_table(info);
    if (!bfd_link_relocatable(info) && htab->stub_sec != NULL && h != NULL && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) && h->def_regular && startswith(h->root.root.string, "_SPUEAR_")) {
        struct got_entry *g = h->got.glist;
        while (g != NULL) {
            int is_match = (htab->params->ovly_flavour == ovly_soft_icache) ? (g->br_addr == g->stub_addr) : (g->addend == 0 && g->ovl == 0);
            if (is_match) {
                sym->st_shndx = (_bfd_elf_section_from_bfd_section(htab->stub_sec[0]->output_section->owner, htab->stub_sec[0]->output_section));
                sym->st_value = g->stub_addr;
                break;
            }
            g = g->next;
        }
    }
    return 1;
}

static int spu_plugin = 0;

void set_spu_plugin(int value) {
    spu_plugin = value;
}

/* Set ELF header e_type for plugins.  */

bool spu_elf_init_file_header(bfd *abfd, struct bfd_link_info *info) {
    if (!_bfd_elf_init_file_header(abfd, info)) {
        return false;
    }

    if (spu_plugin) {
        elf_elfheader(abfd)->e_type = ET_DYN;
    }
    
    return true;
}

/* We may add an extra PT_LOAD segment for .toe.  We also need extra
   segments for overlays.  */

int spu_elf_additional_program_headers(bfd *abfd, struct bfd_link_info *info) {
    int extra = 0;

    if (info) {
        struct spu_link_hash_table *htab = spu_hash_table(info);
        if (htab) {
            extra = htab->num_overlays;
        }
    }

    asection *sec = bfd_get_section_by_name(abfd, ".toe");
    if (sec && (sec->flags & SEC_LOAD)) {
        extra++;
    }

    return extra;
}

/* Remove .toe section from other PT_LOAD segments and put it in
   a segment of its own.  Put overlays in separate segments too.  */

bool spu_elf_modify_segment_map(bfd *abfd, struct bfd_link_info *info) {
    if (!info) return true;

    asection *toe = bfd_get_section_by_name(abfd, ".toe");
    struct elf_segment_map *map = elf_seg_map(abfd), *overlay_map = NULL;
    struct elf_segment_map **seg_map_ptr = &map, **overlay_ptr = &overlay_map, **first_load = NULL;
    
    // Modify segments containing .toe or overlays
    while (map) {
        if (map->p_type == PT_LOAD && map->count > 1) {
            for (unsigned int i = 0; i < map->count; ++i) {
                asection *sec = map->sections[i];
                if (sec == toe || spu_elf_section_data(sec)->u.o.ovl_index != 0) {
                    if (i + 1 < map->count) {
                        struct elf_segment_map *new_map = bfd_zalloc(abfd, sizeof(struct elf_segment_map) +
                                                                     (map->count - (i + 2)) * sizeof(map->sections[0]));
                        if (!new_map) return false;
                        new_map->count = map->count - (i + 1);
                        memcpy(new_map->sections, map->sections + i + 1, new_map->count * sizeof(map->sections[0]));
                        new_map->p_type = PT_LOAD;
                        new_map->next = map->next;
                        map->next = new_map;
                    }
                    map->count = 1;
                    if (i != 0) {
                        map->count = i;
                        struct elf_segment_map *new_map = bfd_zalloc(abfd, sizeof(struct elf_segment_map));
                        if (!new_map) return false;
                        new_map->p_type = PT_LOAD;
                        new_map->count = 1;
                        new_map->sections[0] = sec;
                        new_map->next = map->next;
                        map->next = new_map;
                    }
                    break;
                }
            }
        }
        map = map->next;
    }

    // Separate overlay segments
    while (*seg_map_ptr) {
        if ((*seg_map_ptr)->p_type == PT_LOAD) {
            if (!first_load) first_load = seg_map_ptr;
            if ((*seg_map_ptr)->count == 1 && spu_elf_section_data((*seg_map_ptr)->sections[0])->u.o.ovl_index != 0) {
                struct elf_segment_map *current = *seg_map_ptr;
                current->no_sort_lma = 1;
                *seg_map_ptr = current->next;
                *overlay_ptr = current;
                overlay_ptr = &current->next;
                continue;
            }
        }
        seg_map_ptr = &((*seg_map_ptr)->next);
    }

    // Re-insert overlay segments at head
    if (overlay_map) {
        seg_map_ptr = first_load;
        if (*seg_map_ptr && (*seg_map_ptr)->p_type == PT_LOAD && (*seg_map_ptr)->includes_filehdr) {
            seg_map_ptr = &(*seg_map_ptr)->next;
        }
        *overlay_ptr = *seg_map_ptr;
        *seg_map_ptr = overlay_map;
    }

    return true;
}

/* Tweak the section type of .note.spu_name.  */

static bool spu_elf_fake_sections(bfd *obfd, Elf_Internal_Shdr *hdr, asection *sec) {
    if (sec == NULL || hdr == NULL) {
        return false;
    }
    if (strcmp(sec->name, SPU_PTNOTE_SPUNAME) == 0) {
        hdr->sh_type = SHT_NOTE;
    }
    return true;
}

/* Tweak phdrs before writing them out.  */

bool spu_elf_modify_headers(bfd *abfd, struct bfd_link_info *info) {
    if (info == NULL) 
        return _bfd_elf_modify_headers(abfd, info);

    const struct elf_backend_data *bed = get_elf_backend_data(abfd);
    struct elf_obj_tdata *tdata = elf_tdata(abfd);
    Elf_Internal_Phdr *phdr = tdata->phdr;
    unsigned int count = elf_program_header_size(abfd) / bed->s->sizeof_phdr;
    struct spu_link_hash_table *htab = spu_hash_table(info);

    if (htab->num_overlays != 0) {
        struct elf_segment_map *m;
        unsigned int i, o;

        for (i = 0, m = elf_seg_map(abfd); m; ++i, m = m->next) {
            if (m->count != 0) {
                o = spu_elf_section_data(m->sections[0])->u.o.ovl_index;
                if (o != 0) {
                    phdr[i].p_flags |= PF_OVERLAY;
                    if (htab->ovtab && htab->ovtab->size != 0 && htab->params->ovly_flavour != ovly_soft_icache) {
                        bfd_byte *p = htab->ovtab->contents;
                        unsigned int off = o * 16 + 8;
                        bfd_put_32(htab->ovtab->owner, phdr[i].p_offset, p + off);
                    }
                }
            }
        }

        if (htab->init != NULL && htab->init->size != 0) {
            bfd_vma val = elf_section_data(htab->ovl_sec[0])->this_hdr.sh_offset;
            bfd_put_32(htab->init->owner, val, htab->init->contents + 4);
        }
    }

    Elf_Internal_Phdr *last = NULL;
    for (int i = count - 1; i >= 0; --i) {
        if (phdr[i].p_type == PT_LOAD) {
            unsigned adjust = ((16 - (phdr[i].p_filesz % 16)) % 16);
            if (adjust != 0 && last != NULL && phdr[i].p_offset + phdr[i].p_filesz > last->p_offset - adjust)
                break;

            adjust = ((16 - (phdr[i].p_memsz % 16)) % 16);
            if (adjust != 0 && last != NULL && phdr[i].p_filesz != 0
                && phdr[i].p_vaddr + phdr[i].p_memsz > last->p_vaddr - adjust
                && phdr[i].p_vaddr + phdr[i].p_memsz <= last->p_vaddr)
                break;

            if (phdr[i].p_filesz != 0)
                last = &phdr[i];
        }
    }

    for (unsigned int i = count; i-- != 0;) {
        if (phdr[i].p_type == PT_LOAD) {
            unsigned adjust = ((16 - (phdr[i].p_filesz % 16)) % 16);
            phdr[i].p_filesz += adjust;

            adjust = ((16 - (phdr[i].p_memsz % 16)) % 16);
            phdr[i].p_memsz += adjust;
        }
    }

    return _bfd_elf_modify_headers(abfd, info);
}

bool spu_elf_size_sections(bfd *obfd ATTRIBUTE_UNUSED, struct bfd_link_info *info) {
    struct spu_link_hash_table *htab = spu_hash_table(info);
    if (!htab->params->emit_fixups) {
        return true;
    }

    asection *sfixup = htab->sfixup;
    int fixup_count = 0;
    bfd *ibfd;

    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
        if (bfd_get_flavour(ibfd) != bfd_target_elf_flavour) {
            continue;
        }

        asection *isec;
        for (isec = ibfd->sections; isec != NULL; isec = isec->next) {
            if ((isec->flags & (SEC_ALLOC | SEC_RELOC)) != (SEC_ALLOC | SEC_RELOC) || isec->reloc_count == 0) {
                continue;
            }

            Elf_Internal_Rela *internal_relocs = _bfd_elf_link_read_relocs(ibfd, isec, NULL, NULL, info->keep_memory);
            if (internal_relocs == NULL) {
                return false;
            }

            bfd_vma base_end = 0;
            for (Elf_Internal_Rela *irela = internal_relocs, *irelaend = irela + isec->reloc_count; irela < irelaend; irela++) {
                if (ELF32_R_TYPE(irela->r_info) == R_SPU_ADDR32 && irela->r_offset >= base_end) {
                    base_end = (irela->r_offset & ~(bfd_vma)15) + 16;
                    fixup_count++;
                }
            }
        }
    }

    size_t size = (fixup_count + 1) * FIXUP_RECORD_SIZE;
    if (!bfd_set_section_size(sfixup, size)) {
        return false;
    }

    sfixup->contents = (bfd_byte *)bfd_zalloc(info->input_bfds, size);
    return sfixup->contents != NULL;
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
