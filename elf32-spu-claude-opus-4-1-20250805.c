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
    { BFD_RELOC_NONE, R_SPU_NONE },
    { BFD_RELOC_SPU_IMM10W, R_SPU_ADDR10 },
    { BFD_RELOC_SPU_IMM16W, R_SPU_ADDR16 },
    { BFD_RELOC_SPU_LO16, R_SPU_ADDR16_LO },
    { BFD_RELOC_SPU_HI16, R_SPU_ADDR16_HI },
    { BFD_RELOC_SPU_IMM18, R_SPU_ADDR18 },
    { BFD_RELOC_SPU_PCREL16, R_SPU_REL16 },
    { BFD_RELOC_SPU_IMM7, R_SPU_ADDR7 },
    { BFD_RELOC_SPU_IMM8, R_SPU_NONE },
    { BFD_RELOC_SPU_PCREL9a, R_SPU_REL9 },
    { BFD_RELOC_SPU_PCREL9b, R_SPU_REL9I },
    { BFD_RELOC_SPU_IMM10, R_SPU_ADDR10I },
    { BFD_RELOC_SPU_IMM16, R_SPU_ADDR16I },
    { BFD_RELOC_32, R_SPU_ADDR32 },
    { BFD_RELOC_32_PCREL, R_SPU_REL32 },
    { BFD_RELOC_SPU_PPU32, R_SPU_PPU32 },
    { BFD_RELOC_SPU_PPU64, R_SPU_PPU64 },
    { BFD_RELOC_SPU_ADD_PIC, R_SPU_ADD_PIC }
  };

  size_t i;
  for (i = 0; i < sizeof(reloc_map) / sizeof(reloc_map[0]); i++)
    {
      if (reloc_map[i].bfd_code == code)
        return reloc_map[i].spu_type;
    }

  return (enum elf_spu_reloc_type) -1;
}

static bool
spu_elf_info_to_howto (bfd *abfd,
		       arelent *cache_ptr,
		       Elf_Internal_Rela *dst)
{
  if (abfd == NULL || cache_ptr == NULL || dst == NULL)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }

  unsigned int r_type = ELF32_R_TYPE (dst->r_info);
  
  if (r_type >= R_SPU_max)
    {
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }
  
  cache_ptr->howto = &elf_howto_table[r_type];
  return true;
}

static reloc_howto_type *
spu_elf_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			   bfd_reloc_code_real_type code)
{
  enum elf_spu_reloc_type r_type = spu_elf_bfd_to_reloc_type (code);

  if (r_type == (enum elf_spu_reloc_type) -1)
    return NULL;

  return &elf_howto_table[r_type];
}

static reloc_howto_type *
spu_elf_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			   const char *r_name)
{
  if (r_name == NULL)
    return NULL;

  size_t table_size = sizeof (elf_howto_table) / sizeof (elf_howto_table[0]);
  
  for (size_t i = 0; i < table_size; i++)
    {
      if (elf_howto_table[i].name == NULL)
        continue;
        
      if (strcasecmp (elf_howto_table[i].name, r_name) == 0)
        return &elf_howto_table[i];
    }

  return NULL;
}

/* Apply R_SPU_REL9 and R_SPU_REL9I relocs.  */

static bfd_reloc_status_type
spu_elf_rel9 (bfd *abfd, arelent *reloc_entry, asymbol *symbol,
	      void *data, asection *input_section,
	      bfd *output_bfd, char **error_message)
{
  bfd_size_type octets;
  bfd_vma val;
  long insn;

  if (output_bfd != NULL)
    return bfd_elf_generic_reloc (abfd, reloc_entry, symbol, data,
				  input_section, output_bfd, error_message);

  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;
    
  octets = reloc_entry->address * OCTETS_PER_BYTE (abfd, input_section);

  val = 0;
  if (!bfd_is_com_section (symbol->section))
    val = symbol->value;
    
  if (symbol->section->output_section)
    val += symbol->section->output_section->vma;

  val += reloc_entry->addend;

  if (input_section->output_section == NULL)
    return bfd_reloc_undefined;
    
  val -= input_section->output_section->vma + input_section->output_offset;

  val >>= 2;
  if (val + 256 >= 512)
    return bfd_reloc_overflow;

  insn = bfd_get_32 (abfd, (bfd_byte *) data + octets);

  val = (val & 0x7f) | ((val & 0x180) << 7) | ((val & 0x180) << 16);
  insn &= ~reloc_entry->howto->dst_mask;
  insn |= val & reloc_entry->howto->dst_mask;
  bfd_put_32 (abfd, insn, (bfd_byte *) data + octets);
  
  return bfd_reloc_ok;
}

static bool
spu_elf_new_section_hook (bfd *abfd, asection *sec)
{
  if (abfd == NULL || sec == NULL)
    return false;

  struct _spu_elf_section_data *sdata = bfd_zalloc (abfd, sizeof (*sdata));
  if (sdata == NULL)
    return false;
  
  sec->used_by_bfd = sdata;

  return _bfd_elf_new_section_hook (abfd, sec);
}

/* Set up overlay info for executables.  */

static bool
spu_elf_object_p (bfd *abfd)
{
  if ((abfd->flags & (EXEC_P | DYNAMIC)) == 0)
    return true;

  Elf_Internal_Ehdr *ehdr = elf_elfheader (abfd);
  if (ehdr == NULL)
    return false;

  Elf_Internal_Phdr *phdr = elf_tdata (abfd)->phdr;
  if (phdr == NULL)
    return false;

  unsigned int num_buf = 0;
  unsigned int num_ovl = 0;
  Elf_Internal_Phdr *last_phdr = NULL;

  for (unsigned int i = 0; i < ehdr->e_phnum; i++, phdr++)
    {
      if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_OVERLAY) == 0)
        continue;

      ++num_ovl;
      
      if (last_phdr == NULL || ((last_phdr->p_vaddr ^ phdr->p_vaddr) & 0x3ffff) != 0)
        ++num_buf;
      
      last_phdr = phdr;

      for (unsigned int j = 1; j < elf_numsections (abfd); j++)
        {
          Elf_Internal_Shdr *shdr = elf_elfsections (abfd)[j];
          if (shdr == NULL)
            continue;

          if (shdr->bfd_section == NULL)
            continue;

          if (ELF_SECTION_SIZE (shdr, phdr) == 0)
            continue;

          if (!ELF_SECTION_IN_SEGMENT (shdr, phdr))
            continue;

          asection *sec = shdr->bfd_section;
          if (sec == NULL)
            continue;

          spu_elf_section_data (sec)->u.o.ovl_index = num_ovl;
          spu_elf_section_data (sec)->u.o.ovl_buf = num_buf;
        }
    }

  return true;
}

/* Specially mark defined symbols named _EAR_* with BSF_KEEP so that
   strip --strip-unneeded will not remove them.  */

static void
spu_elf_backend_symbol_processing (bfd *abfd ATTRIBUTE_UNUSED, asymbol *sym)
{
  if (sym == NULL || sym->name == NULL || sym->section == NULL) {
    return;
  }
  
  if (sym->section != bfd_abs_section_ptr && startswith (sym->name, "_EAR_")) {
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

  return &htab->elf.root;
}

void
spu_elf_setup (struct bfd_link_info *info, struct spu_elf_params *params)
{
  struct spu_link_hash_table *htab;
  bfd_vma max_branch_log2;
  
  if (info == NULL || params == NULL) {
    return;
  }
  
  htab = spu_hash_table (info);
  if (htab == NULL) {
    return;
  }
  
  htab->params = params;
  
  if (params->line_size > 0) {
    htab->line_size_log2 = bfd_log2 (params->line_size);
  }
  
  if (params->num_lines > 0) {
    htab->num_lines_log2 = bfd_log2 (params->num_lines);
  }
  
  if (params->max_branch > 0) {
    max_branch_log2 = bfd_log2 (params->max_branch);
    htab->fromelem_size_log2 = (max_branch_log2 > 4) ? (max_branch_log2 - 4) : 0;
  }
}

/* Find the symbol for the given R_SYMNDX in IBFD and set *HP and *SYMP
   to (hash, NULL) for global symbols, and (NULL, sym) for locals.  Set
   *SYMSECP to the symbol's section.  *LOCSYMSP caches local syms.  */

static bool
get_sym_h (struct elf_link_hash_entry **hp,
	   Elf_Internal_Sym **symp,
	   asection **symsecp,
	   Elf_Internal_Sym **locsymsp,
	   unsigned long r_symndx,
	   bfd *ibfd)
{
  if (ibfd == NULL || locsymsp == NULL)
    return false;

  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
  
  if (r_symndx >= symtab_hdr->sh_info)
    return handle_global_symbol(hp, symp, symsecp, r_symndx, ibfd, symtab_hdr);
  
  return handle_local_symbol(hp, symp, symsecp, locsymsp, r_symndx, ibfd, symtab_hdr);
}

static bool
handle_global_symbol(struct elf_link_hash_entry **hp,
                     Elf_Internal_Sym **symp,
                     asection **symsecp,
                     unsigned long r_symndx,
                     bfd *ibfd,
                     Elf_Internal_Shdr *symtab_hdr)
{
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (ibfd);
  if (sym_hashes == NULL)
    return false;
    
  struct elf_link_hash_entry *h = sym_hashes[r_symndx - symtab_hdr->sh_info];
  if (h == NULL)
    return false;
    
  h = resolve_indirect_symbol(h);
  
  if (hp != NULL)
    *hp = h;
    
  if (symp != NULL)
    *symp = NULL;
    
  if (symsecp != NULL)
    *symsecp = get_symbol_section(h);
    
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
  Elf_Internal_Sym *locsyms = *locsymsp;
  
  if (locsyms == NULL)
  {
    locsyms = load_local_symbols(ibfd, symtab_hdr);
    if (locsyms == NULL)
      return false;
    *locsymsp = locsyms;
  }
  
  Elf_Internal_Sym *sym = locsyms + r_symndx;
  
  if (hp != NULL)
    *hp = NULL;
    
  if (symp != NULL)
    *symp = sym;
    
  if (symsecp != NULL)
    *symsecp = bfd_section_from_elf_index (ibfd, sym->st_shndx);
    
  return true;
}

static struct elf_link_hash_entry *
resolve_indirect_symbol(struct elf_link_hash_entry *h)
{
  while (h != NULL && (h->root.type == bfd_link_hash_indirect ||
                       h->root.type == bfd_link_hash_warning))
  {
    h = (struct elf_link_hash_entry *) h->root.u.i.link;
  }
  return h;
}

static asection *
get_symbol_section(struct elf_link_hash_entry *h)
{
  if (h == NULL)
    return NULL;
    
  if (h->root.type == bfd_link_hash_defined ||
      h->root.type == bfd_link_hash_defweak)
    return h->root.u.def.section;
    
  return NULL;
}

static Elf_Internal_Sym *
load_local_symbols(bfd *ibfd, Elf_Internal_Shdr *symtab_hdr)
{
  Elf_Internal_Sym *locsyms = (Elf_Internal_Sym *) symtab_hdr->contents;
  
  if (locsyms == NULL)
  {
    locsyms = bfd_elf_get_elf_syms (ibfd, symtab_hdr,
                                    symtab_hdr->sh_info,
                                    0, NULL, NULL, NULL);
  }
  
  return locsyms;
}

/* Create the note section if not already present.  This is done early so
   that the linker maps the sections to the right place in the output.  */

bool
spu_elf_create_sections (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    if (bfd_get_section_by_name (ibfd, SPU_PTNOTE_SPUNAME) != NULL)
      break;

  if (ibfd == NULL)
    {
      if (!create_spuname_section(info))
        return false;
    }

  if (htab->params->emit_fixups)
    {
      if (!create_fixup_section(htab, info))
        return false;
    }

  return true;
}

static bool
create_spuname_section(struct bfd_link_info *info)
{
  asection *s;
  size_t name_len;
  size_t size;
  bfd_byte *data;
  flagword flags;
  bfd *ibfd = info->input_bfds;
  const char *output_filename;

  if (ibfd == NULL)
    return false;

  flags = SEC_LOAD | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
  s = bfd_make_section_anyway_with_flags (ibfd, SPU_PTNOTE_SPUNAME, flags);
  if (s == NULL)
    return false;

  if (!bfd_set_section_alignment (s, 4))
    return false;

  elf_section_type (s) = SHT_NOTE;

  output_filename = bfd_get_filename (info->output_bfd);
  if (output_filename == NULL)
    return false;

  name_len = strlen (output_filename) + 1;
  size = calculate_section_size(name_len);

  if (!bfd_set_section_size (s, size))
    return false;

  data = bfd_zalloc (ibfd, size);
  if (data == NULL)
    return false;

  populate_section_data(ibfd, data, name_len, output_filename);
  s->contents = data;
  s->alloced = 1;

  return true;
}

static size_t
calculate_section_size(size_t name_len)
{
  size_t plugin_size = (sizeof (SPU_PLUGIN_NAME) + 3) & ~3;
  size_t aligned_name_len = (name_len + 3) & ~3;
  return 12 + plugin_size + aligned_name_len;
}

static void
populate_section_data(bfd *ibfd, bfd_byte *data, size_t name_len, const char *filename)
{
  size_t plugin_size = (sizeof (SPU_PLUGIN_NAME) + 3) & ~3;
  
  bfd_put_32 (ibfd, sizeof (SPU_PLUGIN_NAME), data + 0);
  bfd_put_32 (ibfd, name_len, data + 4);
  bfd_put_32 (ibfd, 1, data + 8);
  memcpy (data + 12, SPU_PLUGIN_NAME, sizeof (SPU_PLUGIN_NAME));
  memcpy (data + 12 + plugin_size, filename, name_len);
}

static bool
create_fixup_section(struct spu_link_hash_table *htab, struct bfd_link_info *info)
{
  asection *s;
  flagword flags;
  bfd *ibfd;

  if (htab->elf.dynobj == NULL)
    {
      if (info->input_bfds == NULL)
        return false;
      htab->elf.dynobj = info->input_bfds;
    }

  ibfd = htab->elf.dynobj;
  flags = (SEC_LOAD | SEC_ALLOC | SEC_READONLY | SEC_HAS_CONTENTS
           | SEC_IN_MEMORY | SEC_LINKER_CREATED);
  
  s = bfd_make_section_anyway_with_flags (ibfd, ".fixup", flags);
  if (s == NULL)
    return false;

  if (!bfd_set_section_alignment (s, 2))
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
  
  if ((*s1)->vma < (*s2)->vma)
    return -1;
  
  if ((*s1)->vma > (*s2)->vma)
    return 1;

  if ((*s1)->index < (*s2)->index)
    return -1;
  
  if ((*s1)->index > (*s2)->index)
    return 1;
  
  return 0;
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

  n = 0;
  for (s = info->output_bfd->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_ALLOC) != 0
          && (s->flags & (SEC_LOAD | SEC_THREAD_LOCAL)) != SEC_THREAD_LOCAL
          && s->size != 0)
        alloc_sec[n++] = s;
    }

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
      if (!process_regular_overlays(info, htab, alloc_sec, n, &ovl_index, &num_buf, &ovl_end))
        return 0;
    }

  htab->num_overlays = ovl_index;
  htab->num_buf = num_buf;
  htab->ovl_sec = alloc_sec;

  if (ovl_index == 0)
    return 1;

  for (i = 0; i < 2; i++)
    {
      if (!setup_overlay_entry(htab, entry_names[i][htab->params->ovly_flavour], i))
        return 0;
    }

  return 2;
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
  unsigned int prev_buf = 0, set_id = 0;
  bfd_vma vma_start = 0;
  asection *s;

  for (i = 1; i < n; i++)
    {
      s = alloc_sec[i];
      if (s->vma < *ovl_end)
        {
          asection *s0 = alloc_sec[i - 1];
          vma_start = s0->vma;
          *ovl_end = s0->vma + ((bfd_vma) 1 << (htab->num_lines_log2 + htab->line_size_log2));
          --i;
          break;
        }
      *ovl_end = s->vma + s->size;
    }

  *ovl_index = 0;
  *num_buf = 0;
  
  for (; i < n; i++)
    {
      s = alloc_sec[i];
      if (s->vma >= *ovl_end)
        break;

      if (startswith (s->name, ".ovl.init"))
        continue;

      *num_buf = ((s->vma - vma_start) >> htab->line_size_log2) + 1;
      set_id = (*num_buf == prev_buf) ? set_id + 1 : 0;
      prev_buf = *num_buf;

      if (!validate_icache_section(info, htab, s, vma_start))
        return 0;

      alloc_sec[(*ovl_index)++] = s;
      spu_elf_section_data (s)->u.o.ovl_index = (set_id << htab->num_lines_log2) + *num_buf;
      spu_elf_section_data (s)->u.o.ovl_buf = *num_buf;
    }

  for (; i < n; i++)
    {
      s = alloc_sec[i];
      if (s->vma < *ovl_end)
        {
          info->callbacks->einfo (_("%X%P: overlay section %pA is not in cache area\n"),
                                  alloc_sec[i-1]);
          bfd_set_error (bfd_error_bad_value);
          return 0;
        }
      *ovl_end = s->vma + s->size;
    }

  return 1;
}

static int
validate_icache_section(struct bfd_link_info *info,
                        struct spu_link_hash_table *htab,
                        asection *s,
                        bfd_vma vma_start)
{
  if ((s->vma - vma_start) & (htab->params->line_size - 1))
    {
      info->callbacks->einfo (_("%X%P: overlay section %pA does not start on a cache line\n"), s);
      bfd_set_error (bfd_error_bad_value);
      return 0;
    }
  
  if (s->size > htab->params->line_size)
    {
      info->callbacks->einfo (_("%X%P: overlay section %pA is larger than a cache line\n"), s);
      bfd_set_error (bfd_error_bad_value);
      return 0;
    }
  
  return 1;
}

static int
process_regular_overlays(struct bfd_link_info *info,
                         struct spu_link_hash_table *htab,
                         asection **alloc_sec,
                         unsigned int n,
                         unsigned int *ovl_index,
                         unsigned int *num_buf,
                         bfd_vma *ovl_end)
{
  unsigned int i;
  asection *s;

  *ovl_index = 0;
  *num_buf = 0;

  for (i = 1; i < n; i++)
    {
      s = alloc_sec[i];
      if (s->vma < *ovl_end)
        {
          if (!process_overlapping_section(info, alloc_sec, i, ovl_index, num_buf, ovl_end))
            return 0;
        }
      else
        {
          *ovl_end = s->vma + s->size;
        }
    }

  return 1;
}

static int
process_overlapping_section(struct bfd_link_info *info,
                            asection **alloc_sec,
                            unsigned int i,
                            unsigned int *ovl_index,
                            unsigned int *num_buf,
                            bfd_vma *ovl_end)
{
  asection *s = alloc_sec[i];
  asection *s0 = alloc_sec[i - 1];

  if (spu_elf_section_data (s0)->u.o.ovl_index == 0)
    {
      ++(*num_buf);
      if (!startswith (s0->name, ".ovl.init"))
        {
          alloc_sec[*ovl_index] = s0;
          spu_elf_section_data (s0)->u.o.ovl_index = ++(*ovl_index);
          spu_elf_section_data (s0)->u.o.ovl_buf = *num_buf;
        }
      else
        {
          *ovl_end = s->vma + s->size;
        }
    }

  if (!startswith (s->name, ".ovl.init"))
    {
      alloc_sec[*ovl_index] = s;
      spu_elf_section_data (s)->u.o.ovl_index = ++(*ovl_index);
      spu_elf_section_data (s)->u.o.ovl_buf = *num_buf;
      
      if (s0->vma != s->vma)
        {
          info->callbacks->einfo (_("%X%P: overlay sections %pA and %pA do not start at the same address\n"),
                                  s0, s);
          bfd_set_error (bfd_error_bad_value);
          return 0;
        }
      
      if (*ovl_end < s->vma + s->size)
        *ovl_end = s->vma + s->size;
    }

  return 1;
}

static int
setup_overlay_entry(struct spu_link_hash_table *htab, const char *name, int index)
{
  struct elf_link_hash_entry *h;

  h = elf_link_hash_lookup (&htab->elf, name, true, false, false);
  if (h == NULL)
    return 0;

  if (h->root.type == bfd_link_hash_new)
    {
      h->root.type = bfd_link_hash_undefined;
      h->ref_regular = 1;
      h->ref_regular_nonweak = 1;
      h->non_elf = 0;
    }
  
  htab->ovly_entry[index] = h;
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
    if (insn == NULL) {
        return false;
    }
    
    const unsigned char BRANCH_MASK_BYTE0 = 0xec;
    const unsigned char BRANCH_PATTERN_BYTE0 = 0x20;
    const unsigned char BRANCH_MASK_BYTE1 = 0x80;
    const unsigned char BRANCH_PATTERN_BYTE1 = 0x00;
    
    return ((insn[0] & BRANCH_MASK_BYTE0) == BRANCH_PATTERN_BYTE0) &&
           ((insn[1] & BRANCH_MASK_BYTE1) == BRANCH_PATTERN_BYTE1);
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
    if (insn == NULL) {
        return false;
    }
    
    const unsigned char FIRST_BYTE_MASK = 0xef;
    const unsigned char FIRST_BYTE_PATTERN = 0x25;
    const unsigned char SECOND_BYTE_MASK = 0x80;
    const unsigned char SECOND_BYTE_PATTERN = 0x00;
    
    return ((insn[0] & FIRST_BYTE_MASK) == FIRST_BYTE_PATTERN) && 
           ((insn[1] & SECOND_BYTE_MASK) == SECOND_BYTE_PATTERN);
}

/* Return true for branch hint instructions.
   hbra  0001000..
   hbrr  0001001..  */

static bool is_hint(const unsigned char *insn)
{
    if (insn == NULL) {
        return false;
    }
    
    const unsigned char HINT_MASK = 0xfc;
    const unsigned char HINT_PATTERN = 0x10;
    
    return (insn[0] & HINT_MASK) == HINT_PATTERN;
}

/* True if INPUT_SECTION might need overlay stubs.  */

static bool
maybe_needs_stubs (asection *input_section)
{
  if (input_section == NULL)
    return false;

  if ((input_section->flags & SEC_ALLOC) == 0)
    return false;

  if (input_section->output_section == bfd_abs_section_ptr)
    return false;

  if (input_section->name != NULL && strcmp(input_section->name, ".eh_frame") == 0)
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

static enum _stub_type
needs_ovl_stub (struct elf_link_hash_entry *h,
		Elf_Internal_Sym *sym,
		asection *sym_sec,
		asection *input_section,
		Elf_Internal_Rela *irela,
		bfd_byte *contents,
		struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  enum elf_spu_reloc_type r_type;
  unsigned int sym_type;
  bool branch, hint, call;
  bfd_byte insn[4];

  if (sym_sec == NULL
      || sym_sec->output_section == bfd_abs_section_ptr
      || spu_elf_section_data (sym_sec->output_section) == NULL)
    return no_stub;

  if (h != NULL)
    {
      if (h == htab->ovly_entry[0] || h == htab->ovly_entry[1])
	return no_stub;

      if (startswith (h->root.root.string, "setjmp")
	  && (h->root.root.string[6] == '\0' || h->root.root.string[6] == '@'))
	return call_ovl_stub;
    }

  sym_type = (h != NULL) ? h->type : ELF_ST_TYPE (sym->st_info);
  r_type = ELF32_R_TYPE (irela->r_info);
  branch = false;
  hint = false;
  call = false;

  if (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16)
    {
      bfd_byte *insn_ptr;
      
      if (contents == NULL)
	{
	  if (!bfd_get_section_contents (input_section->owner,
					 input_section,
					 insn,
					 irela->r_offset, 4))
	    return stub_error;
	  insn_ptr = insn;
	}
      else
	{
	  insn_ptr = contents + irela->r_offset;
	}

      branch = is_branch (insn_ptr);
      hint = is_hint (insn_ptr);
      
      if (branch || hint)
	{
	  call = (insn_ptr[0] & 0xfd) == 0x31;
	  
	  if (call && sym_type != STT_FUNC && contents != NULL)
	    {
	      const char *sym_name;

	      if (h != NULL)
		{
		  sym_name = h->root.root.string;
		}
	      else
		{
		  Elf_Internal_Shdr *symtab_hdr;
		  symtab_hdr = &elf_tdata (input_section->owner)->symtab_hdr;
		  sym_name = bfd_elf_sym_name (input_section->owner,
					       symtab_hdr,
					       sym,
					       sym_sec);
		}
	      
	      _bfd_error_handler
		(_("warning: call to non-function symbol %s defined in %pB"),
		 sym_name, sym_sec->owner);
	    }
	}
    }

  if ((!branch && htab->params->ovly_flavour == ovly_soft_icache)
      || (sym_type != STT_FUNC
	  && !(branch || hint)
	  && (sym_sec->flags & SEC_CODE) == 0))
    return no_stub;

  if (spu_elf_section_data (sym_sec->output_section)->u.o.ovl_index == 0
      && !htab->params->non_overlay_stubs)
    return no_stub;

  if (spu_elf_section_data (sym_sec->output_section)->u.o.ovl_index
       != spu_elf_section_data (input_section->output_section)->u.o.ovl_index)
    {
      unsigned int lrlive = 0;
      
      if (branch)
	lrlive = (contents[1] & 0x70) >> 4;

      if (!lrlive && (call || sym_type == STT_FUNC))
	return call_ovl_stub;
      
      return br000_ovl_stub + lrlive;
    }

  if (!(branch || hint)
      && sym_type == STT_FUNC
      && htab->params->ovly_flavour != ovly_soft_icache)
    return nonovl_stub;

  return no_stub;
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
  struct got_entry **head;
  bfd_vma addend;

  if (stub_type != nonovl_stub)
    ovl = spu_elf_section_data (isec->output_section)->u.o.ovl_index;

  if (h != NULL)
    {
      head = &h->got.glist;
    }
  else
    {
      if (elf_local_got_ents (ibfd) == NULL)
	{
	  bfd_size_type amt = (elf_tdata (ibfd)->symtab_hdr.sh_info
			       * sizeof (*elf_local_got_ents (ibfd)));
	  elf_local_got_ents (ibfd) = bfd_zmalloc (amt);
	  if (elf_local_got_ents (ibfd) == NULL)
	    return false;
	}
      head = elf_local_got_ents (ibfd) + ELF32_R_SYM (irela->r_info);
    }

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      htab->stub_count[ovl] += 1;
      return true;
    }

  addend = (irela != NULL) ? irela->r_addend : 0;

  struct got_entry *g = NULL;
  
  if (ovl == 0)
    {
      g = find_got_entry(*head, addend, 0);
      if (g == NULL)
	remove_matching_stubs(htab, head, addend);
    }
  else
    {
      g = find_got_entry_with_ovl(*head, addend, ovl);
    }

  if (g == NULL)
    {
      g = create_got_entry(ovl, addend);
      if (g == NULL)
	return false;
      g->next = *head;
      *head = g;
      htab->stub_count[ovl] += 1;
    }

  return true;
}

static struct got_entry *
find_got_entry(struct got_entry *head, bfd_vma addend, unsigned int ovl)
{
  struct got_entry *g;
  for (g = head; g != NULL; g = g->next)
    {
      if (g->addend == addend && g->ovl == ovl)
	return g;
    }
  return NULL;
}

static struct got_entry *
find_got_entry_with_ovl(struct got_entry *head, bfd_vma addend, unsigned int ovl)
{
  struct got_entry *g;
  for (g = head; g != NULL; g = g->next)
    {
      if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
	return g;
    }
  return NULL;
}

static void
remove_matching_stubs(struct spu_link_hash_table *htab, 
		      struct got_entry **head, 
		      bfd_vma addend)
{
  struct got_entry *g = *head;
  struct got_entry *prev = NULL;
  
  while (g != NULL)
    {
      struct got_entry *next = g->next;
      if (g->addend == addend)
	{
	  htab->stub_count[g->ovl] -= 1;
	  if (prev != NULL)
	    prev->next = next;
	  else
	    *head = next;
	  free(g);
	}
      else
	{
	  prev = g;
	}
      g = next;
    }
}

static struct got_entry *
create_got_entry(unsigned int ovl, bfd_vma addend)
{
  struct got_entry *g = bfd_malloc(sizeof(*g));
  if (g != NULL)
    {
      g->ovl = ovl;
      g->addend = addend;
      g->stub_addr = (bfd_vma) -1;
      g->next = NULL;
    }
  return g;
}

/* Support two sizes of overlay stubs, a slower more compact stub of two
   instructions, and a faster stub of four instructions.
   Soft-icache stubs are four or eight words.  */

static unsigned int
ovl_stub_size (struct spu_elf_params *params)
{
  if (params == NULL) {
    return 0;
  }
  
  unsigned int base_size = 16;
  unsigned int flavour_shift = params->ovly_flavour;
  unsigned int compact_shift = params->compact_stub;
  
  if (flavour_shift > 31 || compact_shift > 31) {
    return 0;
  }
  
  unsigned int size = base_size << flavour_shift;
  
  if (compact_shift > 0 && size > compact_shift) {
    size = size >> compact_shift;
  } else if (compact_shift > 0) {
    size = 1;
  }
  
  return size;
}

static unsigned int
ovl_stub_size_log2 (const struct spu_elf_params *params)
{
  if (params == NULL) {
    return 0;
  }
  
  unsigned int base_size = 4;
  unsigned int flavour_adjustment = params->ovly_flavour;
  unsigned int compact_adjustment = params->compact_stub;
  
  return base_size + flavour_adjustment - compact_adjustment;
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
  struct spu_link_hash_table *htab = spu_hash_table (info);
  unsigned int ovl, dest_ovl;
  struct got_entry *g, **head;
  asection *sec;
  bfd_vma addend, from, to;

  ovl = 0;
  if (stub_type != nonovl_stub)
    ovl = spu_elf_section_data (isec->output_section)->u.o.ovl_index;

  if (h != NULL)
    head = &h->got.glist;
  else
    head = elf_local_got_ents (ibfd) + ELF32_R_SYM (irela->r_info);

  addend = 0;
  if (irela != NULL)
    addend = irela->r_addend;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      g = bfd_malloc (sizeof *g);
      if (g == NULL)
	return false;
      g->ovl = ovl;
      g->br_addr = 0;
      if (irela != NULL)
	g->br_addr = (irela->r_offset
		      + isec->output_offset
		      + isec->output_section->vma);
      g->next = *head;
      *head = g;
    }
  else
    {
      for (g = *head; g != NULL; g = g->next)
	if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
	  break;
      if (g == NULL)
	abort ();

      if (g->ovl == 0 && ovl != 0)
	return true;

      if (g->stub_addr != (bfd_vma) -1)
	return true;
    }

  sec = htab->stub_sec[ovl];
  dest += dest_sec->output_offset + dest_sec->output_section->vma;
  from = sec->size + sec->output_offset + sec->output_section->vma;
  g->stub_addr = from;
  to = (htab->ovly_entry[0]->root.u.def.value
	+ htab->ovly_entry[0]->root.u.def.section->output_offset
	+ htab->ovly_entry[0]->root.u.def.section->output_section->vma);

  if (((dest | to | from) & 3) != 0)
    {
      htab->stub_err = 1;
      return false;
    }
  dest_ovl = spu_elf_section_data (dest_sec->output_section)->u.o.ovl_index;

  if (htab->params->ovly_flavour == ovly_normal)
    {
      if (!build_normal_stub(sec, dest, dest_ovl, to, from, htab->params->compact_stub))
        return false;
    }
  else if (htab->params->ovly_flavour == ovly_soft_icache && htab->params->compact_stub)
    {
      if (!build_icache_stub(sec, g, htab, dest, dest_ovl, to, ovl, stub_type, irela, isec, info))
        return false;
    }
  else
    abort ();

  sec->size += ovl_stub_size (htab->params);

  if (htab->params->emit_stub_syms)
    return emit_stub_symbol(htab, g, h, irela, dest_sec, sec);

  return true;
}

static bool
build_normal_stub(asection *sec, bfd_vma dest, unsigned int dest_ovl, 
                  bfd_vma to, bfd_vma from, bool compact_stub)
{
  if (!compact_stub)
    {
      bfd_put_32 (sec->owner, ILA + ((dest_ovl << 7) & 0x01ffff80) + 78,
		  sec->contents + sec->size);
      bfd_put_32 (sec->owner, LNOP,
		  sec->contents + sec->size + 4);
      bfd_put_32 (sec->owner, ILA + ((dest << 7) & 0x01ffff80) + 79,
		  sec->contents + sec->size + 8);
      if (!BRA_STUBS)
	bfd_put_32 (sec->owner, BR + (((to - (from + 12)) << 5) & 0x007fff80),
		    sec->contents + sec->size + 12);
      else
	bfd_put_32 (sec->owner, BRA + ((to << 5) & 0x007fff80),
		    sec->contents + sec->size + 12);
    }
  else
    {
      if (!BRA_STUBS)
	bfd_put_32 (sec->owner, BRSL + (((to - from) << 5) & 0x007fff80) + 75,
		    sec->contents + sec->size);
      else
	bfd_put_32 (sec->owner, BRASL + ((to << 5) & 0x007fff80) + 75,
		    sec->contents + sec->size);
      bfd_put_32 (sec->owner, (dest & 0x3ffff) | (dest_ovl << 18),
		  sec->contents + sec->size + 4);
    }
  return true;
}

static unsigned int
calculate_lrlive(enum _stub_type stub_type, const Elf_Internal_Rela *irela,
                asection *isec, struct bfd_link_info *info, 
                struct spu_link_hash_table *htab)
{
  unsigned int lrlive = 0;
  
  if (stub_type == nonovl_stub)
    return 0;
  if (stub_type == call_ovl_stub)
    return 5;
  if (!htab->params->lrlive_analysis)
    return 1;
  
  if (irela != NULL)
    {
      struct function_info *caller;
      bfd_vma off;

      caller = find_function (isec, irela->r_offset, info);
      if (caller->start == NULL)
	off = irela->r_offset;
      else
	{
	  struct function_info *found = NULL;
	  
	  if (caller->lr_store != (bfd_vma) -1
	      || caller->sp_adjust != (bfd_vma) -1)
	    found = caller;
	  while (caller->start != NULL)
	    {
	      caller = caller->start;
	      if (caller->lr_store != (bfd_vma) -1
		  || caller->sp_adjust != (bfd_vma) -1)
		found = caller;
	    }
	  if (found != NULL)
	    caller = found;
	  off = (bfd_vma) -1;
	}

      if (off > caller->sp_adjust)
	{
	  if (off > caller->lr_store)
	    lrlive = 1;
	  else
	    lrlive = 4;
	}
      else if (off > caller->lr_store)
	{
	  lrlive = 3;
	  BFD_ASSERT (0);
	}
      else
	lrlive = 5;

      if (stub_type != br000_ovl_stub
	  && lrlive != stub_type - br000_ovl_stub)
	info->callbacks->einfo (_("%pA:0x%v lrlive .brinfo (%u) differs "
				  "from analysis (%u)\n"),
				isec, irela->r_offset, lrlive,
				stub_type - br000_ovl_stub);
    }

  if (stub_type > br000_ovl_stub)
    lrlive = stub_type - br000_ovl_stub;
    
  return lrlive;
}

static bool
build_icache_stub(asection *sec, struct got_entry *g, struct spu_link_hash_table *htab,
                  bfd_vma dest, unsigned int dest_ovl, bfd_vma to, unsigned int ovl,
                  enum _stub_type stub_type, const Elf_Internal_Rela *irela,
                  asection *isec, struct bfd_link_info *info)
{
  unsigned int lrlive, set_id;
  bfd_vma br_dest, patt;
  
  lrlive = calculate_lrlive(stub_type, irela, isec, info, htab);

  if (ovl == 0)
    to = (htab->ovly_entry[1]->root.u.def.value
	  + htab->ovly_entry[1]->root.u.def.section->output_offset
	  + htab->ovly_entry[1]->root.u.def.section->output_section->vma);

  g->stub_addr += 4;
  br_dest = g->stub_addr;
  if (irela == NULL)
    {
      BFD_ASSERT (stub_type == nonovl_stub);
      g->br_addr = g->stub_addr;
      br_dest = to;
    }

  set_id = ((dest_ovl - 1) >> htab->num_lines_log2) + 1;
  bfd_put_32 (sec->owner, (set_id << 18) | (dest & 0x3ffff),
	      sec->contents + sec->size);
  bfd_put_32 (sec->owner, BRASL + ((to << 5) & 0x007fff80) + 75,
	      sec->contents + sec->size + 4);
  bfd_put_32 (sec->owner, (lrlive << 29) | (g->br_addr & 0x3ffff),
	      sec->contents + sec->size + 8);
  patt = dest ^ br_dest;
  if (irela != NULL && ELF32_R_TYPE (irela->r_info) == R_SPU_REL16)
    patt = (dest - g->br_addr) ^ (br_dest - g->br_addr);
  bfd_put_32 (sec->owner, (patt << 5) & 0x007fff80,
	      sec->contents + sec->size + 12);

  if (ovl == 0)
    sec->size += 16;
    
  return true;
}

static bool
emit_stub_symbol(struct spu_link_hash_table *htab, struct got_entry *g,
                struct elf_link_hash_entry *h, const Elf_Internal_Rela *irela,
                asection *dest_sec, asection *sec)
{
  size_t len;
  char *name;
  int add;

  len = 8 + sizeof (".ovl_call.") - 1;
  if (h != NULL)
    len += strlen (h->root.root.string);
  else
    len += 8 + 1 + 8;
  add = 0;
  if (irela != NULL)
    add = (int) irela->r_addend & 0xffffffff;
  if (add != 0)
    len += 1 + 8;
  name = bfd_malloc (len + 1);
  if (name == NULL)
    return false;

  sprintf (name, "%08x.ovl_call.", g->ovl);
  if (h != NULL)
    strcpy (name + 8 + sizeof (".ovl_call.") - 1, h->root.root.string);
  else
    sprintf (name + 8 + sizeof (".ovl_call.") - 1, "%x:%x",
	     dest_sec->id & 0xffffffff,
	     (int) ELF32_R_SYM (irela->r_info) & 0xffffffff);
  if (add != 0)
    sprintf (name + len - 9, "+%x", add);

  h = elf_link_hash_lookup (&htab->elf, name, true, true, false);
  free (name);
  if (h == NULL)
    return false;
  if (h->root.type == bfd_link_hash_new)
    {
      h->root.type = bfd_link_hash_defined;
      h->root.u.def.section = sec;
      h->size = ovl_stub_size (htab->params);
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

/* Called via elf_link_hash_traverse to allocate stubs for any _SPUEAR_
   symbols.  */

static bool
allocate_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info = inf;
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection *sym_sec;
  struct spu_elf_stack_info *sec_data;

  if (h->root.type != bfd_link_hash_defined && h->root.type != bfd_link_hash_defweak)
    return true;

  if (!h->def_regular)
    return true;

  if (!startswith (h->root.root.string, "_SPUEAR_"))
    return true;

  sym_sec = h->root.u.def.section;
  if (sym_sec == NULL)
    return true;

  if (sym_sec->output_section == bfd_abs_section_ptr)
    return true;

  sec_data = spu_elf_section_data (sym_sec->output_section);
  if (sec_data == NULL)
    return true;

  if (sec_data->u.o.ovl_index == 0 && !htab->params->non_overlay_stubs)
    return true;

  return count_stub (htab, NULL, NULL, nonovl_stub, h, NULL);
}

static bool
build_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info = inf;
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection *sym_sec;
  struct spu_elf_stack_info *sinfo;

  if (h->root.type != bfd_link_hash_defined && h->root.type != bfd_link_hash_defweak)
    return true;

  if (!h->def_regular)
    return true;

  if (!startswith (h->root.root.string, "_SPUEAR_"))
    return true;

  sym_sec = h->root.u.def.section;
  if (sym_sec == NULL)
    return true;

  if (sym_sec->output_section == bfd_abs_section_ptr)
    return true;

  sinfo = spu_elf_section_data (sym_sec->output_section);
  if (sinfo == NULL)
    return true;

  if (sinfo->u.o.ovl_index == 0 && !htab->params->non_overlay_stubs)
    return true;

  return build_stub (info, NULL, NULL, nonovl_stub, h, NULL,
                     h->root.u.def.value, sym_sec);
}

/* Size or build stubs.  */

static bool
process_stubs (struct bfd_link_info *info, bool build)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (!process_bfd_stubs(info, ibfd, htab, build))
        return false;
    }

  return true;
}

static bool
process_bfd_stubs(struct bfd_link_info *info, bfd *ibfd, 
                  struct spu_link_hash_table *htab, bool build)
{
  extern const bfd_target spu_elf32_vec;
  Elf_Internal_Shdr *symtab_hdr;
  asection *isec;
  Elf_Internal_Sym *local_syms = NULL;
  bool result = true;

  if (ibfd->xvec != &spu_elf32_vec)
    return true;

  symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
  if (symtab_hdr->sh_info == 0)
    return true;

  for (isec = ibfd->sections; isec != NULL && result; isec = isec->next)
    {
      result = process_section_stubs(info, ibfd, isec, htab, 
                                     &local_syms, symtab_hdr, build);
    }

  cleanup_local_syms(local_syms, symtab_hdr, info);
  return result;
}

static bool
process_section_stubs(struct bfd_link_info *info, bfd *ibfd, asection *isec,
                     struct spu_link_hash_table *htab, 
                     Elf_Internal_Sym **local_syms,
                     Elf_Internal_Shdr *symtab_hdr, bool build)
{
  Elf_Internal_Rela *internal_relocs;
  bool result;

  if (!section_needs_processing(isec))
    return true;

  internal_relocs = _bfd_elf_link_read_relocs(ibfd, isec, NULL, NULL,
                                              info->keep_memory);
  if (internal_relocs == NULL)
    return false;

  result = process_relocations(info, ibfd, isec, htab, local_syms,
                               internal_relocs, isec->reloc_count, build);

  if (elf_section_data(isec)->relocs != internal_relocs)
    free(internal_relocs);

  return result;
}

static bool
section_needs_processing(asection *isec)
{
  if ((isec->flags & SEC_RELOC) == 0 || isec->reloc_count == 0)
    return false;
  return maybe_needs_stubs(isec);
}

static bool
process_relocations(struct bfd_link_info *info, bfd *ibfd, asection *isec,
                   struct spu_link_hash_table *htab,
                   Elf_Internal_Sym **local_syms,
                   Elf_Internal_Rela *internal_relocs,
                   size_t reloc_count, bool build)
{
  Elf_Internal_Rela *irela;
  Elf_Internal_Rela *irelaend = internal_relocs + reloc_count;

  for (irela = internal_relocs; irela < irelaend; irela++)
    {
      if (!process_single_relocation(info, ibfd, isec, htab, 
                                     local_syms, irela, build))
        return false;
    }
  return true;
}

static bool
process_single_relocation(struct bfd_link_info *info, bfd *ibfd, 
                         asection *isec, struct spu_link_hash_table *htab,
                         Elf_Internal_Sym **local_syms,
                         Elf_Internal_Rela *irela, bool build)
{
  enum elf_spu_reloc_type r_type;
  unsigned int r_indx;
  asection *sym_sec;
  Elf_Internal_Sym *sym;
  struct elf_link_hash_entry *h;
  enum _stub_type stub_type;

  r_type = ELF32_R_TYPE(irela->r_info);
  r_indx = ELF32_R_SYM(irela->r_info);

  if (r_type >= R_SPU_max)
    {
      bfd_set_error(bfd_error_bad_value);
      return false;
    }

  if (!get_sym_h(&h, &sym, &sym_sec, local_syms, r_indx, ibfd))
    return false;

  stub_type = needs_ovl_stub(h, sym, sym_sec, isec, irela, NULL, info);
  
  if (stub_type == stub_error)
    return false;
  
  if (stub_type == no_stub)
    return true;

  if (!ensure_stub_count_allocated(htab))
    return false;

  if (!build)
    return count_stub(htab, ibfd, isec, stub_type, h, irela);

  return create_stub(info, ibfd, isec, stub_type, h, sym, irela, sym_sec);
}

static bool
ensure_stub_count_allocated(struct spu_link_hash_table *htab)
{
  bfd_size_type amt;
  
  if (htab->stub_count != NULL)
    return true;

  amt = (htab->num_overlays + 1) * sizeof(*htab->stub_count);
  htab->stub_count = bfd_zmalloc(amt);
  return htab->stub_count != NULL;
}

static bool
create_stub(struct bfd_link_info *info, bfd *ibfd, asection *isec,
           enum _stub_type stub_type, struct elf_link_hash_entry *h,
           Elf_Internal_Sym *sym, Elf_Internal_Rela *irela,
           asection *sym_sec)
{
  bfd_vma dest;

  if (h != NULL)
    dest = h->root.u.def.value;
  else
    dest = sym->st_value;
  
  dest += irela->r_addend;
  
  return build_stub(info, ibfd, isec, stub_type, h, irela, dest, sym_sec);
}

static void
cleanup_local_syms(Elf_Internal_Sym *local_syms,
                  Elf_Internal_Shdr *symtab_hdr,
                  struct bfd_link_info *info)
{
  if (local_syms == NULL)
    return;
    
  if (symtab_hdr->contents == (unsigned char *) local_syms)
    return;

  if (!info->keep_memory)
    free(local_syms);
  else
    symtab_hdr->contents = (unsigned char *) local_syms;
}

/* Allocate space for overlay call and return stubs.
   Return 0 on error, 1 if no overlays, 2 otherwise.  */

int
spu_elf_size_stubs (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab;
  bfd *ibfd;
  bfd_size_type amt;
  flagword flags;
  unsigned int i;
  asection *stub;

  if (!process_stubs (info, false))
    return 0;

  htab = spu_hash_table (info);
  if (htab == NULL)
    return 0;

  elf_link_hash_traverse (&htab->elf, allocate_spuear_stubs, info);
  if (htab->stub_err)
    return 0;

  ibfd = info->input_bfds;
  if (ibfd == NULL)
    return 0;

  if (htab->stub_count != NULL)
  {
    amt = (htab->num_overlays + 1) * sizeof (*htab->stub_sec);
    htab->stub_sec = bfd_zmalloc (amt);
    if (htab->stub_sec == NULL)
      return 0;

    flags = (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_READONLY
             | SEC_HAS_CONTENTS | SEC_IN_MEMORY);
    stub = bfd_make_section_anyway_with_flags (ibfd, ".stub", flags);
    htab->stub_sec[0] = stub;
    if (stub == NULL)
      return 0;
    if (!bfd_set_section_alignment (stub, ovl_stub_size_log2 (htab->params)))
      return 0;
    
    stub->size = htab->stub_count[0] * ovl_stub_size (htab->params);
    if (htab->params->ovly_flavour == ovly_soft_icache)
      stub->size += htab->stub_count[0] * 16;

    for (i = 0; i < htab->num_overlays; ++i)
    {
      asection *osec = htab->ovl_sec[i];
      if (osec == NULL)
        return 0;
      unsigned int ovl = spu_elf_section_data (osec)->u.o.ovl_index;
      stub = bfd_make_section_anyway_with_flags (ibfd, ".stub", flags);
      htab->stub_sec[ovl] = stub;
      if (stub == NULL)
        return 0;
      if (!bfd_set_section_alignment (stub, ovl_stub_size_log2 (htab->params)))
        return 0;
      stub->size = htab->stub_count[ovl] * ovl_stub_size (htab->params);
    }
  }

  if (htab->params->ovly_flavour == ovly_soft_icache)
  {
    flags = SEC_ALLOC;
    htab->ovtab = bfd_make_section_anyway_with_flags (ibfd, ".ovtab", flags);
    if (htab->ovtab == NULL)
      return 0;
    if (!bfd_set_section_alignment (htab->ovtab, 4))
      return 0;

    htab->ovtab->size = (16 + 16 + (16 << htab->fromelem_size_log2))
                        << htab->num_lines_log2;

    flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
    htab->init = bfd_make_section_anyway_with_flags (ibfd, ".ovini", flags);
    if (htab->init == NULL)
      return 0;
    if (!bfd_set_section_alignment (htab->init, 4))
      return 0;

    htab->init->size = 16;
  }
  else if (htab->stub_count == NULL)
  {
    return 1;
  }
  else
  {
    flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
    htab->ovtab = bfd_make_section_anyway_with_flags (ibfd, ".ovtab", flags);
    if (htab->ovtab == NULL)
      return 0;
    if (!bfd_set_section_alignment (htab->ovtab, 4))
      return 0;

    htab->ovtab->size = htab->num_overlays * 16 + 16 + htab->num_buf * 4;
  }

  htab->toe = bfd_make_section_anyway_with_flags (ibfd, ".toe", SEC_ALLOC);
  if (htab->toe == NULL)
    return 0;
  if (!bfd_set_section_alignment (htab->toe, 4))
    return 0;
  htab->toe->size = 16;

  return 2;
}

/* Called from ld to place overlay manager data sections.  This is done
   after the overlay manager itself is loaded, mainly so that the
   linker's htab->init section is placed after any other .ovl.init
   sections.  */

void
spu_elf_place_overlay_data (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  unsigned int i;

  if (!htab || !htab->params || !htab->params->place_spu_section)
    return;

  if (htab->stub_sec != NULL)
    {
      htab->params->place_spu_section (htab->stub_sec[0], NULL, ".text");

      for (i = 0; i < htab->num_overlays; ++i)
	{
	  asection *osec = htab->ovl_sec[i];
	  if (!osec)
	    continue;
	  unsigned int ovl = spu_elf_section_data (osec)->u.o.ovl_index;
	  if (ovl < htab->num_overlays && htab->stub_sec[ovl])
	    htab->params->place_spu_section (htab->stub_sec[ovl], osec, NULL);
	}
    }

  if (htab->params->ovly_flavour == ovly_soft_icache && htab->init != NULL)
    htab->params->place_spu_section (htab->init, NULL, ".ovl.init");

  if (htab->ovtab != NULL)
    {
      const char *ovout = (htab->params->ovly_flavour == ovly_soft_icache) ? ".bss" : ".data";
      htab->params->place_spu_section (htab->ovtab, NULL, ovout);
    }

  if (htab->toe != NULL)
    htab->params->place_spu_section (htab->toe, NULL, ".toe");
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
  struct _ovl_stream *os;
  size_t count;
  size_t max;
  const char *start;
  const char *end;

  if (stream == NULL || buf == NULL) {
    return 0;
  }

  if (nbytes <= 0 || offset < 0) {
    return 0;
  }

  os = (struct _ovl_stream *) stream;
  
  if (os->start == NULL || os->end == NULL) {
    return 0;
  }

  start = (const char *) os->start;
  end = (const char *) os->end;

  if (end <= start) {
    return 0;
  }

  max = end - start;

  if ((ufile_ptr) offset >= max) {
    return 0;
  }

  count = nbytes;
  if (count > max - offset) {
    count = max - offset;
  }

  memcpy (buf, start + offset, count);
  return count;
}

static int
ovl_mgr_stat (struct bfd *abfd ATTRIBUTE_UNUSED,
	      void *stream,
	      struct stat *sb)
{
  struct _ovl_stream *os = (struct _ovl_stream *) stream;

  if (os == NULL || sb == NULL) {
    return -1;
  }

  memset (sb, 0, sizeof (*sb));
  
  if (os->end < os->start) {
    return -1;
  }
  
  sb->st_size = (const char *) os->end - (const char *) os->start;
  return 0;
}

bool
spu_elf_open_builtin_lib (bfd **ovl_bfd, const struct _ovl_stream *stream)
{
  if (ovl_bfd == NULL || stream == NULL)
    return false;
    
  *ovl_bfd = bfd_openr_iovec ("builtin ovl_mgr",
                               "elf32-spu",
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
  if (sec == NULL)
    return 0;
  
  if (sec->output_section == bfd_abs_section_ptr)
    return 0;
  
  return spu_elf_section_data (sec->output_section)->u.o.ovl_index;
}

/* Define an STT_OBJECT symbol.  */

static struct elf_link_hash_entry *
define_ovtab_symbol (struct spu_link_hash_table *htab, const char *name)
{
  struct elf_link_hash_entry *h;

  if (htab == NULL || name == NULL)
    return NULL;

  h = elf_link_hash_lookup (&htab->elf, name, true, false, false);
  if (h == NULL)
    return NULL;

  if (h->root.type == bfd_link_hash_defined && h->def_regular)
    {
      if (h->root.u.def.section != NULL && h->root.u.def.section->owner != NULL)
        {
          _bfd_error_handler (_("%pB is not allowed to define %s"),
                              h->root.u.def.section->owner,
                              h->root.root.string);
        }
      else
        {
          _bfd_error_handler (_("you are not allowed to define %s in a script"),
                              h->root.root.string);
        }
      bfd_set_error (bfd_error_bad_value);
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

static bool
spu_elf_build_stubs (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  
  if (htab == NULL)
    return false;
    
  if (htab->num_overlays != 0)
    {
      if (!validate_overlay_entries(htab))
        return false;
    }

  if (htab->stub_sec != NULL)
    {
      if (!allocate_stub_sections(htab))
        return false;
        
      process_stubs (info, true);
      if (!htab->stub_err)
        elf_link_hash_traverse (&htab->elf, build_spuear_stubs, info);

      if (htab->stub_err)
        {
          _bfd_error_handler (_("overlay stub relocation overflow"));
          bfd_set_error (bfd_error_bad_value);
          return false;
        }

      if (!verify_stub_sizes(htab))
        return false;
    }

  if (htab->ovtab == NULL || htab->ovtab->size == 0)
    return true;

  htab->ovtab->contents = bfd_zalloc (htab->ovtab->owner, htab->ovtab->size);
  if (htab->ovtab->contents == NULL)
    return false;
  htab->ovtab->alloced = 1;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      if (!setup_icache_symbols(htab))
        return false;
    }
  else
    {
      if (!setup_overlay_table(htab))
        return false;
    }

  struct elf_link_hash_entry *h = define_ovtab_symbol (htab, "_EAR_");
  if (h == NULL)
    return false;
  h->root.u.def.section = htab->toe;
  h->root.u.def.value = 0;
  h->size = 16;

  return true;
}

static bool
validate_overlay_entries(struct spu_link_hash_table *htab)
{
  for (unsigned int i = 0; i < 2; i++)
    {
      struct elf_link_hash_entry *h = htab->ovly_entry[i];
      if (h != NULL
          && (h->root.type == bfd_link_hash_defined
              || h->root.type == bfd_link_hash_defweak)
          && h->def_regular)
        {
          asection *s = h->root.u.def.section->output_section;
          if (spu_elf_section_data (s)->u.o.ovl_index)
            {
              _bfd_error_handler (_("%s in overlay section"),
                                  h->root.root.string);
              bfd_set_error (bfd_error_bad_value);
              return false;
            }
        }
    }
  return true;
}

static bool
allocate_stub_sections(struct spu_link_hash_table *htab)
{
  for (unsigned int i = 0; i <= htab->num_overlays; i++)
    {
      if (htab->stub_sec[i]->size != 0)
        {
          htab->stub_sec[i]->contents = bfd_zalloc (htab->stub_sec[i]->owner,
                                                    htab->stub_sec[i]->size);
          if (htab->stub_sec[i]->contents == NULL)
            return false;
          htab->stub_sec[i]->alloced = 1;
          htab->stub_sec[i]->rawsize = htab->stub_sec[i]->size;
          htab->stub_sec[i]->size = 0;
        }
    }
  return true;
}

static bool
verify_stub_sizes(struct spu_link_hash_table *htab)
{
  for (unsigned int i = 0; i <= htab->num_overlays; i++)
    {
      if (htab->stub_sec[i]->size != htab->stub_sec[i]->rawsize)
        {
          _bfd_error_handler  (_("stubs don't match calculated size"));
          bfd_set_error (bfd_error_bad_value);
          return false;
        }
      htab->stub_sec[i]->rawsize = 0;
    }
  return true;
}

static bool
define_icache_symbol(struct spu_link_hash_table *htab, const char *name, 
                     bfd_vma value, bfd_vma size, asection *section)
{
  struct elf_link_hash_entry *h = define_ovtab_symbol (htab, name);
  if (h == NULL)
    return false;
  h->root.u.def.value = value;
  if (section != NULL)
    h->root.u.def.section = section;
  if (size != 0)
    h->size = size;
  return true;
}

static bool
setup_icache_symbols(struct spu_link_hash_table *htab)
{
  bfd_vma off = 0;
  bfd_vma tag_array_size = 16 << htab->num_lines_log2;
  bfd_vma from_elem_size = 16 << (htab->fromelem_size_log2 + htab->num_lines_log2);
  bfd_vma cache_size = 1 << (htab->num_lines_log2 + htab->line_size_log2);
  
  if (!define_icache_symbol(htab, "__icache_tag_array", 0, tag_array_size, NULL))
    return false;
  off = tag_array_size;

  if (!define_icache_symbol(htab, "__icache_tag_array_size", tag_array_size, 0, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_rewrite_to", off, tag_array_size, NULL))
    return false;
  off += tag_array_size;

  if (!define_icache_symbol(htab, "__icache_rewrite_to_size", tag_array_size, 0, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_rewrite_from", off, from_elem_size, NULL))
    return false;

  if (!define_icache_symbol(htab, "__icache_rewrite_from_size", from_elem_size, 0, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_log2_fromelemsize", htab->fromelem_size_log2, 0, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_base", htab->ovl_sec[0]->vma, 
                           htab->num_buf << htab->line_size_log2, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_linesize", 1 << htab->line_size_log2, 0, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_log2_linesize", htab->line_size_log2, 0, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_neg_log2_linesize", -htab->line_size_log2, 0, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_cachesize", cache_size, 0, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_log2_cachesize", 
                           htab->num_lines_log2 + htab->line_size_log2, 0, bfd_abs_section_ptr))
    return false;

  if (!define_icache_symbol(htab, "__icache_neg_log2_cachesize", 
                           -(htab->num_lines_log2 + htab->line_size_log2), 0, bfd_abs_section_ptr))
    return false;

  if (htab->init != NULL && htab->init->size != 0)
    {
      htab->init->contents = bfd_zalloc (htab->init->owner, htab->init->size);
      if (htab->init->contents == NULL)
        return false;
      htab->init->alloced = 1;

      struct elf_link_hash_entry *h = define_ovtab_symbol (htab, "__icache_fileoff");
      if (h == NULL)
        return false;
      h->root.u.def.value = 0;
      h->root.u.def.section = htab->init;
      h->size = 8;
    }
  return true;
}

static bool
setup_overlay_table(struct spu_link_hash_table *htab)
{
  bfd_byte *p = htab->ovtab->contents;
  p[7] = 1;
  
  bfd *obfd = htab->ovtab->output_section->owner;
  for (asection *s = obfd->sections; s != NULL; s = s->next)
    {
      unsigned int ovl_index = spu_elf_section_data (s)->u.o.ovl_index;
      if (ovl_index != 0)
        {
          unsigned long off = ovl_index * 16;
          unsigned int ovl_buf = spu_elf_section_data (s)->u.o.ovl_buf;

          bfd_put_32 (htab->ovtab->owner, s->vma, p + off);
          bfd_put_32 (htab->ovtab->owner, (s->size + 15) & -16, p + off + 4);
          bfd_put_32 (htab->ovtab->owner, ovl_buf, p + off + 12);
        }
    }

  struct elf_link_hash_entry *h = define_ovtab_symbol (htab, "_ovly_table");
  if (h == NULL)
    return false;
  h->root.u.def.value = 16;
  h->size = htab->num_overlays * 16;

  h = define_ovtab_symbol (htab, "_ovly_table_end");
  if (h == NULL)
    return false;
  h->root.u.def.value = htab->num_overlays * 16 + 16;
  h->size = 0;

  h = define_ovtab_symbol (htab, "_ovly_buf_table");
  if (h == NULL)
    return false;
  h->root.u.def.value = htab->num_overlays * 16 + 16;
  h->size = htab->num_buf * 4;

  h = define_ovtab_symbol (htab, "_ovly_buf_table_end");
  if (h == NULL)
    return false;
  h->root.u.def.value = htab->num_overlays * 16 + 16 + htab->num_buf * 4;
  h->size = 0;

  return true;
}

/* Check that all loadable section VMAs lie in the range
   LO .. HI inclusive, and stash some parameters for --auto-overlay.  */

asection *
spu_elf_check_vma (struct bfd_link_info *info)
{
  struct elf_segment_map *m;
  unsigned int i;
  struct spu_link_hash_table *htab;
  bfd *abfd;
  bfd_vma hi;
  bfd_vma lo;
  asection *section;
  bfd_vma section_end;

  if (info == NULL) {
    return NULL;
  }

  htab = spu_hash_table (info);
  if (htab == NULL || htab->params == NULL) {
    return NULL;
  }

  abfd = info->output_bfd;
  if (abfd == NULL) {
    return NULL;
  }

  hi = htab->params->local_store_hi;
  lo = htab->params->local_store_lo;

  if (hi < lo) {
    return NULL;
  }

  htab->local_store = hi + 1 - lo;

  for (m = elf_seg_map (abfd); m != NULL; m = m->next) {
    if (m->p_type != PT_LOAD) {
      continue;
    }

    for (i = 0; i < m->count; i++) {
      section = m->sections[i];
      
      if (section == NULL || section->size == 0) {
        continue;
      }

      if (section->vma < lo || section->vma > hi) {
        return section;
      }

      section_end = section->vma + section->size - 1;
      if (section_end > hi) {
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

static int
find_function_stack_adjust (asection *sec,
                           bfd_vma offset,
                           bfd_vma *lr_store,
                           bfd_vma *sp_adjust)
{
  int32_t reg[128];
  unsigned char buf[4];
  
  memset (reg, 0, sizeof (reg));
  
  while (offset + 4 <= sec->size)
    {
      if (!bfd_get_section_contents (sec->owner, sec, buf, offset, 4))
        break;
      
      int rt = buf[3] & 0x7f;
      int ra = ((buf[2] & 0x3f) << 1) | (buf[3] >> 7);
      uint32_t imm = (buf[1] << 9) | (buf[2] << 1) | (buf[3] >> 7);
      
      if (buf[0] == 0x24)
        {
          if (rt == 0 && ra == 1)
            *lr_store = offset;
        }
      else if (buf[0] == 0x1c)
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
            {
              imm |= (buf[0] & 1) << 17;
            }
          else
            {
              imm &= 0xffff;
              
              if (buf[0] == 0x40)
                {
                  if ((buf[1] & 0x80) == 0)
                    {
                      offset += 4;
                      continue;
                    }
                  imm = (imm ^ 0x8000) - 0x8000;
                }
              else if ((buf[1] & 0x80) == 0)
                {
                  imm <<= 16;
                }
            }
          reg[rt] = imm;
        }
      else if (buf[0] == 0x60 && (buf[1] & 0x80) != 0)
        {
          reg[rt] |= imm & 0xffff;
        }
      else if (buf[0] == 0x04)
        {
          imm >>= 7;
          imm = (imm ^ 0x200) - 0x200;
          reg[rt] = reg[ra] | imm;
        }
      else if (buf[0] == 0x32 && (buf[1] & 0x80) != 0)
        {
          reg[rt] = ((imm & 0x8000) ? 0xff000000 : 0)
                  | ((imm & 0x4000) ? 0x00ff0000 : 0)
                  | ((imm & 0x2000) ? 0x0000ff00 : 0)
                  | ((imm & 0x1000) ? 0x000000ff : 0);
        }
      else if (buf[0] == 0x16)
        {
          imm >>= 7;
          imm &= 0xff;
          imm |= imm << 8;
          imm |= imm << 16;
          reg[rt] = reg[ra] & imm;
        }
      else if (buf[0] == 0x33 && imm == 1)
        {
          reg[rt] = 0;
        }
      else if (is_branch (buf) || is_indirect_branch (buf))
        {
          break;
        }
      
      offset += 4;
    }
  
  return 0;
}

/* qsort predicate to sort symbols by section and value.  */

static Elf_Internal_Sym *sort_syms_syms;
static asection **sort_syms_psecs;

static int
sort_syms (const void *a, const void *b)
{
  const Elf_Internal_Sym *const *s1 = a;
  const Elf_Internal_Sym *const *s2 = b;
  
  if (s1 == NULL || s2 == NULL || *s1 == NULL || *s2 == NULL) {
    return 0;
  }
  
  asection *sec1 = sort_syms_psecs[*s1 - sort_syms_syms];
  asection *sec2 = sort_syms_psecs[*s2 - sort_syms_syms];
  
  if (sec1 != sec2) {
    if (sec1 == NULL || sec2 == NULL) {
      return (sec1 == NULL) ? 1 : -1;
    }
    return sec1->index - sec2->index;
  }
  
  bfd_signed_vma value_delta = (*s1)->st_value - (*s2)->st_value;
  if (value_delta != 0) {
    return (value_delta < 0) ? -1 : 1;
  }
  
  bfd_signed_vma size_delta = (*s2)->st_size - (*s1)->st_size;
  if (size_delta != 0) {
    return (size_delta < 0) ? -1 : 1;
  }
  
  return (*s1 < *s2) ? -1 : 1;
}

/* Allocate a struct spu_elf_stack_info with MAX_FUN struct function_info
   entries for section SEC.  */

static struct spu_elf_stack_info *
alloc_stack_info (asection *sec, int max_fun)
{
  struct _spu_elf_section_data *sec_data;
  bfd_size_type amt;
  struct spu_elf_stack_info *stack_info;

  if (sec == NULL || max_fun <= 0)
    return NULL;

  sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL)
    return NULL;

  amt = sizeof (struct spu_elf_stack_info);
  if (max_fun > 1)
    {
      bfd_size_type extra = sizeof (struct function_info);
      if (max_fun > (BFD_SIZE_MAX - amt) / extra)
        return NULL;
      amt += (max_fun - 1) * extra;
    }

  stack_info = bfd_zmalloc (amt);
  if (stack_info == NULL)
    return NULL;

  stack_info->max_fun = max_fun;
  sec_data->u.i.stack_info = stack_info;
  
  return stack_info;
}

/* Add a new struct function_info describing a (part of a) function
   starting at SYM_H.  Keep the array sorted by address.  */

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

  if (sinfo == NULL)
    {
      sinfo = alloc_stack_info (sec, 20);
      if (sinfo == NULL)
	return NULL;
    }

  if (!global)
    {
      Elf_Internal_Sym *sym = sym_h;
      off = sym->st_value;
      size = sym->st_size;
    }
  else
    {
      struct elf_link_hash_entry *h = sym_h;
      off = h->root.u.def.value;
      size = h->size;
    }

  for (i = sinfo->num_fun; --i >= 0; )
    if (sinfo->fun[i].lo <= off)
      break;

  if (i >= 0)
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
      if (sinfo->fun[i].hi > off && size == 0)
	return &sinfo->fun[i];
    }

  if (sinfo->num_fun >= sinfo->max_fun)
    {
      bfd_size_type amt = sizeof (struct spu_elf_stack_info);
      bfd_size_type old = amt;

      old += (sinfo->max_fun - 1) * sizeof (struct function_info);
      sinfo->max_fun += 20 + (sinfo->max_fun >> 1);
      amt += (sinfo->max_fun - 1) * sizeof (struct function_info);
      sinfo = bfd_realloc (sinfo, amt);
      if (sinfo == NULL)
	return NULL;
      memset ((char *) sinfo + old, 0, amt - old);
      sec_data->u.i.stack_info = sinfo;
    }

  i++;
  if (i < sinfo->num_fun)
    memmove (&sinfo->fun[i + 1], &sinfo->fun[i],
	     (sinfo->num_fun - i) * sizeof (sinfo->fun[i]));
  sinfo->fun[i].is_func = is_func;
  sinfo->fun[i].global = global;
  sinfo->fun[i].sec = sec;
  if (global)
    sinfo->fun[i].u.h = sym_h;
  else
    sinfo->fun[i].u.sym = sym_h;
  sinfo->fun[i].lo = off;
  sinfo->fun[i].hi = off + size;
  sinfo->fun[i].lr_store = -1;
  sinfo->fun[i].sp_adjust = -1;
  sinfo->fun[i].stack = -find_function_stack_adjust (sec, off,
						     &sinfo->fun[i].lr_store,
						     &sinfo->fun[i].sp_adjust);
  sinfo->num_fun += 1;
  return &sinfo->fun[i];
}

/* Return the name of FUN.  */

static const char *
func_name (struct function_info *fun)
{
  asection *sec;
  bfd *ibfd;
  Elf_Internal_Shdr *symtab_hdr;
  size_t len;
  char *name;

  if (fun == NULL)
    return "(null)";

  while (fun->start != NULL)
    fun = fun->start;

  if (fun->global)
    return fun->u.h->root.root.string;

  sec = fun->sec;
  if (sec == NULL)
    return "(null)";

  if (fun->u.sym->st_name == 0)
    {
      len = strlen (sec->name);
      if (len > SIZE_MAX - 10)
        return "(null)";
      
      name = bfd_malloc (len + 10);
      if (name == NULL)
        return "(null)";
      
      snprintf (name, len + 10, "%s+%lx", sec->name,
                (unsigned long) fun->u.sym->st_value & 0xffffffff);
      return name;
    }
  
  ibfd = sec->owner;
  if (ibfd == NULL)
    return "(null)";
    
  symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
  return bfd_elf_sym_name (ibfd, symtab_hdr, fun->u.sym, sec);
}

/* Read the instruction at OFF in SEC.  Return true iff the instruction
   is a nop, lnop, or stop 0 (all zero insn).  */

static bool
is_nop (asection *sec, bfd_vma off)
{
  unsigned char insn[4];

  if (off + 4 > sec->size)
    return false;
    
  if (!bfd_get_section_contents (sec->owner, sec, insn, off, 4))
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
  if (fun == NULL) {
    return false;
  }
  
  bfd_vma off = (fun->hi + 3) & ~(bfd_vma)3;
  
  if (off >= limit) {
    fun->hi = limit;
    return false;
  }
  
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

static bool
check_function_ranges (asection *sec, struct bfd_link_info *info)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  bool gaps = false;

  if (sinfo == NULL || sinfo->num_fun == 0)
    return sinfo != NULL;

  for (int i = 1; i < sinfo->num_fun; i++)
    {
      if (sinfo->fun[i - 1].hi > sinfo->fun[i].lo)
        {
          const char *f1 = func_name (&sinfo->fun[i - 1]);
          const char *f2 = func_name (&sinfo->fun[i]);
          info->callbacks->einfo (_("warning: %s overlaps %s\n"), f1, f2);
          sinfo->fun[i - 1].hi = sinfo->fun[i].lo;
        }
      else if (insns_at_end (&sinfo->fun[i - 1], sinfo->fun[i].lo))
        {
          gaps = true;
        }
    }

  if (sinfo->fun[0].lo != 0)
    gaps = true;

  int last_idx = sinfo->num_fun - 1;
  if (sinfo->fun[last_idx].hi > sec->size)
    {
      const char *f1 = func_name (&sinfo->fun[last_idx]);
      info->callbacks->einfo (_("warning: %s exceeds section size\n"), f1);
      sinfo->fun[last_idx].hi = sec->size;
    }
  else if (insns_at_end (&sinfo->fun[last_idx], sec->size))
    {
      gaps = true;
    }

  return gaps;
}

/* Search current function info for a function that contains address
   OFFSET in section SEC.  */

static struct function_info *
find_function (asection *sec, bfd_vma offset, struct bfd_link_info *info)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  int lo = 0;
  int hi = sinfo->num_fun;

  while (lo < hi)
    {
      int mid = lo + ((hi - lo) / 2);
      
      if (offset < sinfo->fun[mid].lo)
        {
          hi = mid;
        }
      else if (offset >= sinfo->fun[mid].hi)
        {
          lo = mid + 1;
        }
      else
        {
          return &sinfo->fun[mid];
        }
    }

  info->callbacks->einfo (_("%pA:0x%v not found in function table\n"),
                          sec, offset);
  bfd_set_error (bfd_error_bad_value);
  return NULL;
}

/* Add CALLEE to CALLER call list if not already present.  Return TRUE
   if CALLEE was new.  If this function return FALSE, CALLEE should
   be freed.  */

static bool
insert_callee (struct function_info *caller, struct call_info *callee)
{
  struct call_info **pp;
  struct call_info *p;

  if (caller == NULL || callee == NULL) {
    return false;
  }

  pp = &caller->call_list;
  while (*pp != NULL) {
    p = *pp;
    if (p->fun == callee->fun) {
      p->is_tail &= callee->is_tail;
      if (!p->is_tail) {
        p->fun->start = NULL;
        p->fun->is_func = true;
      }
      p->count += callee->count;
      *pp = p->next;
      p->next = caller->call_list;
      caller->call_list = p;
      return false;
    }
    pp = &p->next;
  }
  
  callee->next = caller->call_list;
  caller->call_list = callee;
  return true;
}

/* Copy CALL and insert the copy into CALLER.  */

static bool
copy_callee (struct function_info *caller, const struct call_info *call)
{
  struct call_info *callee;
  
  if (caller == NULL || call == NULL)
    return false;
    
  callee = bfd_malloc (sizeof (*callee));
  if (callee == NULL)
    return false;
    
  *callee = *call;
  
  if (!insert_callee (caller, callee))
    {
      free (callee);
      return false;
    }
    
  return true;
}

/* We're only interested in code sections.  Testing SEC_IN_MEMORY excludes
   overlay stub sections.  */

static bool
interesting_section (asection *s)
{
  if (s == NULL) {
    return false;
  }
  
  if (s->output_section == bfd_abs_section_ptr) {
    return false;
  }
  
  if (s->size == 0) {
    return false;
  }
  
  const flagword required_flags = SEC_ALLOC | SEC_LOAD | SEC_CODE;
  const flagword mask = SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_IN_MEMORY;
  
  return (s->flags & mask) == required_flags;
}

/* Rummage through the relocs for SEC, looking for function calls.
   If CALL_TREE is true, fill in call graph.  If CALL_TREE is false,
   mark destination symbols on calls as being functions.  Also
   look at branches, which may be tail calls or go to hot/cold
   section part of same function.  */

static bool
mark_functions_via_relocs (asection *sec,
			   struct bfd_link_info *info,
			   int call_tree)
{
  Elf_Internal_Rela *internal_relocs, *irelaend, *irela;
  Elf_Internal_Shdr *symtab_hdr;
  void *psyms;
  unsigned int priority = 0;
  static bool warned;

  if (!interesting_section (sec) || sec->reloc_count == 0)
    return true;

  internal_relocs = _bfd_elf_link_read_relocs (sec->owner, sec, NULL, NULL,
					       info->keep_memory);
  if (internal_relocs == NULL)
    return false;

  symtab_hdr = &elf_tdata (sec->owner)->symtab_hdr;
  psyms = &symtab_hdr->contents;
  irela = internal_relocs;
  irelaend = irela + sec->reloc_count;
  
  for (; irela < irelaend; irela++)
    {
      if (!process_relocation(sec, info, call_tree, psyms, irela, &priority, &warned))
        return false;
    }

  return true;
}

static bool
process_relocation(asection *sec, struct bfd_link_info *info, int call_tree,
                   void *psyms, Elf_Internal_Rela *irela, unsigned int *priority,
                   bool *warned)
{
  enum elf_spu_reloc_type r_type;
  unsigned int r_indx;
  asection *sym_sec;
  Elf_Internal_Sym *sym;
  struct elf_link_hash_entry *h;
  bfd_vma val;
  bool nonbranch, is_call;

  r_type = ELF32_R_TYPE (irela->r_info);
  nonbranch = r_type != R_SPU_REL16 && r_type != R_SPU_ADDR16;

  r_indx = ELF32_R_SYM (irela->r_info);
  if (!get_sym_h (&h, &sym, &sym_sec, psyms, r_indx, sec->owner))
    return false;

  if (sym_sec == NULL || sym_sec->output_section == bfd_abs_section_ptr)
    return true;

  is_call = false;
  if (!nonbranch)
    {
      if (!check_branch_instruction(sec, irela, sym_sec, info, 
                                    &is_call, priority, &nonbranch, warned))
        return true;
    }

  if (nonbranch)
    {
      if (!handle_nonbranch_reference(h, sym, sym_sec, call_tree, info))
        return true;
    }

  val = h ? h->root.u.def.value : sym->st_value;
  val += irela->r_addend;

  if (!call_tree)
    return handle_noncall_tree(sym_sec, sym, h, val, irela, is_call);
  
  return handle_call_tree(sec, sym_sec, val, irela, info, is_call, nonbranch, *priority);
}

static bool
check_branch_instruction(asection *sec, Elf_Internal_Rela *irela,
                         asection *sym_sec, struct bfd_link_info *info,
                         bool *is_call, unsigned int *priority,
                         bool *nonbranch, bool *warned)
{
  unsigned char insn[4];

  if (!bfd_get_section_contents (sec->owner, sec, insn, irela->r_offset, 4))
    return false;
    
  if (!is_branch (insn))
    {
      *nonbranch = true;
      return !is_hint (insn);
    }

  *is_call = (insn[0] & 0xfd) == 0x31;
  *priority = ((insn[1] & 0x0f) << 16) | (insn[2] << 8) | insn[3];
  *priority >>= 7;
  
  if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE))
      != (SEC_ALLOC | SEC_LOAD | SEC_CODE))
    {
      if (!*warned)
        {
          info->callbacks->einfo
            (_("%pB(%pA+0x%v): call to non-code section"
               " %pB(%pA), analysis incomplete\n"),
             sec->owner, sec, irela->r_offset,
             sym_sec->owner, sym_sec);
          *warned = true;
        }
      return false;
    }
  return true;
}

static bool
handle_nonbranch_reference(struct elf_link_hash_entry *h,
                           Elf_Internal_Sym *sym, asection *sym_sec,
                           int call_tree, struct bfd_link_info *info)
{
  unsigned int sym_type;
  
  sym_type = h ? h->type : ELF_ST_TYPE (sym->st_info);
  
  if (sym_type == STT_FUNC)
    {
      if (call_tree && spu_hash_table (info)->params->auto_overlay)
        spu_hash_table (info)->non_ovly_stub += 1;
      return false;
    }
    
  if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE))
      != (SEC_ALLOC | SEC_LOAD | SEC_CODE))
    return false;
    
  return true;
}

static bool
handle_noncall_tree(asection *sym_sec, Elf_Internal_Sym *sym,
                   struct elf_link_hash_entry *h, bfd_vma val,
                   Elf_Internal_Rela *irela, bool is_call)
{
  struct function_info *fun;
  Elf_Internal_Sym *fake = NULL;

  if (irela->r_addend != 0)
    {
      fake = bfd_zmalloc (sizeof (*fake));
      if (fake == NULL)
        return false;
      fake->st_value = val;
      fake->st_shndx = _bfd_elf_section_from_bfd_section (sym_sec->owner, sym_sec);
      sym = fake;
    }
    
  fun = sym ? maybe_insert_function (sym_sec, sym, false, is_call)
            : maybe_insert_function (sym_sec, h, true, is_call);
            
  if (fun == NULL)
    {
      free (fake);
      return false;
    }
    
  if (fake && fun->u.sym != sym)
    free (fake);
    
  return true;
}

static bool
handle_call_tree(asection *sec, asection *sym_sec, bfd_vma val,
                Elf_Internal_Rela *irela, struct bfd_link_info *info,
                bool is_call, bool nonbranch, unsigned int priority)
{
  struct function_info *caller;
  struct call_info *callee;

  caller = find_function (sec, irela->r_offset, info);
  if (caller == NULL)
    return false;
    
  callee = bfd_malloc (sizeof *callee);
  if (callee == NULL)
    return false;

  callee->fun = find_function (sym_sec, val, info);
  if (callee->fun == NULL)
    {
      free (callee);
      return false;
    }
    
  callee->is_tail = !is_call;
  callee->is_pasted = false;
  callee->broken_cycle = false;
  callee->priority = priority;
  callee->count = nonbranch ? 0 : 1;
  
  if (callee->fun->last_caller != sec)
    {
      callee->fun->last_caller = sec;
      callee->fun->call_count += 1;
    }
    
  if (!insert_callee (caller, callee))
    {
      free (callee);
      return true;
    }
    
  if (!is_call && !callee->fun->is_func && callee->fun->stack == 0)
    update_function_relationships(caller, callee, sec, sym_sec);
    
  return true;
}

static void
update_function_relationships(struct function_info *caller,
                             struct call_info *callee,
                             asection *sec, asection *sym_sec)
{
  if (sec->owner != sym_sec->owner)
    {
      callee->fun->start = NULL;
      callee->fun->is_func = true;
      return;
    }
    
  if (callee->fun->start == NULL)
    {
      struct function_info *caller_start = find_function_start(caller);
      if (caller_start != callee->fun)
        callee->fun->start = caller_start;
    }
  else
    {
      struct function_info *callee_start = find_function_start(callee->fun);
      struct function_info *caller_start = find_function_start(caller);
      
      if (caller_start != callee_start)
        {
          callee->fun->start = NULL;
          callee->fun->is_func = true;
        }
    }
}

static struct function_info *
find_function_start(struct function_info *func)
{
  while (func->start)
    func = func->start;
  return func;
}

/* Handle something like .init or .fini, which has a piece of a function.
   These sections are pasted together to form a single function.  */

static bool
pasted_function (asection *sec)
{
  struct bfd_link_order *l;
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  Elf_Internal_Sym *fake;
  struct function_info *fun, *fun_start;
  struct call_info *callee;

  fake = bfd_zmalloc (sizeof (*fake));
  if (fake == NULL)
    return false;
  
  fake->st_value = 0;
  fake->st_size = sec->size;
  fake->st_shndx = _bfd_elf_section_from_bfd_section (sec->owner, sec);
  
  fun = maybe_insert_function (sec, fake, false, false);
  if (!fun)
    return false;

  fun_start = NULL;
  
  for (l = sec->output_section->map_head.link_order; l != NULL; l = l->next)
    {
      if (l->u.indirect.section == sec)
        break;
        
      if (l->type != bfd_indirect_link_order)
        continue;
        
      sec_data = spu_elf_section_data (l->u.indirect.section);
      if (sec_data == NULL)
        continue;
        
      sinfo = sec_data->u.i.stack_info;
      if (sinfo == NULL || sinfo->num_fun == 0)
        continue;
        
      fun_start = &sinfo->fun[sinfo->num_fun - 1];
    }

  if (l == NULL || l->u.indirect.section != sec || fun_start == NULL)
    return true;

  callee = bfd_malloc (sizeof *callee);
  if (callee == NULL)
    return false;

  fun->start = fun_start;
  callee->fun = fun;
  callee->is_tail = true;
  callee->is_pasted = true;
  callee->broken_cycle = false;
  callee->priority = 0;
  callee->count = 1;
  
  if (!insert_callee (fun_start, callee))
    free (callee);
    
  return true;
}

/* Map address ranges in code sections to functions.  */

static bool
discover_functions (struct bfd_link_info *info)
{
  bfd *ibfd;
  int bfd_idx;
  Elf_Internal_Sym ***psym_arr = NULL;
  asection ***sec_arr = NULL;
  bool gaps = false;
  bool result = false;

  bfd_idx = 0;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    bfd_idx++;

  psym_arr = bfd_zmalloc (bfd_idx * sizeof (*psym_arr));
  if (psym_arr == NULL)
    goto cleanup;
    
  sec_arr = bfd_zmalloc (bfd_idx * sizeof (*sec_arr));
  if (sec_arr == NULL)
    goto cleanup;

  if (!process_input_bfds(info, psym_arr, sec_arr, &gaps))
    goto cleanup;

  if (gaps)
    {
      if (!process_gaps(info, psym_arr, sec_arr))
        goto cleanup;
    }

  result = true;

cleanup:
  if (psym_arr != NULL)
    {
      for (ibfd = info->input_bfds, bfd_idx = 0;
           ibfd != NULL;
           ibfd = ibfd->link.next, bfd_idx++)
        {
          if (psym_arr[bfd_idx] != NULL)
            free (psym_arr[bfd_idx]);
        }
      free (psym_arr);
    }

  if (sec_arr != NULL)
    {
      for (ibfd = info->input_bfds, bfd_idx = 0;
           ibfd != NULL;
           ibfd = ibfd->link.next, bfd_idx++)
        {
          if (sec_arr[bfd_idx] != NULL)
            free (sec_arr[bfd_idx]);
        }
      free (sec_arr);
    }

  return result;
}

static bool
process_input_bfds(struct bfd_link_info *info, Elf_Internal_Sym ***psym_arr,
                   asection ***sec_arr, bool *gaps)
{
  bfd *ibfd;
  int bfd_idx;
  extern const bfd_target spu_elf32_vec;

  for (ibfd = info->input_bfds, bfd_idx = 0;
       ibfd != NULL;
       ibfd = ibfd->link.next, bfd_idx++)
    {
      if (ibfd->xvec != &spu_elf32_vec)
        continue;

      if (!process_single_bfd(ibfd, bfd_idx, psym_arr, sec_arr, gaps, info))
        return false;
    }

  return true;
}

static bool
process_single_bfd(bfd *ibfd, int bfd_idx, Elf_Internal_Sym ***psym_arr,
                   asection ***sec_arr, bool *gaps, struct bfd_link_info *info)
{
  Elf_Internal_Shdr *symtab_hdr;
  size_t symcount;
  Elf_Internal_Sym *syms;

  symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
  symcount = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
  
  if (symcount == 0)
    {
      check_gaps_in_sections(ibfd, gaps);
      return true;
    }

  syms = load_symbols(ibfd, symtab_hdr, symcount);
  if (syms == NULL)
    return false;

  if (!process_symbols(ibfd, bfd_idx, psym_arr, sec_arr, syms, symcount, info))
    return false;

  for (asection *sec = ibfd->sections; sec != NULL && !*gaps; sec = sec->next)
    if (interesting_section (sec))
      *gaps |= check_function_ranges (sec, info);

  return true;
}

static void
check_gaps_in_sections(bfd *ibfd, bool *gaps)
{
  if (*gaps)
    return;

  for (asection *sec = ibfd->sections; sec != NULL && !*gaps; sec = sec->next)
    if (interesting_section (sec))
      {
        *gaps = true;
        break;
      }
}

static Elf_Internal_Sym *
load_symbols(bfd *ibfd, Elf_Internal_Shdr *symtab_hdr, size_t symcount)
{
  free (symtab_hdr->contents);
  symtab_hdr->contents = NULL;
  
  Elf_Internal_Sym *syms = bfd_elf_get_elf_syms (ibfd, symtab_hdr, symcount, 0,
                                                  NULL, NULL, NULL);
  symtab_hdr->contents = (void *) syms;
  return syms;
}

static bool
process_symbols(bfd *ibfd, int bfd_idx, Elf_Internal_Sym ***psym_arr,
                asection ***sec_arr, Elf_Internal_Sym *syms, size_t symcount,
                struct bfd_link_info *info)
{
  Elf_Internal_Sym **psyms;
  asection **psecs;

  psyms = bfd_malloc ((symcount + 1) * sizeof (*psyms));
  if (psyms == NULL)
    return false;
  psym_arr[bfd_idx] = psyms;

  psecs = bfd_malloc (symcount * sizeof (*psecs));
  if (psecs == NULL)
    return false;
  sec_arr[bfd_idx] = psecs;

  if (!filter_and_sort_symbols(ibfd, syms, symcount, psyms, psecs))
    return false;

  if (!allocate_stack_info(syms, psyms, psecs, symcount))
    return false;

  if (!install_function_info(syms, psyms, psecs, symcount))
    return false;

  return true;
}

static bool
filter_and_sort_symbols(bfd *ibfd, Elf_Internal_Sym *syms, size_t symcount,
                        Elf_Internal_Sym **psyms, asection **psecs)
{
  Elf_Internal_Sym **psy = psyms;
  asection **p = psecs;
  
  for (Elf_Internal_Sym *sy = syms; sy < syms + symcount; ++p, ++sy)
    {
      if (ELF_ST_TYPE (sy->st_info) == STT_NOTYPE ||
          ELF_ST_TYPE (sy->st_info) == STT_FUNC)
        {
          asection *s = bfd_section_from_elf_index (ibfd, sy->st_shndx);
          *p = s;
          if (s != NULL && interesting_section (s))
            *psy++ = sy;
        }
    }
  
  size_t filtered_count = psy - psyms;
  *psy = NULL;

  sort_syms_syms = syms;
  sort_syms_psecs = psecs;
  qsort (psyms, filtered_count, sizeof (*psyms), sort_syms);

  return true;
}

static bool
allocate_stack_info(Elf_Internal_Sym *syms, Elf_Internal_Sym **psyms,
                    asection **psecs, size_t symcount)
{
  for (Elf_Internal_Sym **psy = psyms; psy < psyms + symcount; )
    {
      asection *s = psecs[*psy - syms];
      Elf_Internal_Sym **psy2;

      for (psy2 = psy; ++psy2 < psyms + symcount; )
        if (psecs[*psy2 - syms] != s)
          break;

      if (!alloc_stack_info (s, psy2 - psy))
        return false;
      psy = psy2;
    }

  return true;
}

static bool
install_function_info(Elf_Internal_Sym *syms, Elf_Internal_Sym **psyms,
                      asection **psecs, size_t symcount)
{
  for (Elf_Internal_Sym **psy = psyms; psy < psyms + symcount; ++psy)
    {
      Elf_Internal_Sym *sy = *psy;
      if (ELF_ST_TYPE (sy->st_info) == STT_FUNC)
        {
          asection *s = psecs[sy - syms];
          if (!maybe_insert_function (s, sy, false, true))
            return false;
        }
    }

  return true;
}

static bool
process_gaps(struct bfd_link_info *info, Elf_Internal_Sym ***psym_arr,
             asection ***sec_arr)
{
  if (!mark_functions_via_relocations(info, psym_arr))
    return false;

  if (!install_global_functions(info, psym_arr, sec_arr))
    return false;

  if (!extend_function_ranges(info))
    return false;

  return true;
}

static bool
mark_functions_via_relocations(struct bfd_link_info *info,
                                Elf_Internal_Sym ***psym_arr)
{
  bfd *ibfd;
  int bfd_idx;

  for (ibfd = info->input_bfds, bfd_idx = 0;
       ibfd != NULL;
       ibfd = ibfd->link.next, bfd_idx++)
    {
      if (psym_arr[bfd_idx] == NULL)
        continue;

      for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
        if (!mark_functions_via_relocs (sec, info, false))
          return false;
    }

  return true;
}

static bool
install_global_functions(struct bfd_link_info *info,
                         Elf_Internal_Sym ***psym_arr,
                         asection ***sec_arr)
{
  bfd *ibfd;
  int bfd_idx;

  for (ibfd = info->input_bfds, bfd_idx = 0;
       ibfd != NULL;
       ibfd = ibfd->link.next, bfd_idx++)
    {
      Elf_Internal_Sym **psyms = psym_arr[bfd_idx];
      if (psyms == NULL)
        continue;

      asection **psecs = sec_arr[bfd_idx];
      Elf_Internal_Shdr *symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
      Elf_Internal_Sym *syms = (Elf_Internal_Sym *) symtab_hdr->contents;

      bool gaps = false;
      for (asection *sec = ibfd->sections; sec != NULL && !gaps; sec = sec->next)
        if (interesting_section (sec))
          gaps |= check_function_ranges (sec, info);
      
      if (!gaps)
        continue;

      for (Elf_Internal_Sym **psy = psyms; *psy != NULL; ++psy)
        {
          Elf_Internal_Sym *sy = *psy;
          asection *s = psecs[sy - syms];

          if (ELF_ST_TYPE (sy->st_info) != STT_FUNC &&
              ELF_ST_BIND (sy->st_info) == STB_GLOBAL)
            {
              if (!maybe_insert_function (s, sy, false, false))
                return false;
            }
        }
    }

  return true;
}

static bool
extend_function_ranges(struct bfd_link_info *info)
{
  extern const bfd_target spu_elf32_vec;

  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (ibfd->xvec != &spu_elf32_vec)
        continue;

      for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
        {
          if (!interesting_section (sec))
            continue;

          struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
          struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
          
          if (sinfo != NULL && sinfo->num_fun != 0)
            {
              bfd_vma hi = sec->size;
              for (int fun_idx = sinfo->num_fun; --fun_idx >= 0; )
                {
                  sinfo->fun[fun_idx].hi = hi;
                  hi = sinfo->fun[fun_idx].lo;
                }
              sinfo->fun[0].lo = 0;
            }
          else if (!pasted_function (sec))
            return false;
        }
    }

  return true;
}

/* Iterate over all function_info we have collected, calling DOIT on
   each node if ROOT_ONLY is false.  Only call DOIT on root nodes
   if ROOT_ONLY.  */

static bool
for_each_node (bool (*doit) (struct function_info *,
			     struct bfd_link_info *,
			     void *),
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

static bool
process_bfd_sections(bfd *ibfd,
		     bool (*doit) (struct function_info *,
				   struct bfd_link_info *,
				   void *),
		     struct bfd_link_info *info,
		     void *param,
		     int root_only)
{
  asection *sec;

  for (sec = ibfd->sections; sec != NULL; sec = sec->next)
    {
      if (!process_section_functions(sec, doit, info, param, root_only))
	return false;
    }
  return true;
}

static bool
process_section_functions(asection *sec,
			  bool (*doit) (struct function_info *,
					struct bfd_link_info *,
					void *),
			  struct bfd_link_info *info,
			  void *param,
			  int root_only)
{
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  int i;

  sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL)
    return true;

  sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL)
    return true;

  for (i = 0; i < sinfo->num_fun; ++i)
    {
      if (root_only && sinfo->fun[i].non_root)
	continue;

      if (!doit (&sinfo->fun[i], info, param))
	return false;
    }
  return true;
}

/* Transfer call info attached to struct function_info entries for
   all of a given function's sections to the first entry.  */

static bool
transfer_calls(struct function_info *fun,
               struct bfd_link_info *info ATTRIBUTE_UNUSED,
               void *param ATTRIBUTE_UNUSED)
{
    struct function_info *start = fun->start;
    struct call_info *call;
    struct call_info *call_next;

    if (start == NULL) {
        return true;
    }

    while (start->start != NULL) {
        start = start->start;
    }

    call = fun->call_list;
    while (call != NULL) {
        call_next = call->next;
        if (!insert_callee(start, call)) {
            free(call);
        }
        call = call_next;
    }

    fun->call_list = NULL;
    return true;
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
      if (call->fun)
        {
          call->fun->non_root = true;
          mark_non_root (call->fun, 0, 0);
        }
    }
  return true;
}

/* Remove cycles from the call graph.  Set depth of nodes.  */

static bool
remove_cycles(struct function_info *fun,
              struct bfd_link_info *info,
              void *param)
{
    if (!fun || !param || !info) {
        return false;
    }

    unsigned int *depth_ptr = (unsigned int *)param;
    unsigned int depth = *depth_ptr;
    unsigned int max_depth = depth;

    fun->depth = depth;
    fun->visit2 = true;
    fun->marking = true;

    struct call_info **callp = &fun->call_list;
    struct call_info *call;

    while ((call = *callp) != NULL) {
        unsigned int call_depth = depth + (call->is_pasted ? 0 : 1);
        call->max_depth = call_depth;

        if (!call->fun) {
            callp = &call->next;
            continue;
        }

        if (!call->fun->visit2) {
            if (!remove_cycles(call->fun, info, &call->max_depth)) {
                fun->marking = false;
                return false;
            }
            if (max_depth < call->max_depth) {
                max_depth = call->max_depth;
            }
        } else if (call->fun->marking) {
            handle_cycle_detection(fun, call, info);
            call->broken_cycle = true;
        }

        callp = &call->next;
    }

    fun->marking = false;
    *depth_ptr = max_depth;
    return true;
}

static void
handle_cycle_detection(struct function_info *fun,
                      struct call_info *call,
                      struct bfd_link_info *info)
{
    struct spu_link_hash_table *htab = spu_hash_table(info);
    
    if (!htab || !htab->params) {
        return;
    }

    if (!htab->params->auto_overlay && htab->params->stack_analysis) {
        const char *f1 = func_name(fun);
        const char *f2 = func_name(call->fun);

        if (f1 && f2 && info->callbacks && info->callbacks->info) {
            info->callbacks->info(_("stack analysis will ignore the call "
                                   "from %s to %s\n"),
                                 f1, f2);
        }
    }
}

/* Check that we actually visited all nodes in remove_cycles.  If we
   didn't, then there is some cycle in the call graph not attached to
   any root node.  Arbitrarily choose a node in the cycle as a new
   root and break the cycle.  */

static bool
mark_detached_root(struct function_info *fun,
                   struct bfd_link_info *info,
                   void *param)
{
    if (fun == NULL || param == NULL) {
        return false;
    }
    
    if (fun->visit2) {
        return true;
    }
    
    fun->non_root = false;
    unsigned int *counter = (unsigned int *)param;
    *counter = 0;
    
    return remove_cycles(fun, info, param);
}

/* Populate call_list for each function.  */

static bool
build_call_tree (struct bfd_link_info *info)
{
  bfd *ibfd;
  unsigned int depth;
  extern const bfd_target spu_elf32_vec;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      asection *sec;

      if (ibfd->xvec != &spu_elf32_vec)
        continue;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
        {
          if (!mark_functions_via_relocs (sec, info, true))
            return false;
        }
    }

  if (!spu_hash_table (info)->params->auto_overlay)
    {
      if (!for_each_node (transfer_calls, info, 0, false))
        return false;
    }

  if (!for_each_node (mark_non_root, info, 0, false))
    return false;

  depth = 0;
  if (!for_each_node (remove_cycles, info, &depth, true))
    return false;

  return for_each_node (mark_detached_root, info, &depth, false);
}

/* qsort predicate to sort calls by priority, max_depth then count.  */

static int
sort_calls (const void *a, const void *b)
{
  const struct call_info *c1 = *(const struct call_info *const *)a;
  const struct call_info *c2 = *(const struct call_info *const *)b;
  int delta;

  delta = c2->priority - c1->priority;
  if (delta != 0)
    return delta;

  delta = c2->max_depth - c1->max_depth;
  if (delta != 0)
    return delta;

  delta = c2->count - c1->count;
  if (delta != 0)
    return delta;

  if (a < b)
    return -1;
  if (a > b)
    return 1;
  return 0;
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

static bool
mark_overlay_section (struct function_info *fun,
		      struct bfd_link_info *info,
		      void *param)
{
  struct _mos_param *mos_param = param;
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (fun->visit4)
    return true;

  fun->visit4 = true;
  
  if (!fun->sec->linker_mark && should_mark_section(fun, htab))
    {
      if (!mark_text_section(fun, htab, mos_param))
        return false;
    }

  if (!sort_and_process_calls(fun, info, param))
    return false;

  check_entry_code(fun, info);
  
  return true;
}

static bool
should_mark_section(struct function_info *fun, struct spu_link_hash_table *htab)
{
  if (htab->params->ovly_flavour != ovly_soft_icache)
    return true;
    
  if (htab->params->non_ia_text)
    return true;
    
  if (startswith(fun->sec->name, ".text.ia."))
    return true;
    
  if (strcmp(fun->sec->name, ".init") == 0)
    return true;
    
  if (strcmp(fun->sec->name, ".fini") == 0)
    return true;
    
  return false;
}

static bool
mark_text_section(struct function_info *fun, 
                  struct spu_link_hash_table *htab,
                  struct _mos_param *mos_param)
{
  unsigned int size;
  
  fun->sec->linker_mark = 1;
  fun->sec->gc_mark = 1;
  fun->sec->segment_mark = 0;
  fun->sec->flags |= SEC_CODE;
  
  size = fun->sec->size;
  
  if (htab->params->auto_overlay & OVERLAY_RODATA)
    {
      if (!process_rodata_section(fun, htab, &size))
        return false;
    }
    
  if (mos_param->max_overlay_size < size)
    mos_param->max_overlay_size = size;
    
  return true;
}

static bool
process_rodata_section(struct function_info *fun, 
                       struct spu_link_hash_table *htab,
                       unsigned int *size)
{
  char *name = create_rodata_name(fun->sec->name);
  
  if (name == NULL)
    return false;
    
  asection *rodata = find_rodata_section(fun->sec, name);
  free(name);
  
  if (rodata != NULL)
    {
      attach_rodata_section(fun, rodata, htab, size);
    }
    
  return true;
}

static char *
create_rodata_name(const char *sec_name)
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

static asection *
find_rodata_section(asection *sec, const char *name)
{
  asection *group_sec = elf_section_data(sec)->next_in_group;
  
  if (group_sec == NULL)
    return bfd_get_section_by_name(sec->owner, name);
    
  while (group_sec != NULL && group_sec != sec)
    {
      if (strcmp(group_sec->name, name) == 0)
        return group_sec;
      group_sec = elf_section_data(group_sec)->next_in_group;
    }
    
  return NULL;
}

static void
attach_rodata_section(struct function_info *fun, 
                     asection *rodata,
                     struct spu_link_hash_table *htab,
                     unsigned int *size)
{
  fun->rodata = rodata;
  *size += rodata->size;
  
  if (htab->params->line_size != 0 && *size > htab->params->line_size)
    {
      *size -= rodata->size;
      fun->rodata = NULL;
    }
  else
    {
      rodata->linker_mark = 1;
      rodata->gc_mark = 1;
      rodata->flags &= ~SEC_CODE;
    }
}

static bool
sort_and_process_calls(struct function_info *fun, 
                      struct bfd_link_info *info,
                      void *param)
{
  struct call_info *call;
  unsigned int count = 0;
  
  for (call = fun->call_list; call != NULL; call = call->next)
    count++;
    
  if (count > 1)
    {
      if (!sort_call_list(fun, count))
        return false;
    }
    
  for (call = fun->call_list; call != NULL; call = call->next)
    {
      if (call->is_pasted)
        {
          BFD_ASSERT(!fun->sec->segment_mark);
          fun->sec->segment_mark = 1;
        }
      if (!call->broken_cycle)
        {
          if (!mark_overlay_section(call->fun, info, param))
            return false;
        }
    }
    
  return true;
}

static bool
sort_call_list(struct function_info *fun, unsigned int count)
{
  struct call_info **calls = bfd_malloc(count * sizeof(*calls));
  struct call_info *call;
  unsigned int i;
  
  if (calls == NULL)
    return false;
    
  for (i = 0, call = fun->call_list; call != NULL; call = call->next)
    calls[i++] = call;
    
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

static void
check_entry_code(struct function_info *fun, struct bfd_link_info *info)
{
  bfd_vma fun_addr = fun->lo + fun->sec->output_offset + 
                     fun->sec->output_section->vma;
                     
  if (fun_addr == info->output_bfd->start_address ||
      startswith(fun->sec->output_section->name, ".ovl.init"))
    {
      fun->sec->linker_mark = 0;
      if (fun->rodata != NULL)
        fun->rodata->linker_mark = 0;
    }
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
  struct call_info *call;
  struct _uos_param *uos_param = param;
  unsigned int excluded;

  if (fun->visit5)
    return true;

  fun->visit5 = true;

  excluded = (fun->sec == uos_param->exclude_input_section ||
              fun->sec->output_section == uos_param->exclude_output_section) ? 1 : 0;

  if (RECURSE_UNMARK)
    uos_param->clearing += excluded;

  if ((RECURSE_UNMARK && uos_param->clearing) || (!RECURSE_UNMARK && excluded))
    {
      fun->sec->linker_mark = 0;
      if (fun->rodata)
	fun->rodata->linker_mark = 0;
    }

  for (call = fun->call_list; call != NULL; call = call->next)
    if (!call->broken_cycle &&
	!unmark_overlay_section (call->fun, info, param))
      return false;

  if (RECURSE_UNMARK)
    uos_param->clearing -= excluded;
  
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
    struct call_info *call;
    unsigned int size;

    if (fun->visit6)
        return true;

    fun->visit6 = true;

    if (!fun->sec->linker_mark || !fun->sec->gc_mark || fun->sec->segment_mark)
        return true;

    size = fun->sec->size;
    if (fun->rodata)
        size += fun->rodata->size;

    if (size > lib_param->lib_size)
        return true;

    *lib_param->lib_sections++ = fun->sec;
    fun->sec->gc_mark = 0;

    if (fun->rodata && fun->rodata->linker_mark && fun->rodata->gc_mark) {
        *lib_param->lib_sections++ = fun->rodata;
        fun->rodata->gc_mark = 0;
    } else {
        *lib_param->lib_sections++ = NULL;
    }

    for (call = fun->call_list; call != NULL; call = call->next) {
        if (!call->broken_cycle)
            collect_lib_sections(call->fun, info, param);
    }

    return true;
}

/* qsort predicate to sort sections by call count.  */

static int
sort_lib (const void *a, const void *b)
{
  asection *const *s1 = a;
  asection *const *s2 = b;
  int delta = 0;

  delta -= calculate_total_call_count(*s1);
  delta += calculate_total_call_count(*s2);

  if (delta != 0)
    return delta;

  return (int)(s1 - s2);
}

static int
calculate_total_call_count(asection *section)
{
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  int total = 0;
  int i;

  sec_data = spu_elf_section_data(section);
  if (sec_data == NULL)
    return 0;

  sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL)
    return 0;

  for (i = 0; i < sinfo->num_fun; ++i)
    total += sinfo->fun[i].call_count;

  return total;
}

/* Remove some sections from those marked to be in overlays.  Choose
   those that are called from many places, likely library functions.  */

static unsigned int
auto_ovl_lib_functions (struct bfd_link_info *info, unsigned int lib_size)
{
  bfd *ibfd;
  asection **lib_sections;
  unsigned int i, lib_count;
  struct _cl_param collect_lib_param;
  struct function_info dummy_caller;
  struct spu_link_hash_table *htab;
  extern const bfd_target spu_elf32_vec;

  memset (&dummy_caller, 0, sizeof (dummy_caller));
  
  lib_count = 0;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      asection *sec;

      if (ibfd->xvec != &spu_elf32_vec)
        continue;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
        if (sec->linker_mark
            && sec->size < lib_size
            && (sec->flags & SEC_CODE) != 0)
          lib_count += 1;
    }
  
  lib_sections = bfd_malloc (lib_count * 2 * sizeof (*lib_sections));
  if (lib_sections == NULL)
    return (unsigned int) -1;
    
  collect_lib_param.lib_size = lib_size;
  collect_lib_param.lib_sections = lib_sections;
  
  if (!for_each_node (collect_lib_sections, info, &collect_lib_param, true))
    {
      free (lib_sections);
      return (unsigned int) -1;
    }
    
  lib_count = (collect_lib_param.lib_sections - lib_sections) / 2;

  if (lib_count > 1)
    qsort (lib_sections, lib_count, 2 * sizeof (*lib_sections), sort_lib);

  htab = spu_hash_table (info);
  
  for (i = 0; i < lib_count; i++)
    {
      if (process_lib_section (lib_sections, i, &lib_size, htab, &dummy_caller) == (unsigned int) -1)
        {
          cleanup_dummy_caller (&dummy_caller);
          free (lib_sections);
          return (unsigned int) -1;
        }
    }
    
  cleanup_dummy_caller (&dummy_caller);
  
  for (i = 0; i < 2 * lib_count; i++)
    if (lib_sections[i])
      lib_sections[i]->gc_mark = 1;
      
  free (lib_sections);
  return lib_size;
}

static unsigned int
process_lib_section (asection **lib_sections, unsigned int i, unsigned int *lib_size,
                     struct spu_link_hash_table *htab, struct function_info *dummy_caller)
{
  unsigned int tmp, stub_size;
  asection *sec;
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;

  sec = lib_sections[2 * i];
  tmp = sec->size;
  
  if (lib_sections[2 * i + 1])
    tmp += lib_sections[2 * i + 1]->size;
    
  stub_size = calculate_stub_size (sec, htab, dummy_caller);
  
  if (tmp + stub_size < *lib_size)
    {
      lib_sections[2 * i]->linker_mark = 0;
      if (lib_sections[2 * i + 1])
        lib_sections[2 * i + 1]->linker_mark = 0;
      *lib_size -= tmp + stub_size;
      
      remove_unneeded_stubs (dummy_caller, lib_size, htab);
      
      if (add_new_stubs (sec, dummy_caller) == (unsigned int) -1)
        return (unsigned int) -1;
    }
    
  return 0;
}

static unsigned int
calculate_stub_size (asection *sec, struct spu_link_hash_table *htab,
                     struct function_info *dummy_caller)
{
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  unsigned int stub_size = 0;
  int k;
  struct call_info *call;

  sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL)
    return 0;
    
  sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL)
    return 0;

  for (k = 0; k < sinfo->num_fun; ++k)
    {
      for (call = sinfo->fun[k].call_list; call; call = call->next)
        {
          if (call->fun->sec->linker_mark && !find_callee (dummy_caller, call->fun))
            stub_size += ovl_stub_size (htab->params);
        }
    }
    
  return stub_size;
}

static int
find_callee (struct function_info *caller, struct function_info *fun)
{
  struct call_info *p;
  
  for (p = caller->call_list; p; p = p->next)
    if (p->fun == fun)
      return 1;
      
  return 0;
}

static void
remove_unneeded_stubs (struct function_info *dummy_caller, unsigned int *lib_size,
                       struct spu_link_hash_table *htab)
{
  struct call_info **pp, *p;
  
  pp = &dummy_caller->call_list;
  while ((p = *pp) != NULL)
    {
      if (!p->fun->sec->linker_mark)
        {
          *lib_size += ovl_stub_size (htab->params);
          *pp = p->next;
          free (p);
        }
      else
        {
          pp = &p->next;
        }
    }
}

static unsigned int
add_new_stubs (asection *sec, struct function_info *dummy_caller)
{
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  int k;
  struct call_info *call;

  sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL)
    return 0;
    
  sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL)
    return 0;

  for (k = 0; k < sinfo->num_fun; ++k)
    {
      for (call = sinfo->fun[k].call_list; call; call = call->next)
        {
          if (call->fun->sec->linker_mark)
            {
              struct call_info *callee;
              callee = bfd_malloc (sizeof (*callee));
              if (callee == NULL)
                return (unsigned int) -1;
              *callee = *call;
              if (!insert_callee (dummy_caller, callee))
                free (callee);
            }
        }
    }
    
  return 0;
}

static void
cleanup_dummy_caller (struct function_info *dummy_caller)
{
  while (dummy_caller->call_list != NULL)
    {
      struct call_info *call = dummy_caller->call_list;
      dummy_caller->call_list = call->next;
      free (call);
    }
}

/* Build an array of overlay sections.  The deepest node's section is
   added first, then its parent node's section, then everything called
   from the parent section.  The idea being to group sections to
   minimise calls between different overlays.  */

static bool
collect_overlays (struct function_info *fun,
		  struct bfd_link_info *info,
		  void *param)
{
  asection ***ovly_sections = param;

  if (fun->visit7)
    return true;

  fun->visit7 = true;
  
  struct call_info *call;
  for (call = fun->call_list; call != NULL; call = call->next)
    {
      if (!call->is_pasted && !call->broken_cycle)
        {
          if (!collect_overlays (call->fun, info, ovly_sections))
            return false;
          break;
        }
    }

  bool added_fun = false;
  if (fun->sec->linker_mark && fun->sec->gc_mark)
    {
      fun->sec->gc_mark = 0;
      *(*ovly_sections)++ = fun->sec;
      
      if (fun->rodata && fun->rodata->linker_mark && fun->rodata->gc_mark)
        {
          fun->rodata->gc_mark = 0;
          *(*ovly_sections)++ = fun->rodata;
        }
      else
        {
          *(*ovly_sections)++ = NULL;
        }
      
      added_fun = true;

      if (fun->sec->segment_mark)
        {
          struct function_info *call_fun = fun;
          while (call_fun->sec->segment_mark)
            {
              struct call_info *pasted_call = NULL;
              for (call = call_fun->call_list; call != NULL; call = call->next)
                {
                  if (call->is_pasted)
                    {
                      pasted_call = call;
                      break;
                    }
                }
              
              if (pasted_call == NULL)
                abort ();
              
              call_fun = pasted_call->fun;
              call_fun->sec->gc_mark = 0;
              if (call_fun->rodata)
                call_fun->rodata->gc_mark = 0;
            }
        }
    }

  for (call = fun->call_list; call != NULL; call = call->next)
    {
      if (!call->broken_cycle && !collect_overlays (call->fun, info, ovly_sections))
        return false;
    }

  if (added_fun)
    {
      struct _spu_elf_section_data *sec_data = spu_elf_section_data (fun->sec);
      if (sec_data != NULL)
        {
          struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
          if (sinfo != NULL)
            {
              for (int i = 0; i < sinfo->num_fun; ++i)
                {
                  if (!collect_overlays (&sinfo->fun[i], info, ovly_sections))
                    return false;
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

static bool
sum_stack (struct function_info *fun,
	   struct bfd_link_info *info,
	   void *param)
{
  struct _sum_stack_param *sum_stack_param = param;
  struct spu_link_hash_table *htab;
  struct call_info *call;
  struct function_info *max = NULL;
  size_t stack, cum_stack;
  bool has_call = false;

  if (fun == NULL || info == NULL || param == NULL)
    return false;

  cum_stack = fun->stack;
  sum_stack_param->cum_stack = cum_stack;
  
  if (fun->visit3)
    return true;

  for (call = fun->call_list; call; call = call->next)
    {
      if (call->broken_cycle)
	continue;
      
      if (!call->is_pasted)
	has_call = true;
      
      if (!sum_stack (call->fun, info, sum_stack_param))
	return false;
      
      stack = sum_stack_param->cum_stack;
      
      if (!call->is_tail || call->is_pasted || call->fun->start != NULL)
	stack += fun->stack;
      
      if (cum_stack < stack)
	{
	  cum_stack = stack;
	  max = call->fun;
	}
    }

  sum_stack_param->cum_stack = cum_stack;
  stack = fun->stack;
  fun->stack = cum_stack;
  fun->visit3 = true;

  if (!fun->non_root && sum_stack_param->overall_stack < cum_stack)
    sum_stack_param->overall_stack = cum_stack;

  htab = spu_hash_table (info);
  if (htab == NULL)
    return false;

  if (htab->params->auto_overlay)
    return true;

  const char *f1 = func_name (fun);
  if (f1 == NULL)
    return false;

  if (htab->params->stack_analysis)
    {
      if (!fun->non_root)
	info->callbacks->info ("  %s: 0x%v\n", f1, (bfd_vma) cum_stack);
      
      info->callbacks->minfo ("%s: 0x%v 0x%v\n",
			      f1, (bfd_vma) stack, (bfd_vma) cum_stack);

      if (has_call)
	{
	  info->callbacks->minfo (_("  calls:\n"));
	  for (call = fun->call_list; call; call = call->next)
	    {
	      if (call->is_pasted || call->broken_cycle)
		continue;
	      
	      const char *f2 = func_name (call->fun);
	      if (f2 == NULL)
		continue;
	      
	      const char *ann1 = (call->fun == max) ? "*" : " ";
	      const char *ann2 = call->is_tail ? "t" : " ";
	      info->callbacks->minfo ("   %s%s %s\n", ann1, ann2, f2);
	    }
	}
    }

  if (!sum_stack_param->emit_stack_syms)
    return true;

  size_t name_len = 18 + strlen (f1);
  char *name = bfd_malloc (name_len);
  if (name == NULL)
    return false;

  if (fun->global || ELF_ST_BIND (fun->u.sym->st_info) == STB_GLOBAL)
    snprintf (name, name_len, "__stack_%s", f1);
  else
    snprintf (name, name_len, "__stack_%x_%s", fun->sec->id & 0xffffffff, f1);

  struct elf_link_hash_entry *h = elf_link_hash_lookup (&htab->elf, name, true, true, false);
  free (name);
  
  if (h == NULL)
    return true;

  if (h->root.type == bfd_link_hash_new ||
      h->root.type == bfd_link_hash_undefined ||
      h->root.type == bfd_link_hash_undefweak)
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

  return true;
}

/* SEC is part of a pasted function.  Return the call_info for the
   next section of this function.  */

static struct call_info *
find_pasted_call (asection *sec)
{
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  struct call_info *call;
  int k;

  if (sec == NULL)
    return NULL;

  sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL)
    return NULL;

  sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL)
    return NULL;

  for (k = 0; k < sinfo->num_fun; ++k)
    {
      if (sinfo->fun == NULL)
        return NULL;
        
      for (call = sinfo->fun[k].call_list; call != NULL; call = call->next)
        {
          if (call->is_pasted)
            return call;
        }
    }

  return NULL;
}

/* qsort predicate to sort bfds by file name.  */

static int sort_bfds(const void *a, const void *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    
    bfd *const *abfd1 = a;
    bfd *const *abfd2 = b;
    
    if (*abfd1 == NULL || *abfd2 == NULL) {
        if (*abfd1 == NULL && *abfd2 == NULL) {
            return 0;
        }
        return (*abfd1 == NULL) ? -1 : 1;
    }
    
    const char *filename1 = bfd_get_filename(*abfd1);
    const char *filename2 = bfd_get_filename(*abfd2);
    
    if (filename1 == NULL || filename2 == NULL) {
        if (filename1 == NULL && filename2 == NULL) {
            return 0;
        }
        return (filename1 == NULL) ? -1 : 1;
    }
    
    return filename_cmp(filename1, filename2);
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

  for (j = base; j < count && ovly_map[j] == ovlynum; j++)
    {
      asection *sec = ovly_sections[2 * j];
      if (write_section_info(script, sec, info) != 0)
        return -1;
      
      if (sec->segment_mark)
        {
          if (process_pasted_calls(script, sec, info, 0) != 0)
            return -1;
        }
    }

  for (j = base; j < count && ovly_map[j] == ovlynum; j++)
    {
      asection *sec = ovly_sections[2 * j + 1];
      if (sec != NULL)
        {
          if (write_section_info(script, sec, info) != 0)
            return -1;
        }

      sec = ovly_sections[2 * j];
      if (sec->segment_mark)
        {
          if (process_pasted_calls(script, sec, info, 1) != 0)
            return -1;
        }
    }

  return j;
}

static int
write_section_info(FILE *script, asection *sec, struct bfd_link_info *info)
{
  if (sec == NULL)
    return 0;
    
  const char *archive_name = "";
  if (sec->owner->my_archive != NULL)
    archive_name = bfd_get_filename(sec->owner->my_archive);
    
  if (fprintf(script, "   %s%c%s (%s)\n",
              archive_name,
              info->path_separator,
              bfd_get_filename(sec->owner),
              sec->name) <= 0)
    return -1;
    
  return 0;
}

static int
process_pasted_calls(FILE *script, asection *sec, struct bfd_link_info *info, int use_rodata)
{
  struct call_info *call = find_pasted_call(sec);
  
  while (call != NULL)
    {
      struct function_info *call_fun = call->fun;
      if (call_fun == NULL)
        break;
        
      asection *target_sec = use_rodata ? call_fun->rodata : call_fun->sec;
      
      if (write_section_info(script, target_sec, info) != 0)
        return -1;
      
      call = find_next_pasted_call(call_fun->call_list);
    }
    
  return 0;
}

static struct call_info *
find_next_pasted_call(struct call_info *call_list)
{
  for (struct call_info *call = call_list; call != NULL; call = call->next)
    {
      if (call->is_pasted)
        return call;
    }
  return NULL;
}

/* Handle --auto-overlay.  */

static void
spu_elf_auto_overlay (struct bfd_link_info *info)
{
  bfd *ibfd;
  bfd **bfd_arr = NULL;
  struct elf_segment_map *m;
  unsigned int fixed_size, lo, hi;
  unsigned int reserved;
  struct spu_link_hash_table *htab;
  unsigned int base, i, count, bfd_count;
  unsigned int region, ovlynum;
  asection **ovly_sections = NULL;
  asection **ovly_p;
  unsigned int *ovly_map = NULL;
  FILE *script = NULL;
  unsigned int total_overlay_size, overlay_size;
  const char *ovly_mgr_entry;
  struct elf_link_hash_entry *h;
  struct _mos_param mos_param;
  struct _uos_param uos_param;
  struct function_info dummy_caller;

  memset(&dummy_caller, 0, sizeof(dummy_caller));
  
  lo = (unsigned int) -1;
  hi = 0;
  for (m = elf_seg_map (info->output_bfd); m != NULL; m = m->next)
    {
      if (m->p_type != PT_LOAD)
        continue;
      for (i = 0; i < m->count; i++)
        {
          if (m->sections[i]->size == 0)
            continue;
          if (m->sections[i]->vma < lo)
            lo = m->sections[i]->vma;
          if (m->sections[i]->vma + m->sections[i]->size - 1 > hi)
            hi = m->sections[i]->vma + m->sections[i]->size - 1;
        }
    }
  fixed_size = hi + 1 - lo;

  if (!discover_functions (info))
    goto err_exit;

  if (!build_call_tree (info))
    goto err_exit;

  htab = spu_hash_table (info);
  reserved = htab->params->auto_overlay_reserved;
  if (reserved == 0)
    {
      struct _sum_stack_param sum_stack_param;
      sum_stack_param.emit_stack_syms = 0;
      sum_stack_param.overall_stack = 0;
      if (!for_each_node (sum_stack, info, &sum_stack_param, true))
        goto err_exit;
      reserved = sum_stack_param.overall_stack + htab->params->extra_stack_space;
    }

  if (fixed_size + reserved <= htab->local_store
      && htab->params->ovly_flavour != ovly_soft_icache)
    {
      htab->params->auto_overlay = 0;
      return;
    }

  uos_param.exclude_input_section = 0;
  uos_param.exclude_output_section = bfd_get_section_by_name (info->output_bfd, ".interrupt");

  ovly_mgr_entry = (htab->params->ovly_flavour == ovly_soft_icache) 
                   ? "__icache_br_handler" : "__ovly_load";
  
  h = elf_link_hash_lookup (&htab->elf, ovly_mgr_entry, false, false, false);
  if (h != NULL
      && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)
      && h->def_regular)
    {
      uos_param.exclude_input_section = h->root.u.def.section;
    }
  else
    {
      fixed_size += (*htab->params->spu_elf_load_ovl_mgr) ();
    }

  mos_param.max_overlay_size = 0;
  if (!for_each_node (mark_overlay_section, info, &mos_param, true))
    goto err_exit;

  uos_param.clearing = 0;
  if ((uos_param.exclude_input_section || uos_param.exclude_output_section)
      && !for_each_node (unmark_overlay_section, info, &uos_param, true))
    goto err_exit;

  bfd_count = 0;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    ++bfd_count;
  
  bfd_arr = bfd_malloc (bfd_count * sizeof (*bfd_arr));
  if (bfd_arr == NULL)
    goto err_exit;

  count = 0;
  bfd_count = 0;
  total_overlay_size = 0;
  
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      extern const bfd_target spu_elf32_vec;
      asection *sec;
      unsigned int old_count;

      if (ibfd->xvec != &spu_elf32_vec)
        continue;

      old_count = count;
      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
        {
          if (sec->linker_mark)
            {
              if ((sec->flags & SEC_CODE) != 0)
                count += 1;
              fixed_size -= sec->size;
              total_overlay_size += sec->size;
            }
          else if ((sec->flags & (SEC_ALLOC | SEC_LOAD)) == (SEC_ALLOC | SEC_LOAD)
                   && sec->output_section->owner == info->output_bfd
                   && startswith (sec->output_section->name, ".ovl.init"))
            {
              fixed_size -= sec->size;
            }
        }
      if (count != old_count)
        bfd_arr[bfd_count++] = ibfd;
    }

  if (bfd_count > 1)
    {
      bool ok = true;
      qsort (bfd_arr, bfd_count, sizeof (*bfd_arr), sort_bfds);
      
      for (i = 1; i < bfd_count; ++i)
        {
          if (filename_cmp (bfd_get_filename (bfd_arr[i - 1]),
                            bfd_get_filename (bfd_arr[i])) != 0)
            continue;
            
          if (bfd_arr[i - 1]->my_archive != bfd_arr[i]->my_archive)
            continue;
            
          if (bfd_arr[i - 1]->my_archive && bfd_arr[i]->my_archive)
            info->callbacks->einfo (_("%s duplicated in %s\n"),
                                  bfd_get_filename (bfd_arr[i]),
                                  bfd_get_filename (bfd_arr[i]->my_archive));
          else
            info->callbacks->einfo (_("%s duplicated\n"),
                                  bfd_get_filename (bfd_arr[i]));
          ok = false;
        }
      
      if (!ok)
        {
          info->callbacks->einfo (_("sorry, no support for duplicate "
                                   "object files in auto-overlay script\n"));
          bfd_set_error (bfd_error_bad_value);
          goto err_exit;
        }
    }
  
  free (bfd_arr);
  bfd_arr = NULL;

  fixed_size += reserved;
  fixed_size += htab->non_ovly_stub * ovl_stub_size (htab->params);
  
  if (fixed_size + mos_param.max_overlay_size <= htab->local_store)
    {
      if (htab->params->ovly_flavour == ovly_soft_icache)
        {
          fixed_size += htab->non_ovly_stub * 16;
          fixed_size += 16 << htab->num_lines_log2;
          fixed_size += 16 << htab->num_lines_log2;
          fixed_size += 16 << (htab->fromelem_size_log2 + htab->num_lines_log2);
          fixed_size += 16;
        }
      else
        {
          ovlynum = (total_overlay_size * 2 * htab->params->num_lines
                     / (htab->local_store - fixed_size));
          fixed_size += ovlynum * 16 + 16 + 4 + 16;
        }
    }

  if (fixed_size + mos_param.max_overlay_size > htab->local_store)
    {
      info->callbacks->einfo (_("non-overlay size of 0x%v plus maximum overlay "
                               "size of 0x%v exceeds local store\n"),
                             (bfd_vma) fixed_size,
                             (bfd_vma) mos_param.max_overlay_size);
    }
  else if (fixed_size < htab->params->auto_overlay_fixed)
    {
      unsigned int max_fixed, lib_size;
      max_fixed = htab->local_store - mos_param.max_overlay_size;
      if (max_fixed > htab->params->auto_overlay_fixed)
        max_fixed = htab->params->auto_overlay_fixed;
      lib_size = max_fixed - fixed_size;
      lib_size = auto_ovl_lib_functions (info, lib_size);
      if (lib_size == (unsigned int) -1)
        goto err_exit;
      fixed_size = max_fixed - lib_size;
    }

  ovly_sections = bfd_malloc (2 * count * sizeof (*ovly_sections));
  if (ovly_sections == NULL)
    goto err_exit;
    
  ovly_p = ovly_sections;
  if (!for_each_node (collect_overlays, info, &ovly_p, true))
    goto err_exit;
    
  count = (size_t) (ovly_p - ovly_sections) / 2;
  ovly_map = bfd_malloc (count * sizeof (*ovly_map));
  if (ovly_map == NULL)
    goto err_exit;

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
          asection *sec, *rosec;
          unsigned int tmp, rotmp;
          unsigned int num_stubs;
          struct call_info *call, *pasty;
          struct _spu_elf_section_data *sec_data;
          struct spu_elf_stack_info *sinfo;
          unsigned int k;

          sec = ovly_sections[2 * i];
          tmp = align_power (size, sec->alignment_power) + sec->size;
          rotmp = rosize;
          rosec = ovly_sections[2 * i + 1];
          
          if (rosec != NULL)
            {
              rotmp = align_power (rotmp, rosec->alignment_power) + rosec->size;
              if (roalign < rosec->alignment_power)
                roalign = rosec->alignment_power;
            }
            
          if (align_power (tmp, roalign) + rotmp > overlay_size)
            break;
            
          if (sec->segment_mark)
            {
              pasty = find_pasted_call (sec);
              while (pasty != NULL)
                {
                  struct function_info *call_fun = pasty->fun;
                  tmp = align_power (tmp, call_fun->sec->alignment_power) + call_fun->sec->size;
                  if (call_fun->rodata)
                    {
                      rotmp = align_power (rotmp, call_fun->rodata->alignment_power) + call_fun->rodata->size;
                      if (roalign < rosec->alignment_power)
                        roalign = rosec->alignment_power;
                    }
                  for (pasty = call_fun->call_list; pasty; pasty = pasty->next)
                    if (pasty->is_pasted)
                      break;
                }
            }
            
          if (align_power (tmp, roalign) + rotmp > overlay_size)
            break;

          pasty = NULL;
          sec_data = spu_elf_section_data (sec);
          sinfo = sec_data->u.i.stack_info;
          
          for (k = 0; k < (unsigned) sinfo->num_fun; ++k)
            {
              for (call = sinfo->fun[k].call_list; call; call = call->next)
                {
                  if (call->is_pasted)
                    {
                      BFD_ASSERT (pasty == NULL);
                      pasty = call;
                    }
                  else if (call->fun->sec->linker_mark)
                    {
                      if (!copy_callee (&dummy_caller, call))
                        goto err_exit;
                    }
                }
            }
            
          while (pasty != NULL)
            {
              struct function_info *call_fun = pasty->fun;
              pasty = NULL;
              for (call = call_fun->call_list; call; call = call->next)
                {
                  if (call->is_pasted)
                    {
                      BFD_ASSERT (pasty == NULL);
                      pasty = call;
                    }
                  else if (!copy_callee (&dummy_caller, call))
                    goto err_exit;
                }
            }

          num_stubs = 0;
          for (call = dummy_caller.call_list; call; call = call->next)
            {
              unsigned int stub_delta = 1;
              if (htab->params->ovly_flavour == ovly_soft_icache)
                stub_delta = call->count;
              num_stubs += stub_delta;

              for (k = base; k < i + 1; k++)
                {
                  if (call->fun->sec == ovly_sections[2 * k])
                    {
                      num_stubs -= stub_delta;
                      break;
                    }
                }
            }
            
          if (htab->params->ovly_flavour == ovly_soft_icache
              && num_stubs > htab->params->max_branch)
            break;
            
          if (align_power (tmp, roalign) + rotmp
              + num_stubs * ovl_stub_size (htab->params) > overlay_size)
            break;
            
          size = tmp;
          rosize = rotmp;
        }

      if (i == base)
        {
          info->callbacks->einfo (_("%pB:%pA%s exceeds overlay size\n"),
                                ovly_sections[2 * i]->owner,
                                ovly_sections[2 * i],
                                ovly_sections[2 * i + 1] ? " + rodata" : "");
          bfd_set_error (bfd_error_bad_value);
          goto err_exit;
        }

      while (dummy_caller.call_list != NULL)
        {
          struct call_info *call = dummy_caller.call_list;
          dummy_caller.call_list = call->next;
          free (call);
        }

      ++ovlynum;
      while (base < i)
        ovly_map[base++] = ovlynum;
    }

  script = htab->params->spu_elf_open_overlay_script ();
  if (script == NULL)
    goto err_exit;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      if (fprintf (script, "SECTIONS\n{\n") <= 0)
        goto file_err;

      if (fprintf (script,
                   " . = ALIGN (%u);\n"
                   " .ovl.init : { *(.ovl.init) }\n"
                   " . = ABSOLUTE (ADDR (.ovl.init));\n",
                   htab->params->line_size) <= 0)
        goto file_err;

      base = 0;
      ovlynum = 1;
      while (base < count)
        {
          unsigned int indx = ovlynum - 1;
          unsigned int vma, lma;

          vma = (indx & (htab->params->num_lines - 1)) << htab->line_size_log2;
          lma = vma + (((indx >> htab->num_lines_log2) + 1) << 18);

          if (fprintf (script, " .ovly%u ABSOLUTE (ADDR (.ovl.init)) + %u "
                               ": AT (LOADADDR (.ovl.init) + %u) {\n",
                       ovlynum, vma, lma) <= 0)
            goto file_err;

          base = print_one_overlay_section (script, base, count, ovlynum,
                                           ovly_map, ovly_sections, info);
          if (base == (unsigned) -1)
            goto file_err;

          if (fprintf (script, "  }\n") <= 0)
            goto file_err;

          ovlynum++;
        }

      if (fprintf (script, " . = ABSOLUTE (ADDR (.ovl.init)) + %u;\n",
                   1 << (htab->num_lines_log2 + htab->line_size_log2)) <= 0)
        goto file_err;

      if (fprintf (script, "}\nINSERT AFTER .toe;\n") <= 0)
        goto file_err;
    }
  else
    {
      if (fprintf (script, "SECTIONS\n{\n") <= 0)
        goto file_err;

      if (fprintf (script,
                   " . = ALIGN (16);\n"
                   " .ovl.init : { *(.ovl.init) }\n"
                   " . = ABSOLUTE (ADDR (.ovl.init));\n") <= 0)
        goto file_err;

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
              if (fprintf (script,
                          " OVERLAY : AT (ALIGN (LOADADDR (.ovl.init) + SIZEOF (.ovl.init), 16))\n {\n") <= 0)
                goto file_err;
            }
          else
            {
              if (fprintf (script, " OVERLAY :\n {\n") <= 0)
                goto file_err;
            }

          while (base < count)
            {
              if (fprintf (script, "  .ovly%u {\n", ovlynum) <= 0)
                goto file_err;

              base = print_one_overlay_section (script, base, count, ovlynum,
                                               ovly_map, ovly_sections, info);
              if (base == (unsigned) -1)
                goto file_err;

              if (fprintf (script, "  }\n") <= 0)
                goto file_err;

              ovlynum += htab->params->num_lines;
              while (base < count && ovly_map[base] < ovlynum)
                base++;
            }

          if (fprintf (script, " }\n") <= 0)
            goto file_err;
        }

      if (fprintf (script, "}\nINSERT BEFORE .text;\n") <= 0)
        goto file_err;
    }

  free (ovly_map);
  free (ovly_sections);

  if (fclose (script) != 0)
    goto file_err;

  if (htab->params->auto_overlay & AUTO_RELINK)
    (*htab->params->spu_elf_relink) ();

  xexit (0);

 file_err:
  bfd_set_error (bfd_error_system_call);
 err_exit:
  if (bfd_arr)
    free (bfd_arr);
  if (ovly_map)
    free (ovly_map);
  if (ovly_sections)
    free (ovly_sections);
  while (dummy_caller.call_list != NULL)
    {
      struct call_info *call = dummy_caller.call_list;
      dummy_caller.call_list = call->next;
      free (call);
    }
  info->callbacks->fatal (_("%P: auto overlay error: %E\n"));
}

/* Provide an estimate of total stack required.  */

static bool
spu_elf_stack_analysis (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab;
  struct _sum_stack_param sum_stack_param;

  if (!info)
    return false;

  if (!discover_functions (info))
    return false;

  if (!build_call_tree (info))
    return false;

  htab = spu_hash_table (info);
  if (!htab || !htab->params)
    return false;

  if (htab->params->stack_analysis && info->callbacks)
    {
      if (info->callbacks->info)
        info->callbacks->info (_("Stack size for call graph root nodes.\n"));
      
      if (info->callbacks->minfo)
        info->callbacks->minfo (_("\nStack size for functions.  "
                                  "Annotations: '*' max stack, 't' tail call\n"));
    }

  memset(&sum_stack_param, 0, sizeof(sum_stack_param));
  sum_stack_param.emit_stack_syms = htab->params->emit_stack_syms;
  sum_stack_param.overall_stack = 0;
  
  if (!for_each_node (sum_stack, info, &sum_stack_param, true))
    return false;

  if (htab->params->stack_analysis && info->callbacks && info->callbacks->info)
    {
      info->callbacks->info (_("Maximum stack required is 0x%v\n"),
                             (bfd_vma) sum_stack_param.overall_stack);
    }
    
  return true;
}

/* Perform a final link.  */

static bool
spu_elf_final_link (bfd *output_bfd, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bool needs_analysis;
  
  if (htab->params->auto_overlay)
    spu_elf_auto_overlay (info);

  needs_analysis = htab->params->stack_analysis || 
                   (htab->params->ovly_flavour == ovly_soft_icache && 
                    htab->params->lrlive_analysis);
  
  if (needs_analysis && !spu_elf_stack_analysis (info))
    info->callbacks->einfo (_("%X%P: stack/lrlive analysis error: %E\n"));

  if (!spu_elf_build_stubs (info))
    info->callbacks->fatal (_("%P: can not build overlay stubs: %E\n"));

  return bfd_elf_final_link (output_bfd, info);
}

/* Called when not normally emitting relocs, ie. !bfd_link_relocatable (info)
   and !info->emitrelocations.  Returns a count of special relocs
   that need to be emitted.  */

static unsigned int
spu_elf_count_relocs (struct bfd_link_info *info, asection *sec)
{
  Elf_Internal_Rela *relocs;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  unsigned int count = 0;
  int r_type;

  if (sec == NULL || sec->owner == NULL || info == NULL)
    return 0;

  relocs = _bfd_elf_link_read_relocs (sec->owner, sec, NULL, NULL,
                                      info->keep_memory);
  if (relocs == NULL)
    return 0;

  relend = relocs + sec->reloc_count;
  
  for (rel = relocs; rel < relend; rel++)
    {
      r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
        count++;
    }

  if (elf_section_data (sec)->relocs != relocs)
    free (relocs);

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
static void
spu_elf_emit_fixup (bfd * output_bfd, struct bfd_link_info *info,
		    bfd_vma offset)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection *sfixup = htab->sfixup;
  bfd_vma qaddr = offset & ~(bfd_vma) 15;
  bfd_vma bit = ((bfd_vma) 8) >> ((offset & 15) >> 2);
  
  if (sfixup->reloc_count == 0)
    {
      FIXUP_PUT (output_bfd, htab, 0, qaddr | bit);
      sfixup->reloc_count++;
      return;
    }
  
  bfd_vma base = FIXUP_GET (output_bfd, htab, sfixup->reloc_count - 1);
  
  if (qaddr == (base & ~(bfd_vma) 15))
    {
      FIXUP_PUT (output_bfd, htab, sfixup->reloc_count - 1, base | bit);
      return;
    }
  
  if ((sfixup->reloc_count + 1) * FIXUP_RECORD_SIZE > sfixup->size)
    {
      _bfd_error_handler (_("fatal error while creating .fixup"));
      return;
    }
  
  FIXUP_PUT (output_bfd, htab, sfixup->reloc_count, qaddr | bit);
  sfixup->reloc_count++;
}

/* Apply RELOCS to CONTENTS of INPUT_SECTION from INPUT_BFD.  */

static int
spu_elf_relocate_section (bfd *output_bfd,
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
  unsigned int iovl = 0;

  htab = spu_hash_table (info);
  if (!htab)
    return false;
    
  bool stubs = (htab->stub_sec != NULL && maybe_needs_stubs (input_section));
  iovl = overlay_index (input_section);
  ea = bfd_get_section_by_name (output_bfd, "._ea");
  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  sym_hashes = (struct elf_link_hash_entry **) (elf_sym_hashes (input_bfd));

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  
  for (; rel < relend; rel++)
    {
      if (!process_relocation(output_bfd, info, input_bfd, input_section,
                              contents, rel, local_syms, local_sections,
                              symtab_hdr, sym_hashes, htab, ea, stubs, iovl,
                              &emit_these_relocs, &ret))
        continue;
    }

  if (ret && emit_these_relocs && !info->emitrelocations)
    {
      ret = filter_ppu_relocations(input_section, relocs);
    }

  return ret;
}

static bool
process_relocation(bfd *output_bfd, struct bfd_link_info *info,
                   bfd *input_bfd, asection *input_section,
                   bfd_byte *contents, Elf_Internal_Rela *rel,
                   Elf_Internal_Sym *local_syms, asection **local_sections,
                   Elf_Internal_Shdr *symtab_hdr,
                   struct elf_link_hash_entry **sym_hashes,
                   struct spu_link_hash_table *htab, asection *ea,
                   bool stubs, unsigned int iovl,
                   bool *emit_these_relocs, int *ret)
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
  bool is_ea_sym;

  r_symndx = ELF32_R_SYM (rel->r_info);
  r_type = ELF32_R_TYPE (rel->r_info);
  howto = elf_howto_table + r_type;
  unresolved_reloc = false;
  h = NULL;
  sym = NULL;
  sec = NULL;

  if (r_symndx < symtab_hdr->sh_info)
    {
      sym = local_syms + r_symndx;
      sec = local_sections[r_symndx];
      sym_name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym, sec);
      relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
    }
  else
    {
      if (sym_hashes == NULL)
        {
          *ret = false;
          return false;
        }
      if (!resolve_global_symbol(info, input_bfd, input_section, rel,
                                 symtab_hdr, sym_hashes, r_symndx, r_type,
                                 &h, &sec, &relocation, &unresolved_reloc,
                                 &sym_name))
        {
          *ret = false;
          return false;
        }
    }

  if (sec != NULL && discarded_section (sec))
    {
      RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
                                       rel, 1, rel + 1, R_SPU_NONE,
                                       howto, 0, contents);
    }

  if (bfd_link_relocatable (info))
    return false;

  handle_add_pic_relocation(r_type, h, contents, rel);

  is_ea_sym = (ea != NULL && sec != NULL && sec->output_section == ea);
  addend = rel->r_addend;

  if (stubs && !is_ea_sym)
    {
      handle_overlay_stub(htab, h, sym, sec, input_section, rel,
                          contents, info, iovl, r_symndx, input_bfd,
                          &relocation, &addend);
    }
  else
    {
      handle_soft_icache_encoding(htab, r_type, sec, is_ea_sym, &relocation);
    }

  emit_fixup_if_needed(htab, info, input_section, rel, output_bfd, r_type);

  if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
    {
      handle_ppu_relocation(ea, is_ea_sym, rel, relocation, r_type);
      *emit_these_relocs = true;
      return false;
    }
  
  if (is_ea_sym)
    unresolved_reloc = true;

  if (unresolved_reloc && !handle_unresolved_relocation(output_bfd, info,
                                                        input_bfd, input_section,
                                                        rel, howto, sym_name))
    *ret = false;

  r = _bfd_final_link_relocate (howto, input_bfd, input_section,
                                contents, rel->r_offset, relocation, addend);

  if (r != bfd_reloc_ok)
    {
      handle_relocation_error(info, h, sym_name, howto, input_bfd,
                             input_section, rel, r);
      *ret = false;
    }

  return true;
}

static bool
resolve_global_symbol(struct bfd_link_info *info, bfd *input_bfd,
                     asection *input_section, Elf_Internal_Rela *rel,
                     Elf_Internal_Shdr *symtab_hdr,
                     struct elf_link_hash_entry **sym_hashes,
                     unsigned int r_symndx, int r_type,
                     struct elf_link_hash_entry **h, asection **sec,
                     bfd_vma *relocation, bool *unresolved_reloc,
                     const char **sym_name)
{
  *h = sym_hashes[r_symndx - symtab_hdr->sh_info];

  if (info->wrap_hash != NULL && (input_section->flags & SEC_DEBUGGING) != 0)
    *h = ((struct elf_link_hash_entry *)
          unwrap_hash_lookup (info, input_bfd, &(*h)->root));

  while ((*h)->root.type == bfd_link_hash_indirect ||
         (*h)->root.type == bfd_link_hash_warning)
    *h = (struct elf_link_hash_entry *) (*h)->root.u.i.link;

  *relocation = 0;
  
  if ((*h)->root.type == bfd_link_hash_defined ||
      (*h)->root.type == bfd_link_hash_defweak)
    {
      *sec = (*h)->root.u.def.section;
      if (*sec == NULL || (*sec)->output_section == NULL)
        *unresolved_reloc = true;
      else
        *relocation = ((*h)->root.u.def.value +
                      (*sec)->output_section->vma +
                      (*sec)->output_offset);
    }
  else if ((*h)->root.type == bfd_link_hash_undefweak)
    {
    }
  else if (info->unresolved_syms_in_objects == RM_IGNORE &&
           ELF_ST_VISIBILITY ((*h)->other) == STV_DEFAULT)
    {
    }
  else if (!bfd_link_relocatable (info) &&
           !(r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64))
    {
      bool err = (info->unresolved_syms_in_objects == RM_DIAGNOSE &&
                 !info->warn_unresolved_syms) ||
                ELF_ST_VISIBILITY ((*h)->other) != STV_DEFAULT;

      info->callbacks->undefined_symbol(info, (*h)->root.root.string,
                                       input_bfd, input_section,
                                       rel->r_offset, err);
    }
  
  *sym_name = (*h)->root.root.string;
  return true;
}

static void
handle_add_pic_relocation(int r_type, struct elf_link_hash_entry *h,
                         bfd_byte *contents, Elf_Internal_Rela *rel)
{
  if (r_type == R_SPU_ADD_PIC && h != NULL &&
      !(h->def_regular || ELF_COMMON_DEF_P (h)))
    {
      bfd_byte *loc = contents + rel->r_offset;
      loc[0] = 0x1c;
      loc[1] = 0x00;
      loc[2] &= 0x3f;
    }
}

static void
handle_overlay_stub(struct spu_link_hash_table *htab,
                   struct elf_link_hash_entry *h, Elf_Internal_Sym *sym,
                   asection *sec, asection *input_section,
                   Elf_Internal_Rela *rel, bfd_byte *contents,
                   struct bfd_link_info *info, unsigned int iovl,
                   unsigned int r_symndx, bfd *input_bfd,
                   bfd_vma *relocation, bfd_vma *addend)
{
  enum _stub_type stub_type;
  
  stub_type = needs_ovl_stub (h, sym, sec, input_section, rel, contents, info);
  if (stub_type == no_stub)
    return;

  unsigned int ovl = (stub_type != nonovl_stub) ? iovl : 0;
  struct got_entry *g, **head;

  if (h != NULL)
    head = &h->got.glist;
  else
    head = elf_local_got_ents (input_bfd) + r_symndx;

  for (g = *head; g != NULL; g = g->next)
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
          if (g->addend == *addend && (g->ovl == ovl || g->ovl == 0))
            break;
        }
    }
  
  if (g == NULL)
    abort ();

  *relocation = g->stub_addr;
  *addend = 0;
}

static void
handle_soft_icache_encoding(struct spu_link_hash_table *htab, int r_type,
                           asection *sec, bool is_ea_sym, bfd_vma *relocation)
{
  if (htab->params->ovly_flavour == ovly_soft_icache &&
      (r_type == R_SPU_ADDR16_HI || r_type == R_SPU_ADDR32 ||
       r_type == R_SPU_REL32) && !is_ea_sym)
    {
      unsigned int ovl = overlay_index (sec);
      if (ovl != 0)
        {
          unsigned int set_id = ((ovl - 1) >> htab->num_lines_log2) + 1;
          *relocation += set_id << 18;
        }
    }
}

static void
emit_fixup_if_needed(struct spu_link_hash_table *htab,
                    struct bfd_link_info *info, asection *input_section,
                    Elf_Internal_Rela *rel, bfd *output_bfd, int r_type)
{
  if (htab->params->emit_fixups && !bfd_link_relocatable (info) &&
      (input_section->flags & SEC_ALLOC) != 0 && r_type == R_SPU_ADDR32)
    {
      bfd_vma offset = rel->r_offset + input_section->output_section->vma +
                      input_section->output_offset;
      spu_elf_emit_fixup (output_bfd, info, offset);
    }
}

static void
handle_ppu_relocation(asection *ea, bool is_ea_sym, Elf_Internal_Rela *rel,
                     bfd_vma relocation, int r_type)
{
  if (is_ea_sym && ea != NULL)
    {
      rel->r_addend += (relocation - ea->vma +
                       elf_section_data (ea)->this_hdr.sh_offset);
      rel->r_info = ELF32_R_INFO (0, r_type);
    }
}

static bool
handle_unresolved_relocation(bfd *output_bfd, struct bfd_link_info *info,
                            bfd *input_bfd, asection *input_section,
                            Elf_Internal_Rela *rel, reloc_howto_type *howto,
                            const char *sym_name)
{
  if (_bfd_elf_section_offset (output_bfd, info, input_section,
                               rel->r_offset) != (bfd_vma) -1)
    {
      _bfd_error_handler
        (_("%pB(%s+%#" PRIx64 "): "
           "unresolvable %s relocation against symbol `%s'"),
         input_bfd,
         bfd_section_name (input_section),
         (uint64_t) rel->r_offset,
         howto->name,
         sym_name);
      return false;
    }
  return true;
}

static void
handle_relocation_error(struct bfd_link_info *info,
                       struct elf_link_hash_entry *h,
                       const char *sym_name, reloc_howto_type *howto,
                       bfd *input_bfd, asection *input_section,
                       Elf_Internal_Rela *rel, bfd_reloc_status_type r)
{
  const char *msg = NULL;

  switch (r)
    {
    case bfd_reloc_overflow:
      (*info->callbacks->reloc_overflow)
        (info, (h ? &h->root : NULL), sym_name, howto->name,
         (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
      break;

    case bfd_reloc_undefined:
      (*info->callbacks->undefined_symbol)
        (info, sym_name, input_bfd, input_section, rel->r_offset, true);
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
      break;
    }

  if (msg != NULL)
    (*info->callbacks->warning) (info, msg, sym_name, input_bfd,
                                input_section, rel->r_offset);
}

static int
filter_ppu_relocations(asection *input_section, Elf_Internal_Rela *relocs)
{
  Elf_Internal_Rela *wrel, *rel, *relend;
  Elf_Internal_Shdr *rel_hdr;

  wrel = rel = relocs;
  relend = relocs + input_section->reloc_count;
  
  for (; rel < relend; rel++)
    {
      int r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
        *wrel++ = *rel;
    }
  
  input_section->reloc_count = wrel - relocs;
  rel_hdr = _bfd_elf_single_rel_hdr (input_section);
  rel_hdr->sh_size = input_section->reloc_count * rel_hdr->sh_entsize;
  
  return 2;
}

static bool
spu_elf_finish_dynamic_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
				 struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  return true;
}

/* Adjust _SPUEAR_ syms to point at their overlay stubs.  */

static int
spu_elf_output_symbol_hook (struct bfd_link_info *info,
			    const char *sym_name ATTRIBUTE_UNUSED,
			    Elf_Internal_Sym *sym,
			    asection *sym_sec ATTRIBUTE_UNUSED,
			    struct elf_link_hash_entry *h)
{
  struct spu_link_hash_table *htab;
  struct got_entry *g;
  bfd_boolean is_soft_icache;
  bfd_boolean is_spuear_symbol;
  bfd_boolean is_defined_symbol;

  if (info == NULL || sym == NULL || h == NULL) {
    return 1;
  }

  htab = spu_hash_table (info);
  if (htab == NULL || htab->stub_sec == NULL) {
    return 1;
  }

  if (bfd_link_relocatable (info)) {
    return 1;
  }

  is_defined_symbol = (h->root.type == bfd_link_hash_defined ||
                       h->root.type == bfd_link_hash_defweak) &&
                      h->def_regular;

  if (!is_defined_symbol) {
    return 1;
  }

  is_spuear_symbol = (h->root.root.string != NULL &&
                      startswith (h->root.root.string, "_SPUEAR_"));

  if (!is_spuear_symbol) {
    return 1;
  }

  is_soft_icache = (htab->params != NULL &&
                    htab->params->ovly_flavour == ovly_soft_icache);

  for (g = h->got.glist; g != NULL; g = g->next) {
    bfd_boolean match_found = FALSE;

    if (is_soft_icache) {
      match_found = (g->br_addr == g->stub_addr);
    } else {
      match_found = (g->addend == 0 && g->ovl == 0);
    }

    if (match_found) {
      if (htab->stub_sec[0] != NULL &&
          htab->stub_sec[0]->output_section != NULL &&
          htab->stub_sec[0]->output_section->owner != NULL) {
        sym->st_shndx = _bfd_elf_section_from_bfd_section
                       (htab->stub_sec[0]->output_section->owner,
                        htab->stub_sec[0]->output_section);
        sym->st_value = g->stub_addr;
      }
      break;
    }
  }

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
  Elf_Internal_Ehdr *i_ehdrp;

  if (abfd == NULL || info == NULL)
    return false;

  if (!_bfd_elf_init_file_header (abfd, info))
    return false;

  if (!spu_plugin)
    return true;

  i_ehdrp = elf_elfheader (abfd);
  if (i_ehdrp == NULL)
    return false;

  i_ehdrp->e_type = ET_DYN;
  return true;
}

/* We may add an extra PT_LOAD segment for .toe.  We also need extra
   segments for overlays.  */

static int
spu_elf_additional_program_headers (bfd *abfd, struct bfd_link_info *info)
{
  int extra = 0;
  asection *sec;
  struct spu_link_hash_table *htab;

  if (info != NULL)
    {
      htab = spu_hash_table (info);
      if (htab != NULL)
        {
          extra = htab->num_overlays;
          if (extra > 0)
            extra++;
        }
    }

  sec = bfd_get_section_by_name (abfd, ".toe");
  if (sec != NULL && (sec->flags & SEC_LOAD) != 0)
    extra++;

  return extra;
}

/* Remove .toe section from other PT_LOAD segments and put it in
   a segment of its own.  Put overlays in separate segments too.  */

static bool
spu_elf_modify_segment_map (bfd *abfd, struct bfd_link_info *info)
{
  asection *toe;
  struct elf_segment_map *m;
  struct elf_segment_map **p;
  struct elf_segment_map **p_overlay;
  struct elf_segment_map **first_load;
  struct elf_segment_map *m_overlay;

  if (info == NULL)
    return true;

  toe = bfd_get_section_by_name (abfd, ".toe");
  
  for (m = elf_seg_map (abfd); m != NULL; m = m->next)
    {
      if (m->p_type != PT_LOAD || m->count <= 1)
        continue;
        
      for (unsigned int i = 0; i < m->count; i++)
        {
          asection *s = m->sections[i];
          if (s != toe && spu_elf_section_data (s)->u.o.ovl_index == 0)
            continue;
            
          if (!split_segment_at_index (abfd, m, i))
            return false;
          break;
        }
    }

  p = &elf_seg_map (abfd);
  p_overlay = &m_overlay;
  m_overlay = NULL;
  first_load = NULL;
  
  while (*p != NULL)
    {
      if ((*p)->p_type == PT_LOAD)
        {
          if (first_load == NULL)
            first_load = p;
            
          if ((*p)->count == 1 &&
              spu_elf_section_data ((*p)->sections[0])->u.o.ovl_index != 0)
            {
              m = *p;
              m->no_sort_lma = 1;
              *p = m->next;
              *p_overlay = m;
              p_overlay = &m->next;
              continue;
            }
        }
      p = &((*p)->next);
    }

  if (m_overlay != NULL)
    {
      p = first_load;
      if (p != NULL && *p != NULL && (*p)->p_type == PT_LOAD && (*p)->includes_filehdr)
        p = &(*p)->next;
      *p_overlay = *p;
      *p = m_overlay;
    }

  return true;
}

static bool
split_segment_at_index (bfd *abfd, struct elf_segment_map *m, unsigned int index)
{
  struct elf_segment_map *m2;
  bfd_vma amt;
  asection *section = m->sections[index];

  if (index + 1 < m->count)
    {
      amt = sizeof (struct elf_segment_map);
      amt += (m->count - (index + 2)) * sizeof (m->sections[0]);
      m2 = bfd_zalloc (abfd, amt);
      if (m2 == NULL)
        return false;
        
      m2->count = m->count - (index + 1);
      memcpy (m2->sections, m->sections + index + 1,
              m2->count * sizeof (m->sections[0]));
      m2->p_type = PT_LOAD;
      m2->next = m->next;
      m->next = m2;
    }

  if (index != 0)
    {
      m->count = index;
      amt = sizeof (struct elf_segment_map);
      m2 = bfd_zalloc (abfd, amt);
      if (m2 == NULL)
        return false;
        
      m2->p_type = PT_LOAD;
      m2->count = 1;
      m2->sections[0] = section;
      m2->next = m->next;
      m->next = m2;
    }
  else
    {
      m->count = 1;
    }

  return true;
}

/* Tweak the section type of .note.spu_name.  */

static bool
spu_elf_fake_sections (bfd *obfd ATTRIBUTE_UNUSED,
		       Elf_Internal_Shdr *hdr,
		       asection *sec)
{
  if (sec == NULL || hdr == NULL || sec->name == NULL)
    return false;
    
  if (strcmp (sec->name, SPU_PTNOTE_SPUNAME) == 0)
    hdr->sh_type = SHT_NOTE;
    
  return true;
}

/* Tweak phdrs before writing them out.  */

static bool
spu_elf_modify_headers (bfd *abfd, struct bfd_link_info *info)
{
  if (info == NULL)
    return _bfd_elf_modify_headers (abfd, info);

  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf_obj_tdata *tdata = elf_tdata (abfd);
  Elf_Internal_Phdr *phdr = tdata->phdr;
  unsigned int count = elf_program_header_size (abfd) / bed->s->sizeof_phdr;
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (htab->num_overlays != 0)
    {
      struct elf_segment_map *m = elf_seg_map (abfd);
      unsigned int i = 0;
      
      while (m != NULL)
        {
          if (m->count != 0)
            {
              unsigned int ovl_index = spu_elf_section_data (m->sections[0])->u.o.ovl_index;
              if (ovl_index != 0)
                {
                  phdr[i].p_flags |= PF_OVERLAY;

                  if (htab->ovtab != NULL && htab->ovtab->size != 0
                      && htab->params->ovly_flavour != ovly_soft_icache)
                    {
                      bfd_byte *p = htab->ovtab->contents;
                      unsigned int off = ovl_index * 16 + 8;
                      bfd_put_32 (htab->ovtab->owner, phdr[i].p_offset, p + off);
                    }
                }
            }
          i++;
          m = m->next;
        }

      if (htab->init != NULL && htab->init->size != 0)
        {
          bfd_vma val = elf_section_data (htab->ovl_sec[0])->this_hdr.sh_offset;
          bfd_put_32 (htab->init->owner, val, htab->init->contents + 4);
        }
    }

  Elf_Internal_Phdr *last = NULL;
  unsigned int i;
  
  for (i = count; i-- != 0; )
    {
      if (phdr[i].p_type != PT_LOAD)
        continue;

      unsigned adjust_filesz = -phdr[i].p_filesz & 15;
      if (adjust_filesz != 0 && last != NULL)
        {
          if (phdr[i].p_offset + phdr[i].p_filesz > last->p_offset - adjust_filesz)
            break;
        }

      unsigned adjust_memsz = -phdr[i].p_memsz & 15;
      if (adjust_memsz != 0 && last != NULL && phdr[i].p_filesz != 0)
        {
          bfd_vma end_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
          if (end_vaddr > last->p_vaddr - adjust_memsz && end_vaddr <= last->p_vaddr)
            break;
        }

      if (phdr[i].p_filesz != 0)
        last = &phdr[i];
    }

  if (i == (unsigned int) -1)
    {
      for (i = count; i-- != 0; )
        {
          if (phdr[i].p_type == PT_LOAD)
            {
              phdr[i].p_filesz += -phdr[i].p_filesz & 15;
              phdr[i].p_memsz += -phdr[i].p_memsz & 15;
            }
        }
    }

  return _bfd_elf_modify_headers (abfd, info);
}

bool
spu_elf_size_sections (bfd *obfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  
  if (!htab->params->emit_fixups)
    return true;
    
  asection *sfixup = htab->sfixup;
  int fixup_count = 0;
  
  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour)
        continue;
        
      for (asection *isec = ibfd->sections; isec != NULL; isec = isec->next)
        {
          if ((isec->flags & SEC_ALLOC) == 0
              || (isec->flags & SEC_RELOC) == 0
              || isec->reloc_count == 0)
            continue;
            
          Elf_Internal_Rela *internal_relocs = 
            _bfd_elf_link_read_relocs (ibfd, isec, NULL, NULL,
                                       info->keep_memory);
          if (internal_relocs == NULL)
            return false;
            
          bfd_vma base_end = 0;
          Elf_Internal_Rela *irelaend = internal_relocs + isec->reloc_count;
          
          for (Elf_Internal_Rela *irela = internal_relocs; irela < irelaend; irela++)
            {
              if (ELF32_R_TYPE (irela->r_info) == R_SPU_ADDR32
                  && irela->r_offset >= base_end)
                {
                  base_end = (irela->r_offset & ~(bfd_vma) 15) + 16;
                  fixup_count++;
                }
            }
        }
    }
    
  size_t size = (fixup_count + 1) * FIXUP_RECORD_SIZE;
  
  if (!bfd_set_section_size (sfixup, size))
    return false;
    
  sfixup->contents = (bfd_byte *) bfd_zalloc (info->input_bfds, size);
  if (sfixup->contents == NULL)
    return false;
    
  sfixup->alloced = 1;
  return true;
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
