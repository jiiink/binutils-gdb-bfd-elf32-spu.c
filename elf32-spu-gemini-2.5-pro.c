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

#include <stdlib.h>

typedef struct {
    bfd_reloc_code_real_type bfd_code;
    enum elf_spu_reloc_type elf_code;
} reloc_map_entry;

static const reloc_map_entry RELOC_MAP[] = {
    { BFD_RELOC_NONE, R_SPU_NONE },
    { BFD_RELOC_32, R_SPU_ADDR32 },
    { BFD_RELOC_32_PCREL, R_SPU_REL32 },
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
    { BFD_RELOC_SPU_PPU32, R_SPU_PPU32 },
    { BFD_RELOC_SPU_PPU64, R_SPU_PPU64 },
    { BFD_RELOC_SPU_ADD_PIC, R_SPU_ADD_PIC }
};

static int
compare_reloc_entries (const void *key, const void *element)
{
  const bfd_reloc_code_real_type bfd_code = *(const bfd_reloc_code_real_type *) key;
  const reloc_map_entry *entry = (const reloc_map_entry *) element;

  if (bfd_code < entry->bfd_code)
    return -1;
  if (bfd_code > entry->bfd_code)
    return 1;
  return 0;
}

static enum elf_spu_reloc_type
spu_elf_bfd_to_reloc_type (bfd_reloc_code_real_type code)
{
  const reloc_map_entry *entry = bsearch (&code, RELOC_MAP,
                                          sizeof (RELOC_MAP) / sizeof (RELOC_MAP[0]),
                                          sizeof (RELOC_MAP[0]),
                                          compare_reloc_entries);

  if (entry)
    {
      return entry->elf_code;
    }

  return (enum elf_spu_reloc_type) -1;
}

static bool
spu_elf_info_to_howto (bfd *abfd,
		       arelent *cache_ptr,
		       Elf_Internal_Rela *dst)
{
  const enum elf_spu_reloc_type r_type =
    (enum elf_spu_reloc_type) ELF32_R_TYPE (dst->r_info);

  if (r_type >= R_SPU_max)
    {
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, (unsigned int) r_type);
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
  const enum elf_spu_reloc_type r_type = spu_elf_bfd_to_reloc_type (code);

  /* A single unsigned check handles both negative error codes and positive
     out-of-bounds values, preventing potential out-of-bounds access. */
  if ((unsigned int) r_type >= R_SPU_NUM_RELOCS)
    return NULL;

  return &elf_howto_table[r_type];
}

static reloc_howto_type *
spu_elf_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  if (r_name == NULL)
    {
      return NULL;
    }

  const size_t howto_count = sizeof (elf_howto_table) / sizeof (elf_howto_table[0]);
  for (size_t i = 0; i < howto_count; i++)
    {
      reloc_howto_type *howto = &elf_howto_table[i];
      if (howto->name != NULL && strcasecmp (howto->name, r_name) == 0)
	{
	  return howto;
	}
    }

  return NULL;
}

/* Apply R_SPU_REL9 and R_SPU_REL9I relocs.  */

static bfd_reloc_status_type
spu_elf_rel9 (bfd *abfd, arelent *reloc_entry, asymbol *symbol,
	      void *data, asection *input_section,
	      bfd *output_bfd, char **error_message)
{
  bfd_vma val;
  long insn;
  bfd_size_type octets;
  bfd_byte *data_ptr;

  if (output_bfd != NULL)
    {
      return bfd_elf_generic_reloc (abfd, reloc_entry, symbol, data,
				  input_section, output_bfd, error_message);
    }

  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    {
      return bfd_reloc_outofrange;
    }

  if (input_section->output_section == NULL)
    {
      return bfd_reloc_dangerous;
    }

  val = 0;
  if (!bfd_is_com_section (symbol->section))
    {
      val = symbol->value;
    }

  if (symbol->section->output_section)
    {
      val += symbol->section->output_section->vma;
    }

  val += reloc_entry->addend;

  val -= (input_section->output_section->vma
          + input_section->output_offset);

  val >>= 2;

  bfd_signed_vma sval = (bfd_signed_vma) val;
  if (sval < -256 || sval > 255)
    {
      return bfd_reloc_overflow;
    }

  octets = reloc_entry->address * OCTETS_PER_BYTE (abfd, input_section);
  data_ptr = (bfd_byte *) data + octets;

  insn = bfd_get_32 (abfd, data_ptr);

  {
    const bfd_vma low_part_mask = 0x7f;
    const bfd_vma high_part_mask = 0x180;
    const int high_part_shift1 = 7;
    const int high_part_shift2 = 16;

    bfd_vma low_part = val & low_part_mask;
    bfd_vma high_part = val & high_part_mask;
    bfd_vma reloc_field = low_part | (high_part << high_part_shift1)
                          | (high_part << high_part_shift2);

    insn &= ~reloc_entry->howto->dst_mask;
    insn |= reloc_field & reloc_entry->howto->dst_mask;
  }

  bfd_put_32 (abfd, insn, data_ptr);

  return bfd_reloc_ok;
}

static bool
spu_elf_new_section_hook (bfd *abfd, asection *sec)
{
  if (!sec)
    {
      return false;
    }

  struct _spu_elf_section_data *sdata = bfd_zalloc (abfd, sizeof (*sdata));
  if (!sdata)
    {
      return false;
    }

  sec->used_by_bfd = sdata;
  return _bfd_elf_new_section_hook (abfd, sec);
}

/* Set up overlay info for executables.  */

#define SPU_LOCAL_STORE_MASK 0x3ffff

static void
set_overlay_section_data (bfd *abfd, Elf_Internal_Phdr *phdr,
			  unsigned int ovl_index, unsigned int ovl_buf)
{
  Elf_Internal_Shdr **sections = elf_elfsections (abfd);
  if (!sections)
    return;

  unsigned int num_sections = elf_numsections (abfd);
  for (unsigned int j = 1; j < num_sections; j++)
    {
      Elf_Internal_Shdr *shdr = sections[j];
      if (shdr->bfd_section != NULL
	  && ELF_SECTION_SIZE (shdr, phdr) != 0
	  && ELF_SECTION_IN_SEGMENT (shdr, phdr))
	{
	  asection *sec = shdr->bfd_section;
	  struct spu_elf_section_data *sdata = spu_elf_section_data (sec);
	  if (sdata)
	    {
	      sdata->u.o.ovl_index = ovl_index;
	      sdata->u.o.ovl_buf = ovl_buf;
	    }
	}
    }
}

static bool
spu_elf_object_p (bfd *abfd)
{
  if ((abfd->flags & (EXEC_P | DYNAMIC)) == 0)
    return true;

  Elf_Internal_Ehdr *ehdr = elf_elfheader (abfd);
  Elf_Internal_Phdr *phdrs = elf_tdata (abfd)->phdr;

  if (!ehdr || !phdrs)
    return true;

  unsigned int num_ovl = 0;
  unsigned int num_buf = 0;
  Elf_Internal_Phdr *last_phdr = NULL;

  for (unsigned int i = 0; i < ehdr->e_phnum; i++)
    {
      Elf_Internal_Phdr *phdr = &phdrs[i];

      if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_OVERLAY) == 0)
	continue;

      num_ovl++;
      if (last_phdr == NULL
	  || ((last_phdr->p_vaddr ^ phdr->p_vaddr) & SPU_LOCAL_STORE_MASK) != 0)
	{
	  num_buf++;
	}
      last_phdr = phdr;

      set_overlay_section_data (abfd, phdr, num_ovl, num_buf);
    }

  return true;
}

/* Specially mark defined symbols named _EAR_* with BSF_KEEP so that
   strip --strip-unneeded will not remove them.  */

static void
spu_elf_backend_symbol_processing (bfd *abfd ATTRIBUTE_UNUSED, asymbol *sym)
{
  if (!sym || !sym->name || sym->section == bfd_abs_section_ptr)
    {
      return;
    }

  if (startswith (sym->name, "_EAR_"))
    {
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
  if (!info || !params)
    {
      return;
    }

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (!htab)
    {
      return;
    }

  htab->params = params;
  htab->line_size_log2 = bfd_log2 (params->line_size);
  htab->num_lines_log2 = bfd_log2 (params->num_lines);

  const bfd_vma max_branch_log2 = bfd_log2 (params->max_branch);
  htab->fromelem_size_log2 = (max_branch_log2 > 4) ? (max_branch_log2 - 4) : 0;
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
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;

  if (r_symndx >= symtab_hdr->sh_info)
    {
      struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (ibfd);
      struct elf_link_hash_entry *h = sym_hashes[r_symndx - symtab_hdr->sh_info];

      while (h->root.type == bfd_link_hash_indirect
	     || h->root.type == bfd_link_hash_warning)
	{
	  h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      if (hp != NULL)
	*hp = h;
      if (symp != NULL)
	*symp = NULL;
      if (symsecp != NULL)
	{
	  *symsecp = (h->root.type == bfd_link_hash_defined
		      || h->root.type == bfd_link_hash_defweak)
		     ? h->root.u.def.section
		     : NULL;
	}
    }
  else
    {
      Elf_Internal_Sym *locsyms = *locsymsp;
      if (locsyms == NULL)
	{
	  locsyms = (Elf_Internal_Sym *) symtab_hdr->contents;
	  if (locsyms == NULL)
	    {
	      locsyms = bfd_elf_get_elf_syms (ibfd, symtab_hdr,
					    symtab_hdr->sh_info,
					    0, NULL, NULL, NULL);
	    }
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
    }

  return true;
}

/* Create the note section if not already present.  This is done early so
   that the linker maps the sections to the right place in the output.  */

bool
spu_elf_create_sections (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *note_bfd = NULL;
  bfd *ibfd;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (bfd_get_section_by_name (ibfd, SPU_PTNOTE_SPUNAME) != NULL)
	{
	  note_bfd = ibfd;
	  break;
	}
    }

  if (note_bfd == NULL)
    {
      asection *s;
      flagword flags;
      bfd_byte *data;
      const char *output_filename;
      size_t name_len;
      size_t size;
      const size_t note_header_size = 12;
      const size_t name_field_size = (sizeof (SPU_PLUGIN_NAME) + 3) & ~3U;
      size_t desc_field_size;

      note_bfd = info->input_bfds;
      flags = SEC_LOAD | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
      s = bfd_make_section_anyway_with_flags (note_bfd, SPU_PTNOTE_SPUNAME, flags);
      if (s == NULL || !bfd_set_section_alignment (s, 4))
	return false;

      elf_section_type (s) = SHT_NOTE;

      output_filename = bfd_get_filename (info->output_bfd);
      name_len = strlen (output_filename) + 1;
      desc_field_size = (name_len + 3) & ~3U;
      size = note_header_size + name_field_size + desc_field_size;

      if (!bfd_set_section_size (s, size))
	return false;

      data = bfd_zalloc (note_bfd, size);
      if (data == NULL)
	return false;

      bfd_put_32 (note_bfd, sizeof (SPU_PLUGIN_NAME), data);
      bfd_put_32 (note_bfd, name_len, data + 4);
      bfd_put_32 (note_bfd, 1, data + 8);
      memcpy (data + note_header_size, SPU_PLUGIN_NAME, sizeof (SPU_PLUGIN_NAME));
      memcpy (data + note_header_size + name_field_size, output_filename, name_len);

      s->contents = data;
      s->alloced = 1;
    }

  if (htab->params->emit_fixups)
    {
      asection *s;
      flagword flags;
      bfd *fixup_bfd;

      if (htab->elf.dynobj == NULL)
	htab->elf.dynobj = note_bfd;
      fixup_bfd = htab->elf.dynobj;

      flags = (SEC_LOAD | SEC_ALLOC | SEC_READONLY | SEC_HAS_CONTENTS
	       | SEC_IN_MEMORY | SEC_LINKER_CREATED);
      s = bfd_make_section_anyway_with_flags (fixup_bfd, ".fixup", flags);
      if (s == NULL || !bfd_set_section_alignment (s, 2))
	return false;

      htab->sfixup = s;
    }

  return true;
}

/* qsort predicate to sort sections by vma.  */

static int
sort_sections (const void *a, const void *b)
{
  const asection *s1 = *(const asection **) a;
  const asection *s2 = *(const asection **) b;

  if (s1->vma < s2->vma)
    return -1;
  if (s1->vma > s2->vma)
    return 1;

  if (s1->index < s2->index)
    return -1;
  if (s1->index > s2->index)
    return 1;

  return 0;
}

/* Identify overlays in the output bfd, and number them.
   Returns 0 on error, 1 if no overlays, 2 if overlays.  */

static bool
is_alloc_section (const asection *s)
{
  return (s->flags & SEC_ALLOC) != 0
         && (s->flags & (SEC_LOAD | SEC_THREAD_LOCAL)) != SEC_THREAD_LOCAL
         && s->size != 0;
}

static bool
report_error_and_fail (struct bfd_link_info *info, const char *msg, asection *s)
{
  info->callbacks->einfo (msg, s);
  bfd_set_error (bfd_error_bad_value);
  return false;
}

static bool
report_error_and_fail2 (struct bfd_link_info *info, const char *msg,
                        asection *s1, asection *s2)
{
  info->callbacks->einfo (msg, s1, s2);
  bfd_set_error (bfd_error_bad_value);
  return false;
}

static bool
setup_overlay_entries (struct spu_link_hash_table *htab)
{
  static const char *const entry_names[2][2] = {
    { "__ovly_load", "__icache_br_handler" },
    { "__ovly_return", "__icache_call_handler" }
  };

  for (int i = 0; i < 2; i++)
    {
      const char *name = entry_names[i][htab->params->ovly_flavour];
      struct elf_link_hash_entry *h =
        elf_link_hash_lookup (&htab->elf, name, true, false, false);
      if (h == NULL)
        return false;

      if (h->root.type == bfd_link_hash_new)
        {
          h->root.type = bfd_link_hash_undefined;
          h->ref_regular = 1;
          h->ref_regular_nonweak = 1;
          h->non_elf = 0;
        }
      htab->ovly_entry[i] = h;
    }
  return true;
}

int
spu_elf_find_overlays (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection **alloc_sec = NULL;
  unsigned int n = 0;
  unsigned int ovl_index = 0;
  unsigned int num_buf = 0;
  int result = 0;

  if (info->output_bfd->section_count < 2)
    return 1;

  alloc_sec
    = bfd_malloc (info->output_bfd->section_count * sizeof (*alloc_sec));
  if (alloc_sec == NULL)
    return 0;

  for (asection *s = info->output_bfd->sections; s != NULL; s = s->next)
    if (is_alloc_section (s))
      alloc_sec[n++] = s;

  if (n == 0)
    {
      free (alloc_sec);
      return 1;
    }

  qsort (alloc_sec, n, sizeof (*alloc_sec), sort_sections);

  bfd_vma ovl_end = alloc_sec[0]->vma + alloc_sec[0]->size;
  unsigned int i;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      unsigned int prev_buf = 0;
      unsigned int set_id = 0;
      bfd_vma vma_start = 0;

      for (i = 1; i < n; i++)
        {
          asection *s = alloc_sec[i];
          if (s->vma < ovl_end)
            {
              asection *s0 = alloc_sec[i - 1];
              vma_start = s0->vma;
              ovl_end = (s0->vma
                         + ((bfd_vma) 1
                            << (htab->num_lines_log2 + htab->line_size_log2)));
              --i;
              break;
            }
          ovl_end = s->vma + s->size;
        }

      for (; i < n; i++)
        {
          asection *s = alloc_sec[i];
          if (s->vma >= ovl_end)
            break;

          if (startswith (s->name, ".ovl.init"))
            continue;

          num_buf = ((s->vma - vma_start) >> htab->line_size_log2) + 1;
          set_id = (num_buf == prev_buf) ? set_id + 1 : 0;
          prev_buf = num_buf;

          if ((s->vma - vma_start) & (htab->params->line_size - 1))
            {
              if (!report_error_and_fail (info,
                                          _("%X%P: overlay section %pA "
                                            "does not start on a cache line\n"), s))
                goto fail;
            }
          else if (s->size > htab->params->line_size)
            {
              if (!report_error_and_fail (info,
                                          _("%X%P: overlay section %pA "
                                            "is larger than a cache line\n"), s))
                goto fail;
            }

          alloc_sec[ovl_index] = s;
          spu_elf_section_data (s)->u.o.ovl_index
            = (set_id << htab->num_lines_log2) + num_buf;
          spu_elf_section_data (s)->u.o.ovl_buf = num_buf;
          ovl_index++;
        }

      for (; i < n; i++)
        {
          asection *s = alloc_sec[i];
          if (s->vma < ovl_end)
            {
              if (!report_error_and_fail (info,
                                          _("%X%P: overlay section %pA "
                                            "is not in cache area\n"),
                                          alloc_sec[i-1]))
                goto fail;
            }
          else
            ovl_end = s->vma + s->size;
        }
    }
  else
    {
      for (i = 1; i < n; i++)
        {
          asection *s = alloc_sec[i];
          if (s->vma < ovl_end)
            {
              asection *s0 = alloc_sec[i - 1];
              if (spu_elf_section_data (s0)->u.o.ovl_index == 0)
                {
                  ++num_buf;
                  if (!startswith (s0->name, ".ovl.init"))
                    {
                      alloc_sec[ovl_index] = s0;
                      spu_elf_section_data (s0)->u.o.ovl_index = ++ovl_index;
                      spu_elf_section_data (s0)->u.o.ovl_buf = num_buf;
                    }
                  else
                    ovl_end = s->vma + s->size;
                }
              if (!startswith (s->name, ".ovl.init"))
                {
                  alloc_sec[ovl_index] = s;
                  spu_elf_section_data (s)->u.o.ovl_index = ++ovl_index;
                  spu_elf_section_data (s)->u.o.ovl_buf = num_buf;
                  if (s0->vma != s->vma)
                    {
                      if (!report_error_and_fail2 (info,
                                                   _("%X%P: overlay sections %pA "
                                                     "and %pA do not start at the "
                                                     "same address\n"), s0, s))
                        goto fail;
                    }
                  if (ovl_end < s->vma + s->size)
                    ovl_end = s->vma + s->size;
                }
            }
          else
            ovl_end = s->vma + s->size;
        }
    }

  htab->num_overlays = ovl_index;
  htab->num_buf = num_buf;

  if (ovl_index == 0)
    {
      result = 1;
      goto success;
    }

  if (!setup_overlay_entries (htab))
    goto fail;

  result = 2;

success:
  htab->ovl_sec = alloc_sec;
  return result;

fail:
  free (alloc_sec);
  return 0;
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

static bool
is_branch (const unsigned char *insn)
{
  if (!insn)
    {
      return false;
    }

  const unsigned char BRANCH_OPCODE_MASK = 0xec;
  const unsigned char BRANCH_OPCODE_VALUE = 0x20;
  const unsigned char BRANCH_CONDITION_MASK = 0x80;

  const bool opcode_matches = (insn[0] & BRANCH_OPCODE_MASK) == BRANCH_OPCODE_VALUE;
  const bool condition_matches = (insn[1] & BRANCH_CONDITION_MASK) == 0;

  return opcode_matches && condition_matches;
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

#define INSN_OPCODE_MASK 0xef
#define INSN_OPCODE_VALUE 0x25
#define INSN_MODRM_MASK 0x80
#define INSN_MODRM_INDIRECT_VALUE 0x00

static bool
is_indirect_branch (const unsigned char *insn)
{
  if (insn == NULL)
    {
      return false;
    }

  const bool opcode_matches = (insn[0] & INSN_OPCODE_MASK) == INSN_OPCODE_VALUE;
  const bool modrm_matches = (insn[1] & INSN_MODRM_MASK) == INSN_MODRM_INDIRECT_VALUE;

  return opcode_matches && modrm_matches;
}

/* Return true for branch hint instructions.
   hbra  0001000..
   hbrr  0001001..  */

static bool
is_hint (const unsigned char *insn)
{
  if (!insn)
    {
      return false;
    }

  const unsigned char hint_opcode_mask = 0xfc;
  const unsigned char hint_opcode_value = 0x10;

  return (insn[0] & hint_opcode_mask) == hint_opcode_value;
}

/* True if INPUT_SECTION might need overlay stubs.  */

static bool
maybe_needs_stubs (asection *input_section)
{
  if (input_section == NULL)
    {
      return false;
    }

  if ((input_section->flags & SEC_ALLOC) == 0)
    {
      return false;
    }

  if (input_section->output_section == bfd_abs_section_ptr)
    {
      return false;
    }

  if (input_section->name != NULL
      && strcmp (input_section->name, ".eh_frame") == 0)
    {
      return false;
    }

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
  enum _stub_type stub_needed = no_stub;

  if (sym_sec == NULL
      || sym_sec->output_section == bfd_abs_section_ptr
      || spu_elf_section_data (sym_sec->output_section) == NULL)
    return no_stub;

  if (h != NULL)
    {
      if (h == htab->ovly_entry[0] || h == htab->ovly_entry[1])
	return no_stub;

      if (startswith (h->root.root.string, "setjmp")
	  && (h->root.root.string[6] == '\0'
	      || h->root.root.string[6] == '@'))
	stub_needed = call_ovl_stub;
    }

  unsigned int sym_type = h ? h->type : ELF_ST_TYPE (sym->st_info);
  enum elf_spu_reloc_type r_type = ELF32_R_TYPE (irela->r_info);
  bool branch = false;
  bool hint = false;
  bool call = false;
  unsigned int lrlive = 0;

  if (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16)
    {
      bfd_byte insn_buffer[4];
      const bfd_byte *insn_ptr;
      bool contents_was_null = (contents == NULL);

      if (contents_was_null)
	{
	  if (!bfd_get_section_contents (input_section->owner,
					 input_section, insn_buffer,
					 irela->r_offset, 4))
	    return stub_error;
	  insn_ptr = insn_buffer;
	}
      else
	insn_ptr = contents + irela->r_offset;

      branch = is_branch (insn_ptr);
      hint = is_hint (insn_ptr);

      if (branch || hint)
	{
	  call = (insn_ptr[0] & 0xfd) == 0x31;
	  if (branch)
	    lrlive = (insn_ptr[1] & 0x70) >> 4;

	  if (call && sym_type != STT_FUNC && !contents_was_null)
	    {
	      const char *sym_name =
		h ? h->root.root.string
		  : bfd_elf_sym_name (input_section->owner,
				      &elf_tdata (input_section->owner)->symtab_hdr,
				      sym, sym_sec);
	      _bfd_error_handler
		(_("warning: call to non-function symbol %s defined in %pB"),
		 sym_name, sym_sec->owner);
	    }
	}
    }

  bool is_data_ref = !(branch || hint);
  if ((is_data_ref && htab->params->ovly_flavour == ovly_soft_icache)
      || (sym_type != STT_FUNC && is_data_ref
	  && (sym_sec->flags & SEC_CODE) == 0))
    return no_stub;

  struct spu_elf_section_data *sym_sec_data =
    spu_elf_section_data (sym_sec->output_section);
  if (sym_sec_data->u.o.ovl_index == 0 && !htab->params->non_overlay_stubs)
    return stub_needed;

  struct spu_elf_section_data *input_sec_data =
    spu_elf_section_data (input_section->output_section);
  if (sym_sec_data->u.o.ovl_index != input_sec_data->u.o.ovl_index)
    {
      if (!lrlive && (call || sym_type == STT_FUNC))
	return call_ovl_stub;
      else
	return (enum _stub_type) (br000_ovl_stub + lrlive);
    }

  if (is_data_ref && sym_type == STT_FUNC
      && htab->params->ovly_flavour != ovly_soft_icache)
    stub_needed = nonovl_stub;

  return stub_needed;
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
  if (stub_type != nonovl_stub)
    ovl = spu_elf_section_data (isec->output_section)->u.o.ovl_index;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      htab->stub_count[ovl] += 1;
      return true;
    }

  struct got_entry **head;
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

  bfd_vma addend = (irela != NULL) ? irela->r_addend : 0;
  struct got_entry *g;

  for (g = *head; g != NULL; g = g->next)
    {
      if (g->addend == addend
	  && (g->ovl == ovl || (ovl != 0 && g->ovl == 0)))
	return true;
    }

  if (ovl == 0)
    {
      struct got_entry **p = head;
      while (*p != NULL)
	{
	  g = *p;
	  if (g->addend == addend)
	    {
	      htab->stub_count[g->ovl] -= 1;
	      *p = g->next;
	      free (g);
	    }
	  else
	    {
	      p = &g->next;
	    }
	}
    }

  g = bfd_malloc (sizeof (*g));
  if (g == NULL)
    return false;

  g->ovl = ovl;
  g->addend = addend;
  g->stub_addr = (bfd_vma) -1;
  g->next = *head;
  *head = g;

  htab->stub_count[ovl] += 1;

  return true;
}

/* Support two sizes of overlay stubs, a slower more compact stub of two
   instructions, and a faster stub of four instructions.
   Soft-icache stubs are four or eight words.  */

static unsigned int
ovl_stub_size (struct spu_elf_params *params)
{
  if (!params)
  {
    return 0;
  }

  unsigned int size = 16U << params->ovly_flavour;
  return size >> params->compact_stub;
}

static const unsigned int BASE_STUB_SIZE_LOG2 = 4;

static unsigned int
ovl_stub_size_log2(struct spu_elf_params *params)
{
    if (!params) {
        return 0;
    }

    const unsigned int unadjusted_size = BASE_STUB_SIZE_LOG2 + params->ovly_flavour;

    if (params->compact_stub > unadjusted_size) {
        return 0;
    }

    return unadjusted_size - params->compact_stub;
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

static void
build_normal_stub_code (asection *sec,
			struct spu_link_hash_table *htab,
			bfd_vma dest,
			unsigned int dest_ovl,
			bfd_vma from,
			bfd_vma to)
{
  bfd *owner = sec->owner;
  unsigned char *contents = sec->contents + sec->size;

  if (!htab->params->compact_stub)
    {
      bfd_put_32 (owner, ILA + ((dest_ovl << 7) & 0x01ffff80) + 78, contents);
      bfd_put_32 (owner, LNOP, contents + 4);
      bfd_put_32 (owner, ILA + ((dest << 7) & 0x01ffff80) + 79, contents + 8);
      if (!BRA_STUBS)
	bfd_put_32 (owner, BR + (((to - (from + 12)) << 5) & 0x007fff80), contents + 12);
      else
	bfd_put_32 (owner, BRA + ((to << 5) & 0x007fff80), contents + 12);
    }
  else
    {
      if (!BRA_STUBS)
	bfd_put_32 (owner, BRSL + (((to - from) << 5) & 0x007fff80) + 75, contents);
      else
	bfd_put_32 (owner, BRASL + ((to << 5) & 0x007fff80) + 75, contents);
      bfd_put_32 (owner, (dest & 0x3ffff) | (dest_ovl << 18), contents + 4);
    }
}

static unsigned int
calculate_lrlive (struct spu_link_hash_table *htab,
		  asection *isec,
		  const Elf_Internal_Rela *irela,
		  enum _stub_type stub_type,
		  struct bfd_link_info *info)
{
  unsigned int lrlive = 0;

  if (stub_type == call_ovl_stub)
    lrlive = 5;
  else if (!htab->params->lrlive_analysis)
    lrlive = 1;
  else if (irela != NULL)
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

static void
build_soft_icache_stub_code (asection *sec,
			     struct spu_link_hash_table *htab,
			     struct got_entry *g,
			     asection *isec,
			     const Elf_Internal_Rela *irela,
			     enum _stub_type stub_type,
			     struct bfd_link_info *info,
			     bfd_vma dest,
			     unsigned int dest_ovl,
			     bfd_vma to)
{
  bfd_vma br_dest, patt;
  unsigned int set_id;
  unsigned int lrlive;
  bfd *owner = sec->owner;
  unsigned char *contents;

  if (g->ovl == 0)
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

  lrlive = calculate_lrlive (htab, isec, irela, stub_type, info);
  set_id = ((dest_ovl - 1) >> htab->num_lines_log2) + 1;

  contents = sec->contents + sec->size;
  bfd_put_32 (owner, (set_id << 18) | (dest & 0x3ffff), contents);
  bfd_put_32 (owner, BRASL + ((to << 5) & 0x007fff80) + 75, contents + 4);
  bfd_put_32 (owner, (lrlive << 29) | (g->br_addr & 0x3ffff), contents + 8);

  patt = dest ^ br_dest;
  if (irela != NULL && ELF32_R_TYPE (irela->r_info) == R_SPU_REL16)
    patt = (dest - g->br_addr) ^ (br_dest - g->br_addr);
  bfd_put_32 (owner, (patt << 5) & 0x007fff80, contents + 12);

  if (g->ovl == 0)
    sec->size += 16;
}

static bool
create_stub_symbol (struct spu_link_hash_table *htab,
		    struct elf_link_hash_entry *h,
		    const Elf_Internal_Rela *irela,
		    struct got_entry *g,
		    asection *sec,
		    asection *dest_sec)
{
  size_t len;
  char *name;
  int add;
  struct elf_link_hash_entry *stub_h;

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

  stub_h = elf_link_hash_lookup (&htab->elf, name, true, true, false);
  free (name);
  if (stub_h == NULL)
    return false;

  if (stub_h->root.type == bfd_link_hash_new)
    {
      stub_h->root.type = bfd_link_hash_defined;
      stub_h->root.u.def.section = sec;
      stub_h->size = ovl_stub_size (htab->params);
      stub_h->root.u.def.value = sec->size - stub_h->size;
      stub_h->type = STT_FUNC;
      stub_h->ref_regular = 1;
      stub_h->def_regular = 1;
      stub_h->ref_regular_nonweak = 1;
      stub_h->forced_local = 1;
      stub_h->non_elf = 0;
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
  struct spu_link_hash_table *htab = spu_hash_table (info);
  unsigned int ovl = 0;
  struct got_entry *g;
  struct got_entry **head;
  asection *sec;
  bfd_vma addend = 0;
  bfd_vma from, to, dest_addr;
  unsigned int dest_ovl;

  if (stub_type != nonovl_stub)
    ovl = spu_elf_section_data (isec->output_section)->u.o.ovl_index;

  if (h != NULL)
    head = &h->got.glist;
  else
    head = elf_local_got_ents (ibfd) + ELF32_R_SYM (irela->r_info);

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
	return false;

      if ((g->ovl == 0 && ovl != 0) || g->stub_addr != (bfd_vma) -1)
	return true;
    }

  sec = htab->stub_sec[ovl];
  dest_addr = dest + dest_sec->output_offset + dest_sec->output_section->vma;
  from = sec->size + sec->output_offset + sec->output_section->vma;
  g->stub_addr = from;

  to = (htab->ovly_entry[0]->root.u.def.value
	+ htab->ovly_entry[0]->root.u.def.section->output_offset
	+ htab->ovly_entry[0]->root.u.def.section->output_section->vma);

  if (((dest_addr | to | from) & 3) != 0)
    {
      htab->stub_err = 1;
      return false;
    }

  dest_ovl = spu_elf_section_data (dest_sec->output_section)->u.o.ovl_index;

  if (htab->params->ovly_flavour == ovly_normal)
    {
      build_normal_stub_code (sec, htab, dest_addr, dest_ovl, from, to);
    }
  else if (htab->params->ovly_flavour == ovly_soft_icache
	   && htab->params->compact_stub)
    {
      build_soft_icache_stub_code (sec, htab, g, isec, irela, stub_type,
				   info, dest_addr, dest_ovl, to);
    }
  else
    {
      return false;
    }

  sec->size += ovl_stub_size (htab->params);

  if (htab->params->emit_stub_syms)
    {
      if (!create_stub_symbol (htab, h, irela, g, sec, dest_sec))
	return false;
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
  struct spu_elf_section_data *sdata;

  if ((h->root.type != bfd_link_hash_defined && h->root.type != bfd_link_hash_defweak)
      || !h->def_regular
      || !startswith (h->root.root.string, "_SPUEAR_"))
    {
      return true;
    }

  sym_sec = h->root.u.def.section;
  if (sym_sec == NULL || sym_sec->output_section == bfd_abs_section_ptr)
    {
      return true;
    }

  sdata = spu_elf_section_data (sym_sec->output_section);
  if (sdata == NULL)
    {
      return true;
    }

  if (sdata->u.o.ovl_index != 0 || htab->params->non_overlay_stubs)
    {
      return count_stub (htab, NULL, NULL, nonovl_stub, h, NULL);
    }

  return true;
}

static bool
build_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info = inf;
  asection *sym_sec;
  asection *output_sec;
  struct spu_elf_section_data *sec_data;

  if (h->root.type != bfd_link_hash_defined
      && h->root.type != bfd_link_hash_defweak)
    return true;

  if (!h->def_regular)
    return true;

  if (!startswith (h->root.root.string, "_SPUEAR_"))
    return true;

  sym_sec = h->root.u.def.section;
  if (sym_sec == NULL)
    return true;

  output_sec = sym_sec->output_section;
  if (output_sec == bfd_abs_section_ptr)
    return true;

  sec_data = spu_elf_section_data (output_sec);
  if (sec_data == NULL)
    return true;

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (sec_data->u.o.ovl_index == 0 && !htab->params->non_overlay_stubs)
    return true;

  return build_stub (info, NULL, NULL, nonovl_stub, h, NULL,
		     h->root.u.def.value, sym_sec);
}

/* Size or build stubs.  */

static bool
process_reloc_stub (struct bfd_link_info *info, bool build,
                    struct spu_link_hash_table *htab, bfd *ibfd,
                    asection *isec, Elf_Internal_Rela *irela,
                    Elf_Internal_Sym **local_syms_ptr)
{
  enum elf_spu_reloc_type r_type = ELF32_R_TYPE (irela->r_info);
  if (r_type >= R_SPU_max)
    {
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  unsigned int r_indx = ELF32_R_SYM (irela->r_info);
  struct elf_link_hash_entry *h;
  Elf_Internal_Sym *sym;
  asection *sym_sec;

  if (!get_sym_h (&h, &sym, &sym_sec, local_syms_ptr, r_indx, ibfd))
    return false;

  enum _stub_type stub_type = needs_ovl_stub (h, sym, sym_sec, isec, irela,
                                              NULL, info);
  if (stub_type == stub_error)
    return false;
  if (stub_type == no_stub)
    return true;

  if (htab->stub_count == NULL)
    {
      bfd_size_type amt = (htab->num_overlays + 1) * sizeof (*htab->stub_count);
      htab->stub_count = bfd_zmalloc (amt);
      if (htab->stub_count == NULL)
        return false;
    }

  if (!build)
    return count_stub (htab, ibfd, isec, stub_type, h, irela);

  bfd_vma dest = (h != NULL) ? h->root.u.def.value : sym->st_value;
  dest += irela->r_addend;
  return build_stub (info, ibfd, isec, stub_type, h, irela, dest, sym_sec);
}

static bool
process_section_stubs (struct bfd_link_info *info, bool build,
                       struct spu_link_hash_table *htab, bfd *ibfd,
                       asection *isec, Elf_Internal_Sym **local_syms_ptr)
{
  if ((isec->flags & SEC_RELOC) == 0
      || isec->reloc_count == 0
      || !maybe_needs_stubs (isec))
    return true;

  Elf_Internal_Rela *internal_relocs =
    _bfd_elf_link_read_relocs (ibfd, isec, NULL, NULL, info->keep_memory);
  if (internal_relocs == NULL)
    return false;

  bool success = true;
  Elf_Internal_Rela *irela = internal_relocs;
  Elf_Internal_Rela *irelaend = irela + isec->reloc_count;
  for (; irela < irelaend; irela++)
    {
      if (!process_reloc_stub (info, build, htab, ibfd, isec, irela,
                               local_syms_ptr))
        {
          success = false;
          break;
        }
    }

  if (elf_section_data (isec)->relocs != internal_relocs)
    free (internal_relocs);

  return success;
}

static bool
process_bfd_stubs (struct bfd_link_info *info, bool build,
                   struct spu_link_hash_table *htab, bfd *ibfd)
{
  extern const bfd_target spu_elf32_vec;
  if (ibfd->xvec != &spu_elf32_vec)
    return true;

  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
  if (symtab_hdr->sh_info == 0)
    return true;

  Elf_Internal_Sym *local_syms = NULL;
  bool success = true;

  for (asection *isec = ibfd->sections; isec != NULL; isec = isec->next)
    {
      if (!process_section_stubs (info, build, htab, ibfd, isec, &local_syms))
        {
          success = false;
          break;
        }
    }

  if (local_syms != NULL
      && symtab_hdr->contents != (unsigned char *) local_syms)
    {
      if (success && info->keep_memory)
        symtab_hdr->contents = (unsigned char *) local_syms;
      else
        free (local_syms);
    }

  return success;
}

static bool
process_stubs (struct bfd_link_info *info, bool build)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (!process_bfd_stubs (info, build, htab, ibfd))
	return false;
    }

  return true;
}

/* Allocate space for overlay call and return stubs.
   Return 0 on error, 1 if no overlays, 2 otherwise.  */

#define QUADWORD_SIZE 16
#define OVLY_TABLE_ENTRY_SIZE 16
#define OVLY_TABLE_TERMINATOR_SIZE 16
#define OVLY_BUF_TABLE_ENTRY_SIZE 4
#define QUADWORD_ALIGN_LOG2 4

static asection *
create_and_configure_section (bfd *ibfd, const char *name,
                              flagword flags, unsigned int alignment_log2)
{
  asection *sec = bfd_make_section_anyway_with_flags (ibfd, name, flags);
  if (sec != NULL && !bfd_set_section_alignment (sec, alignment_log2))
    return NULL;
  return sec;
}

static bool
create_one_stub_section (bfd *ibfd, struct spu_link_hash_table *htab,
                         unsigned int index, bfd_size_type count)
{
  const flagword flags = (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_READONLY
                          | SEC_HAS_CONTENTS | SEC_IN_MEMORY);
  unsigned int align_log2 = ovl_stub_size_log2 (htab->params);

  asection *stub = create_and_configure_section (ibfd, ".stub", flags, align_log2);
  if (stub == NULL)
    return false;

  stub->size = count * ovl_stub_size (htab->params);
  if (htab->params->ovly_flavour == ovly_soft_icache)
    stub->size += count * QUADWORD_SIZE;

  htab->stub_sec[index] = stub;
  return true;
}

static bool
create_all_stub_sections (bfd *ibfd, struct spu_link_hash_table *htab)
{
  if (htab->stub_count == NULL)
    return true;

  bfd_size_type amt = (htab->num_overlays + 1) * sizeof (*htab->stub_sec);
  htab->stub_sec = bfd_zmalloc (amt);
  if (htab->stub_sec == NULL)
    return false;

  if (!create_one_stub_section (ibfd, htab, 0, htab->stub_count[0]))
    return false;

  for (unsigned int i = 0; i < htab->num_overlays; ++i)
    {
      asection *osec = htab->ovl_sec[i];
      unsigned int ovl = spu_elf_section_data (osec)->u.o.ovl_index;
      if (!create_one_stub_section (ibfd, htab, ovl, htab->stub_count[ovl]))
	return false;
    }
  return true;
}

static bool
create_ovly_tables (bfd *ibfd, struct spu_link_hash_table *htab)
{
  flagword flags;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      flags = SEC_ALLOC;
      htab->ovtab = create_and_configure_section (ibfd, ".ovtab", flags,
                                                  QUADWORD_ALIGN_LOG2);
      if (htab->ovtab == NULL)
	return false;

      htab->ovtab->size = (QUADWORD_SIZE + QUADWORD_SIZE
                           + (QUADWORD_SIZE << htab->fromelem_size_log2))
	                  << htab->num_lines_log2;

      flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
      htab->init = create_and_configure_section (ibfd, ".ovini", flags,
                                                 QUADWORD_ALIGN_LOG2);
      if (htab->init == NULL)
	return false;
      htab->init->size = QUADWORD_SIZE;
    }
  else if (htab->stub_count != NULL)
    {
      flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
      htab->ovtab = create_and_configure_section (ibfd, ".ovtab", flags,
                                                  QUADWORD_ALIGN_LOG2);
      if (htab->ovtab == NULL)
	return false;

      htab->ovtab->size = (htab->num_overlays * OVLY_TABLE_ENTRY_SIZE
                           + OVLY_TABLE_TERMINATOR_SIZE
                           + htab->num_buf * OVLY_BUF_TABLE_ENTRY_SIZE);
    }
  return true;
}

int
spu_elf_size_stubs (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd = info->input_bfds;

  if (!process_stubs (info, false))
    return 0;

  elf_link_hash_traverse (&htab->elf, allocate_spuear_stubs, info);
  if (htab->stub_err)
    return 0;

  if (!create_all_stub_sections (ibfd, htab))
    return 0;

  if (!create_ovly_tables (ibfd, htab))
    return 0;

  if (htab->params->ovly_flavour != ovly_soft_icache
      && htab->stub_count == NULL)
    return 1;

  htab->toe = create_and_configure_section (ibfd, ".toe",
                                            SEC_ALLOC, QUADWORD_ALIGN_LOG2);
  if (htab->toe == NULL)
    return 0;

  htab->toe->size = QUADWORD_SIZE;
  return 2;
}

/* Called from ld to place overlay manager data sections.  This is done
   after the overlay manager itself is loaded, mainly so that the
   linker's htab->init section is placed after any other .ovl.init
   sections.  */

void
spu_elf_place_overlay_data (struct bfd_link_info *info)
{
  if (info == NULL)
    {
      return;
    }

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (htab == NULL || htab->params == NULL || htab->params->place_spu_section == NULL)
    {
      return;
    }

  if (htab->stub_sec != NULL)
    {
      htab->params->place_spu_section (htab->stub_sec[0], NULL, ".text");

      for (unsigned int i = 0; i < htab->num_overlays; ++i)
	{
	  asection *osec = htab->ovl_sec[i];
	  unsigned int ovl = spu_elf_section_data (osec)->u.o.ovl_index;
	  htab->params->place_spu_section (htab->stub_sec[ovl], osec, NULL);
	}
    }

  if (htab->params->ovly_flavour == ovly_soft_icache && htab->init != NULL)
    {
      htab->params->place_spu_section (htab->init, NULL, ".ovl.init");
    }

  if (htab->ovtab != NULL)
    {
      const char *ovout = (htab->params->ovly_flavour == ovly_soft_icache)
	? ".bss" : ".data";
      htab->params->place_spu_section (htab->ovtab, NULL, ovout);
    }

  if (htab->toe != NULL)
    {
      htab->params->place_spu_section (htab->toe, NULL, ".toe");
    }
}

/* Functions to handle embedded spu_ovl.o object.  */

static void *ovl_mgr_open(struct bfd *nbfd, void *stream)
{
  (void)nbfd;
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

  if (!os || nbytes < 0 || offset < 0)
    {
      return 0;
    }

  const char * const start_ptr = (const char *) os->start;
  const char * const end_ptr = (const char *) os->end;

  if (start_ptr > end_ptr)
    {
      return 0;
    }

  const size_t max_size = (size_t) (end_ptr - start_ptr);
  const size_t read_offset = (size_t) offset;

  if (read_offset >= max_size)
    {
      return 0;
    }

  const size_t bytes_available = max_size - read_offset;
  size_t bytes_to_copy = (size_t) nbytes;

  if (bytes_to_copy > bytes_available)
    {
      bytes_to_copy = bytes_available;
    }

  if (bytes_to_copy > 0)
    {
      memcpy (buf, start_ptr + read_offset, bytes_to_copy);
    }

  return (file_ptr) bytes_to_copy;
}

static int
ovl_mgr_stat (struct bfd *abfd ATTRIBUTE_UNUSED,
	      void *stream,
	      struct stat *sb)
{
  if (stream == NULL || sb == NULL)
    {
      return -1;
    }

  const struct _ovl_stream *os = (const struct _ovl_stream *) stream;

  memset (sb, 0, sizeof (*sb));

  if (os->start == NULL || os->end < os->start)
    {
      return -1;
    }

  sb->st_size = (const char *) os->end - (const char *) os->start;
  return 0;
}

bool
spu_elf_open_builtin_lib (bfd **ovl_bfd, const struct _ovl_stream *stream)
{
  if (!ovl_bfd || !stream)
    {
      return false;
    }

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
  if (sec == NULL
      || sec->output_section == NULL
      || sec->output_section == bfd_abs_section_ptr)
    {
      return 0;
    }

  struct spu_elf_section_data *sdata =
    spu_elf_section_data (sec->output_section);

  return sdata ? sdata->u.o.ovl_index : 0;
}

/* Define an STT_OBJECT symbol.  */

static struct elf_link_hash_entry *
define_ovtab_symbol (struct spu_link_hash_table *htab, const char *name)
{
  struct elf_link_hash_entry *h =
    elf_link_hash_lookup (&htab->elf, name, true, false, false);
  if (!h)
    {
      return NULL;
    }

  if (h->root.type == bfd_link_hash_defined && h->def_regular)
    {
      if (h->root.u.def.section->owner)
        {
          /* xgettext:c-format */
          _bfd_error_handler (_("%pB is not allowed to define %s"),
                              h->root.u.def.section->owner,
                              h->root.root.string);
        }
      else
        {
          _bfd_error_handler (
            _("you are not allowed to define %s in a script"),
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
create_and_set_symbol (struct spu_link_hash_table *htab,
                       const char *name,
                       bfd_vma value,
                       bfd_size_type size,
                       asection *sec)
{
  struct elf_link_hash_entry *h = define_ovtab_symbol (htab, name);
  if (h == NULL)
    return false;

  h->root.u.def.value = value;
  h->size = size;
  if (sec != NULL)
    h->root.u.def.section = sec;

  return true;
}

static bool
check_overlay_entries (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  unsigned int i;

  if (htab->num_overlays == 0)
    return true;

  for (i = 0; i < 2; i++)
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
process_stub_sections (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  unsigned int i;

  if (htab->stub_sec == NULL)
    return true;

  for (i = 0; i <= htab->num_overlays; i++)
    {
      asection *s = htab->stub_sec[i];
      if (s->size != 0)
        {
          s->contents = bfd_zalloc (s->owner, s->size);
          if (s->contents == NULL)
            return false;
          s->alloced = 1;
          s->rawsize = s->size;
          s->size = 0;
        }
    }

  process_stubs (info, true);
  if (!htab->stub_err)
    elf_link_hash_traverse (&htab->elf, build_spuear_stubs, info);

  if (htab->stub_err)
    {
      _bfd_error_handler (_("overlay stub relocation overflow"));
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  for (i = 0; i <= htab->num_overlays; i++)
    {
      asection *s = htab->stub_sec[i];
      if (s->size != s->rawsize)
        {
          _bfd_error_handler (_("stubs don't match calculated size"));
          bfd_set_error (bfd_error_bad_value);
          return false;
        }
      s->rawsize = 0;
    }

  return true;
}

static bool
build_soft_icache_symbols (struct spu_link_hash_table *htab)
{
  bfd_vma off = 0;
  bfd_size_type size;
  const bfd_size_type icache_entry_size = 16;

  size = icache_entry_size << htab->num_lines_log2;
  if (!create_and_set_symbol (htab, "__icache_tag_array", off, size, NULL)
      || !create_and_set_symbol (htab, "__icache_tag_array_size", size, 0,
                                 bfd_abs_section_ptr))
    return false;
  off += size;

  if (!create_and_set_symbol (htab, "__icache_rewrite_to", off, size, NULL)
      || !create_and_set_symbol (htab, "__icache_rewrite_to_size", size, 0,
                                 bfd_abs_section_ptr))
    return false;
  off += size;

  size = icache_entry_size << (htab->fromelem_size_log2
                               + htab->num_lines_log2);
  if (!create_and_set_symbol (htab, "__icache_rewrite_from", off, size, NULL)
      || !create_and_set_symbol (htab, "__icache_rewrite_from_size", size, 0,
                                 bfd_abs_section_ptr))
    return false;

  bfd_vma log2_cachesize = htab->num_lines_log2 + htab->line_size_log2;
  if (!create_and_set_symbol (htab, "__icache_log2_fromelemsize",
                              htab->fromelem_size_log2, 0, bfd_abs_section_ptr)
      || !create_and_set_symbol (htab, "__icache_base", htab->ovl_sec[0]->vma,
                                 htab->num_buf << htab->line_size_log2,
                                 bfd_abs_section_ptr)
      || !create_and_set_symbol (htab, "__icache_linesize",
                                 1 << htab->line_size_log2, 0,
                                 bfd_abs_section_ptr)
      || !create_and_set_symbol (htab, "__icache_log2_linesize",
                                 htab->line_size_log2, 0, bfd_abs_section_ptr)
      || !create_and_set_symbol (htab, "__icache_neg_log2_linesize",
                                 -htab->line_size_log2, 0,
                                 bfd_abs_section_ptr)
      || !create_and_set_symbol (htab, "__icache_cachesize",
                                 1 << log2_cachesize, 0, bfd_abs_section_ptr)
      || !create_and_set_symbol (htab, "__icache_log2_cachesize",
                                 log2_cachesize, 0, bfd_abs_section_ptr)
      || !create_and_set_symbol (htab, "__icache_neg_log2_cachesize",
                                 -log2_cachesize, 0, bfd_abs_section_ptr))
    return false;

  if (htab->init != NULL && htab->init->size != 0)
    {
      const bfd_size_type fileoff_size = 8;
      htab->init->contents = bfd_zalloc (htab->init->owner, htab->init->size);
      if (htab->init->contents == NULL)
        return false;
      htab->init->alloced = 1;
      if (!create_and_set_symbol (htab, "__icache_fileoff", 0, fileoff_size,
                                  htab->init))
        return false;
    }
  return true;
}

static bool
build_default_overlay_table (struct spu_link_hash_table *htab)
{
  bfd *obfd = htab->ovtab->output_section->owner;
  bfd_byte *p = htab->ovtab->contents;
  asection *s;
  const bfd_vma table_entry_size = 16;
  const bfd_vma buf_table_entry_size = 4;
  const bfd_vma alignment_mask = -16;
  const unsigned int alignment = 15;

  p[7] = 1;

  for (s = obfd->sections; s != NULL; s = s->next)
    {
      unsigned int ovl_index = spu_elf_section_data (s)->u.o.ovl_index;
      if (ovl_index != 0)
        {
          unsigned long off = ovl_index * table_entry_size;
          unsigned int ovl_buf = spu_elf_section_data (s)->u.o.ovl_buf;

          bfd_put_32 (obfd, s->vma, p + off);
          bfd_put_32 (obfd, (s->size + alignment) & alignment_mask,
                      p + off + 4);
          bfd_put_32 (obfd, ovl_buf, p + off + 12);
        }
    }

  bfd_vma table_size = htab->num_overlays * table_entry_size;
  bfd_vma table_start = table_entry_size;
  bfd_vma table_end = table_start + table_size;
  bfd_vma buf_table_size = htab->num_buf * buf_table_entry_size;

  if (!create_and_set_symbol (htab, "_ovly_table", table_start, table_size,
                              NULL)
      || !create_and_set_symbol (htab, "_ovly_table_end", table_end, 0, NULL)
      || !create_and_set_symbol (htab, "_ovly_buf_table", table_end,
                                 buf_table_size, NULL)
      || !create_and_set_symbol (htab, "_ovly_buf_table_end",
                                 table_end + buf_table_size, 0, NULL))
    return false;

  return true;
}

static bool
spu_elf_build_stubs (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (!check_overlay_entries (info) || !process_stub_sections (info))
    return false;

  if (htab->ovtab == NULL || htab->ovtab->size == 0)
    return true;

  htab->ovtab->contents = bfd_zalloc (htab->ovtab->owner, htab->ovtab->size);
  if (htab->ovtab->contents == NULL)
    return false;
  htab->ovtab->alloced = 1;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      if (!build_soft_icache_symbols (htab))
        return false;
    }
  else
    {
      if (!build_default_overlay_table (htab))
        return false;
    }

  if (!create_and_set_symbol (htab, "_EAR_", 0, 16, htab->toe))
    return false;

  return true;
}

/* Check that all loadable section VMAs lie in the range
   LO .. HI inclusive, and stash some parameters for --auto-overlay.  */

asection *
spu_elf_check_vma (struct bfd_link_info *info)
{
  if (!info || !info->output_bfd)
    {
      return NULL;
    }

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (!htab || !htab->params)
    {
      return NULL;
    }

  const bfd_vma lo = htab->params->local_store_lo;
  const bfd_vma hi = htab->params->local_store_hi;

  if (lo > hi)
    {
      htab->local_store = 0;
    }
  else
    {
      htab->local_store = hi - lo + 1;
    }

  bfd *abfd = info->output_bfd;
  for (struct elf_segment_map *m = elf_seg_map (abfd); m; m = m->next)
    {
      if (m->p_type != PT_LOAD)
	{
	  continue;
	}

      for (unsigned int i = 0; i < m->count; i++)
	{
	  asection *sec = m->sections[i];
	  if (!sec || sec->size == 0)
	    {
	      continue;
	    }

	  const bfd_vma vma = sec->vma;
	  if (vma < lo || vma > hi || sec->size > hi - vma + 1)
	    {
	      return sec;
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

#define NUM_REGS 128
#define INSN_SIZE 4

#define REG_LR 0
#define REG_SP 1

#define OPCODE_ORI 0x04
#define OPCODE_SF 0x08
#define OPCODE_ANDBI 0x16
#define OPCODE_A 0x18
#define OPCODE_AI 0x1c
#define OPCODE_STQD 0x24
#define OPCODE_FSMBI 0x32
#define OPCODE_BRSL 0x33
#define OPCODE_IL_FAMILY_MASK 0xfc
#define OPCODE_IL_FAMILY 0x40
#define OPCODE_IL 0x40
#define OPCODE_ILA_MIN 0x42
#define OPCODE_IOHL 0x60

static inline int32_t
sign_extend_10 (uint32_t val)
{
  return (int32_t) ((val ^ 0x200) - 0x200);
}

static inline int32_t
sign_extend_16 (uint32_t val)
{
  return (int32_t) ((val ^ 0x8000) - 0x8000);
}

static int
find_function_stack_adjust (asection *sec, bfd_vma offset, bfd_vma *lr_store, bfd_vma *sp_adjust)
{
  int32_t reg[NUM_REGS];

  memset (reg, 0, sizeof (reg));
  for ( ; offset + INSN_SIZE <= sec->size; offset += INSN_SIZE)
    {
      unsigned char buf[INSN_SIZE];
      if (!bfd_get_section_contents (sec->owner, sec, buf, offset, INSN_SIZE))
	break;

      if (is_branch (buf) || is_indirect_branch (buf))
	break;

      uint8_t opcode = buf[0];
      int rt = buf[3] & 0x7f;
      int ra = ((buf[2] & 0x3f) << 1) | (buf[3] >> 7);
      uint32_t imm = (uint32_t) (buf[1] << 9) | (buf[2] << 1) | (buf[3] >> 7);

      if ((opcode & OPCODE_IL_FAMILY_MASK) == OPCODE_IL_FAMILY)
	{
	  if (opcode >= OPCODE_ILA_MIN)
	    {
	      imm |= (opcode & 1) << 17;
	    }
	  else
	    {
	      imm &= 0xffff;
	      if (opcode == OPCODE_IL)
		{
		  if ((buf[1] & 0x80) == 0)
		    continue;
		  imm = sign_extend_16 (imm);
		}
	      else if ((buf[1] & 0x80) == 0)
		{
		  imm <<= 16;
		}
	    }
	  reg[rt] = imm;
	  continue;
	}

      bool sp_may_have_changed = false;
      switch (opcode)
	{
	case OPCODE_STQD:
	  if (rt == REG_LR && ra == REG_SP)
	    *lr_store = offset;
	  continue;

	case OPCODE_AI:
	  reg[rt] = reg[ra] + sign_extend_10 (imm >> 7);
	  if (rt == REG_SP)
	    sp_may_have_changed = true;
	  break;

	case OPCODE_A:
	  if ((buf[1] & 0xe0) == 0)
	    {
	      int rb = ((buf[1] & 0x1f) << 2) | ((buf[2] & 0xc0) >> 6);
	      reg[rt] = reg[ra] + reg[rb];
	      if (rt == REG_SP)
		sp_may_have_changed = true;
	    }
	  break;

	case OPCODE_SF:
	  if ((buf[1] & 0xe0) == 0)
	    {
	      int rb = ((buf[1] & 0x1f) << 2) | ((buf[2] & 0xc0) >> 6);
	      reg[rt] = reg[rb] - reg[ra];
	      if (rt == REG_SP)
		sp_may_have_changed = true;
	    }
	  break;

	case OPCODE_IOHL:
	  if ((buf[1] & 0x80) != 0)
	    reg[rt] |= imm & 0xffff;
	  continue;

	case OPCODE_ORI:
	  reg[rt] = reg[ra] | sign_extend_10 (imm >> 7);
	  continue;

	case OPCODE_FSMBI:
	  if ((buf[1] & 0x80) != 0)
	    {
	      reg[rt] = (((imm & 0x8000) ? 0xff000000 : 0) |
			 ((imm & 0x4000) ? 0x00ff0000 : 0) |
			 ((imm & 0x2000) ? 0x0000ff00 : 0) |
			 ((imm & 0x1000) ? 0x000000ff : 0));
	    }
	  continue;

	case OPCODE_ANDBI:
	  {
	    uint32_t andbi_imm = (imm >> 7) & 0xff;
	    andbi_imm |= andbi_imm << 8;
	    andbi_imm |= andbi_imm << 16;
	    reg[rt] = reg[ra] & andbi_imm;
	  }
	  continue;

	case OPCODE_BRSL:
	  if (imm == 1)
	    reg[rt] = 0;
	  continue;
	}

      if (sp_may_have_changed)
	{
	  if (reg[REG_SP] > 0)
	    break;
	  *sp_adjust = offset;
	  return reg[REG_SP];
	}
    }

  return 0;
}

/* qsort predicate to sort symbols by section and value.  */

static Elf_Internal_Sym *sort_syms_syms;
static asection **sort_syms_psecs;

static int
sort_syms (const void *a, const void *b)
{
  const Elf_Internal_Sym *sym1 = *(Elf_Internal_Sym * const *) a;
  const Elf_Internal_Sym *sym2 = *(Elf_Internal_Sym * const *) b;

  const ptrdiff_t index1 = sym1 - sort_syms_syms;
  const ptrdiff_t index2 = sym2 - sort_syms_syms;

  const asection *sec1 = sort_syms_psecs[index1];
  const asection *sec2 = sort_syms_psecs[index2];

  if (sec1 != sec2)
    {
      if (sec1->index < sec2->index)
        return -1;
      if (sec1->index > sec2->index)
        return 1;
    }

  if (sym1->st_value < sym2->st_value)
    return -1;
  if (sym1->st_value > sym2->st_value)
    return 1;

  if (sym1->st_size > sym2->st_size)
    return -1;
  if (sym1->st_size < sym2->st_size)
    return 1;

  if (sym1 < sym2)
    return -1;
  if (sym1 > sym2)
    return 1;

  return 0;
}

/* Allocate a struct spu_elf_stack_info with MAX_FUN struct function_info
   entries for section SEC.  */

static struct spu_elf_stack_info *
alloc_stack_info (asection *sec, int max_fun)
{
  struct _spu_elf_section_data *sec_data;
  bfd_size_type num_extra_funcs;
  bfd_size_type total_size;

  if (max_fun <= 0)
    return NULL;

  num_extra_funcs = (bfd_size_type)max_fun - 1;
  total_size = sizeof (struct spu_elf_stack_info);

  if (num_extra_funcs > 0)
    {
      bfd_size_type extra_size;
      const bfd_size_type func_info_size = sizeof (struct function_info);

      if (func_info_size > ((bfd_size_type)-1) / num_extra_funcs)
        return NULL;
      extra_size = num_extra_funcs * func_info_size;

      if (extra_size > ((bfd_size_type)-1) - total_size)
        return NULL;
      total_size += extra_size;
    }

  sec_data = spu_elf_section_data (sec);
  sec_data->u.i.stack_info = bfd_zmalloc (total_size);

  if (sec_data->u.i.stack_info != NULL)
    sec_data->u.i.stack_info->max_fun = max_fun;

  return sec_data->u.i.stack_info;
}

/* Add a new struct function_info describing a (part of a) function
   starting at SYM_H.  Keep the array sorted by address.  */

static const int INITIAL_FUNCTION_CAPACITY = 20;
static const int FUNCTION_CAPACITY_INCREMENT = 20;

static struct function_info *
maybe_insert_function (asection *sec,
		       void *sym_h,
		       bool global,
		       bool is_func)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;

  if (sinfo == NULL)
    {
      sinfo = alloc_stack_info (sec, INITIAL_FUNCTION_CAPACITY);
      if (sinfo == NULL)
	return NULL;
      sec_data->u.i.stack_info = sinfo;
    }

  bfd_vma off, size;
  if (global)
    {
      struct elf_link_hash_entry *h = sym_h;
      off = h->root.u.def.value;
      size = h->size;
    }
  else
    {
      Elf_Internal_Sym *sym = sym_h;
      off = sym->st_value;
      size = sym->st_size;
    }

  int found_idx = -1;
  for (int i = sinfo->num_fun - 1; i >= 0; --i)
    {
      if (sinfo->fun[i].lo <= off)
	{
	  found_idx = i;
	  break;
	}
    }

  if (found_idx >= 0)
    {
      struct function_info *existing_func = &sinfo->fun[found_idx];
      if (existing_func->lo == off)
	{
	  if (global && !existing_func->global)
	    {
	      existing_func->global = true;
	      existing_func->u.h = sym_h;
	    }
	  if (is_func)
	    {
	      existing_func->is_func = true;
	    }
	  return existing_func;
	}
      if (existing_func->hi > off && size == 0)
	{
	  return existing_func;
	}
    }

  if (sinfo->num_fun >= sinfo->max_fun)
    {
      size_t old_max = sinfo->max_fun;
      size_t new_max = old_max + (old_max >> 1) + FUNCTION_CAPACITY_INCREMENT;

      bfd_size_type base_size = sizeof (struct spu_elf_stack_info) - sizeof (struct function_info);
      bfd_size_type old_size = base_size + old_max * sizeof (struct function_info);
      bfd_size_type new_size = base_size + new_max * sizeof (struct function_info);

      struct spu_elf_stack_info *new_sinfo = bfd_realloc (sinfo, new_size);
      if (new_sinfo == NULL)
	return NULL;

      sinfo = new_sinfo;
      sinfo->max_fun = new_max;
      sec_data->u.i.stack_info = sinfo;
      memset ((char *) sinfo + old_size, 0, new_size - old_size);
    }

  int insertion_idx = found_idx + 1;
  if (insertion_idx < sinfo->num_fun)
    {
      memmove (&sinfo->fun[insertion_idx + 1],
	       &sinfo->fun[insertion_idx],
	       (sinfo->num_fun - insertion_idx) * sizeof (sinfo->fun[0]));
    }

  sinfo->num_fun++;
  struct function_info *new_func = &sinfo->fun[insertion_idx];

  new_func->is_func = is_func;
  new_func->global = global;
  new_func->sec = sec;
  if (global)
    new_func->u.h = sym_h;
  else
    new_func->u.sym = sym_h;
  new_func->lo = off;
  new_func->hi = off + size;
  new_func->lr_store = -1;
  new_func->sp_adjust = -1;
  new_func->stack = -find_function_stack_adjust (sec, off,
						 &new_func->lr_store,
						 &new_func->sp_adjust);
  return new_func;
}

/* Return the name of FUN.  */

static const char *
func_name (struct function_info *fun)
{
  const struct function_info *root_fun = fun;
  if (root_fun == NULL)
    {
      return "(null)";
    }

  while (root_fun->start != NULL)
    {
      root_fun = root_fun->start;
    }

  if (root_fun->global)
    {
      return root_fun->u.h->root.root.string;
    }

  const asection *sec = root_fun->sec;
  if (sec == NULL || sec->name == NULL || root_fun->u.sym == NULL)
    {
      return "(null)";
    }

  if (root_fun->u.sym->st_name == 0)
    {
      unsigned long value = (unsigned long) root_fun->u.sym->st_value & 0xffffffff;
      int len = snprintf (NULL, 0, "%s+%lx", sec->name, value);
      if (len < 0)
	{
	  return "(null)";
	}

      size_t buf_size = (size_t) len + 1;
      char *name = bfd_malloc (buf_size);
      if (name == NULL)
	{
	  return "(null)";
	}

      snprintf (name, buf_size, "%s+%lx", sec->name, value);
      return name;
    }

  bfd *ibfd = sec->owner;
  if (ibfd == NULL)
    {
      return "(null)";
    }

  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
  return bfd_elf_sym_name (ibfd, symtab_hdr, root_fun->u.sym, sec);
}

/* Read the instruction at OFF in SEC.  Return true iff the instruction
   is a nop, lnop, or stop 0 (all zero insn).  */

#define INSTRUCTION_SIZE 4
#define NOP_PATTERN1_BYTE0_MASK  0xbf
#define NOP_PATTERN1_BYTE1_MASK  0xe0
#define NOP_PATTERN1_BYTE1_VALUE 0x20

static bool
is_nop (asection *sec, bfd_vma off)
{
  unsigned char insn[INSTRUCTION_SIZE];

  if (off > sec->size - INSTRUCTION_SIZE)
    {
      return false;
    }

  if (!bfd_get_section_contents (sec->owner, sec, insn, off, INSTRUCTION_SIZE))
    {
      return false;
    }

  const bool is_pattern1 = (insn[0] & NOP_PATTERN1_BYTE0_MASK) == 0
                        && (insn[1] & NOP_PATTERN1_BYTE1_MASK) == NOP_PATTERN1_BYTE1_VALUE;

  const bool is_pattern2 = insn[0] == 0 && insn[1] == 0
                        && insn[2] == 0 && insn[3] == 0;

  return is_pattern1 || is_pattern2;
}

/* Extend the range of FUN to cover nop padding up to LIMIT.
   Return TRUE iff some instruction other than a NOP was found.  */

static bool
insns_at_end (struct function_info *fun, bfd_vma limit)
{
  const unsigned int instruction_size = 4;
  bfd_vma scan_addr = (fun->hi + instruction_size - 1) & -(bfd_vma) instruction_size;

  while (scan_addr < limit && is_nop (fun->sec, scan_addr))
    {
      scan_addr += instruction_size;
    }

  const bool non_nop_found = scan_addr < limit;
  fun->hi = non_nop_found ? scan_addr : limit;
  return non_nop_found;
}

/* Check and fix overlapping function ranges.  Return TRUE iff there
   are gaps in the current info we have about functions in SEC.  */

static bool
check_function_ranges (asection *sec, struct bfd_link_info *info)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;

  if (sinfo == NULL)
    {
      return false;
    }

  if (sinfo->num_fun == 0)
    {
      return true;
    }

  bool gaps = (sinfo->fun[0].lo != 0);

  for (int i = 1; i < sinfo->num_fun; i++)
    {
      struct spu_elf_func_info *prev_fun = &sinfo->fun[i - 1];
      struct spu_elf_func_info *curr_fun = &sinfo->fun[i];

      if (prev_fun->hi > curr_fun->lo)
        {
          const char *f1 = func_name (prev_fun);
          const char *f2 = func_name (curr_fun);
          info->callbacks->einfo (_("warning: %s overlaps %s\n"), f1, f2);
          prev_fun->hi = curr_fun->lo;
        }
      else if (insns_at_end (prev_fun, curr_fun->lo))
        {
          gaps = true;
        }
    }

  struct spu_elf_func_info *last_fun = &sinfo->fun[sinfo->num_fun - 1];
  if (last_fun->hi > sec->size)
    {
      const char *f1 = func_name (last_fun);
      info->callbacks->einfo (_("warning: %s exceeds section size\n"), f1);
      last_fun->hi = sec->size;
    }
  else if (insns_at_end (last_fun, sec->size))
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
  if (!sec_data)
    {
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }

  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  if (!sinfo || (sinfo->num_fun > 0 && !sinfo->fun))
    {
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }

  int lo = 0;
  int hi = sinfo->num_fun;
  while (lo < hi)
    {
      int mid = lo + (hi - lo) / 2;
      const struct function_info *f = &sinfo->fun[mid];

      if (offset < f->lo)
        {
          hi = mid;
        }
      else if (offset >= f->hi)
        {
          lo = mid + 1;
        }
      else
        {
          return &sinfo->fun[mid];
        }
    }

  if (info && info->callbacks && info->callbacks->einfo)
    {
      info->callbacks->einfo (_("%pA:0x%v not found in function table\n"),
                              sec, offset);
    }
  bfd_set_error (bfd_error_bad_value);
  return NULL;
}

/* Add CALLEE to CALLER call list if not already present.  Return TRUE
   if CALLEE was new.  If this function return FALSE, CALLEE should
   be freed.  */

static void
update_and_move_to_front(struct function_info *caller,
                         struct call_info **node_handle,
                         struct call_info *existing_node,
                         const struct call_info *new_info)
{
  existing_node->is_tail &= new_info->is_tail;
  if (!existing_node->is_tail)
    {
      existing_node->fun->start = NULL;
      existing_node->fun->is_func = true;
    }
  existing_node->count += new_info->count;

  if (caller->call_list != existing_node)
    {
      *node_handle = existing_node->next;
      existing_node->next = caller->call_list;
      caller->call_list = existing_node;
    }
}

static bool
insert_callee (struct function_info *caller, struct call_info *callee)
{
  if (!caller || !callee || !callee->fun)
    {
      return false;
    }

  for (struct call_info **pp = &caller->call_list; *pp; pp = &(*pp)->next)
    {
      if ((*pp)->fun == callee->fun)
        {
          update_and_move_to_front(caller, pp, *pp, callee);
          return false;
        }
    }

  callee->next = caller->call_list;
  caller->call_list = callee;
  return true;
}

/* Copy CALL and insert the copy into CALLER.  */

static bool
copy_callee (struct function_info *caller, const struct call_info *call)
{
  struct call_info *callee = bfd_malloc (sizeof (*callee));
  if (!callee)
    {
      return false;
    }

  *callee = *call;

  if (insert_callee (caller, callee))
    {
      return true;
    }

  free (callee);
  return false;
}

/* We're only interested in code sections.  Testing SEC_IN_MEMORY excludes
   overlay stub sections.  */

static bool
interesting_section (asection *s)
{
  if (!s || s->size == 0 || s->output_section == bfd_abs_section_ptr)
    {
      return false;
    }

  const flagword required_flags = SEC_ALLOC | SEC_LOAD | SEC_CODE;
  const bool has_required = (s->flags & required_flags) == required_flags;
  const bool is_in_memory = (s->flags & SEC_IN_MEMORY) != 0;

  return has_required && !is_in_memory;
}

/* Rummage through the relocs for SEC, looking for function calls.
   If CALL_TREE is true, fill in call graph.  If CALL_TREE is false,
   mark destination symbols on calls as being functions.  Also
   look at branches, which may be tail calls or go to hot/cold
   section part of same function.  */

#define CODE_SECTION_FLAGS (SEC_ALLOC | SEC_LOAD | SEC_CODE)

static bool warned_about_non_code_call;

static bool
is_code_section (const asection *sec)
{
  return (sec->flags & CODE_SECTION_FLAGS) == CODE_SECTION_FLAGS;
}

static unsigned int
get_spu_branch_priority (const unsigned char *insn)
{
  unsigned int priority = (unsigned int) (insn[1] & 0x0f) << 16;
  priority |= (unsigned int) insn[2] << 8;
  priority |= insn[3];
  return priority >> 7;
}

static struct function_info *
find_function_start (struct function_info *func)
{
  while (func && func->start)
    func = func->start;
  return func;
}

static void
handle_tail_call_or_func_part (struct function_info *caller,
			       struct call_info *callee,
			       const asection *caller_sec,
			       const asection *callee_sec)
{
  if (caller_sec->owner != callee_sec->owner)
    {
      callee->fun->start = NULL;
      callee->fun->is_func = true;
      return;
    }

  struct function_info *caller_start = find_function_start (caller);
  if (callee->fun->start == NULL)
    {
      if (caller_start != callee->fun)
	callee->fun->start = caller_start;
    }
  else
    {
      struct function_info *callee_start = find_function_start (callee->fun);
      if (caller_start != callee_start)
	{
	  callee->fun->start = NULL;
	  callee->fun->is_func = true;
	}
    }
}

static bool
add_function_from_reloc (asection *sym_sec, Elf_Internal_Sym *sym,
			 struct elf_link_hash_entry *h, bfd_vma val,
			 bfd_vma r_addend, bool is_call)
{
  Elf_Internal_Sym *temp_sym = NULL;
  Elf_Internal_Sym *sym_to_use = sym;

  if (r_addend != 0)
    {
      temp_sym = bfd_zmalloc (sizeof (*temp_sym));
      if (temp_sym == NULL)
	return false;
      temp_sym->st_value = val;
      temp_sym->st_shndx
	= _bfd_elf_section_from_bfd_section (sym_sec->owner, sym_sec);
      sym_to_use = temp_sym;
    }

  struct function_info *fun = (sym_to_use
			       ? maybe_insert_function (sym_sec, sym_to_use,
							false, is_call)
			       : maybe_insert_function (sym_sec, h, true,
							is_call));

  if (fun == NULL)
    {
      free (temp_sym);
      return false;
    }

  if (temp_sym != NULL && fun->u.sym != temp_sym)
    free (temp_sym);

  return true;
}

static bool
add_call_to_tree (asection *sec, asection *sym_sec,
		  struct bfd_link_info *info, bfd_vma r_offset,
		  bfd_vma val, bool is_call, bool nonbranch,
		  unsigned int priority)
{
  struct function_info *caller = find_function (sec, r_offset, info);
  if (caller == NULL)
    return false;

  struct call_info *callee = bfd_malloc (sizeof (*callee));
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
    }
  else if (!is_call && !callee->fun->is_func && callee->fun->stack == 0)
    {
      handle_tail_call_or_func_part (caller, callee, sec, sym_sec);
    }

  return true;
}

static bool
mark_functions_via_relocs (asection *sec, struct bfd_link_info *info,
			   int call_tree)
{
  if (!interesting_section (sec) || sec->reloc_count == 0)
    return true;

  Elf_Internal_Rela *internal_relocs
    = _bfd_elf_link_read_relocs (sec->owner, sec, NULL, NULL,
				 info->keep_memory);
  if (internal_relocs == NULL)
    return false;

  bool result = true;
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (sec->owner)->symtab_hdr;
  void *psyms = &symtab_hdr->contents;
  unsigned int priority = 0;

  for (Elf_Internal_Rela * irela = internal_relocs;
       irela < internal_relocs + sec->reloc_count; irela++)
    {
      unsigned int r_indx = ELF32_R_SYM (irela->r_info);
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *sym;
      asection *sym_sec;

      if (!get_sym_h (&h, &sym, &sym_sec, psyms, r_indx, sec->owner))
	{
	  result = false;
	  break;
	}

      if (sym_sec == NULL || sym_sec->output_section == bfd_abs_section_ptr)
	continue;

      bool is_call = false;
      bool nonbranch;
      enum elf_spu_reloc_type r_type = ELF32_R_TYPE (irela->r_info);

      if (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16)
	{
	  unsigned char insn[4];
	  if (!bfd_get_section_contents (sec->owner, sec, insn,
					 irela->r_offset, 4))
	    {
	      result = false;
	      break;
	    }

	  if (is_branch (insn))
	    {
	      if (!is_code_section (sym_sec))
		{
		  if (!warned_about_non_code_call)
		    {
		      info->callbacks->einfo (
			_("%pB(%pA+0x%v): call to non-code section"
			  " %pB(%pA), analysis incomplete\n"),
			sec->owner, sec, irela->r_offset, sym_sec->owner,
			sym_sec);
		      warned_about_non_code_call = true;
		    }
		  continue;
		}
	      is_call = (insn[0] & 0xfd) == 0x31;
	      priority = get_spu_branch_priority (insn);
	      nonbranch = false;
	    }
	  else
	    {
	      if (is_hint (insn))
		continue;
	      nonbranch = true;
	    }
	}
      else
	{
	  nonbranch = true;
	}

      if (nonbranch)
	{
	  unsigned int sym_type = h ? h->type : ELF_ST_TYPE (sym->st_info);
	  if (sym_type == STT_FUNC)
	    {
	      if (call_tree && spu_hash_table (info)->params->auto_overlay)
		spu_hash_table (info)->non_ovly_stub += 1;
	      continue;
	    }
	  if (!is_code_section (sym_sec))
	    continue;
	}

      bfd_vma val = (h ? h->root.u.def.value : sym->st_value) + irela->r_addend;

      if (!call_tree)
	{
	  if (!add_function_from_reloc (sym_sec, sym, h, val,
					irela->r_addend, is_call))
	    {
	      result = false;
	      break;
	    }
	}
      else
	{
	  if (!add_call_to_tree (sec, sym_sec, info, irela->r_offset, val,
				 is_call, nonbranch, priority))
	    {
	      result = false;
	      break;
	    }
	}
    }

  if (!info->keep_memory)
    free (internal_relocs);

  return result;
}

/* Handle something like .init or .fini, which has a piece of a function.
   These sections are pasted together to form a single function.  */

static bool
pasted_function (asection *sec)
{
  Elf_Internal_Sym *fake = bfd_zmalloc (sizeof (*fake));
  if (!fake)
    return false;

  fake->st_value = 0;
  fake->st_size = sec->size;
  fake->st_shndx = _bfd_elf_section_from_bfd_section (sec->owner, sec);

  struct function_info *fun = maybe_insert_function (sec, fake, false, false);
  if (!fun)
    {
      free (fake);
      return false;
    }

  struct function_info *fun_start = NULL;
  for (struct bfd_link_order *l = sec->output_section->map_head.link_order;
       l; l = l->next)
    {
      if (l->u.indirect.section == sec)
        {
          if (fun_start)
            {
              struct call_info *callee = bfd_malloc (sizeof (*callee));
              if (!callee)
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
            }
          break;
        }

      if (l->type != bfd_indirect_link_order)
        continue;

      struct _spu_elf_section_data *sec_data =
        spu_elf_section_data (l->u.indirect.section);
      if (!sec_data)
        continue;

      struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
      if (sinfo && sinfo->num_fun != 0)
        fun_start = &sinfo->fun[sinfo->num_fun - 1];
    }

  return true;
}

/* Map address ranges in code sections to functions.  */

static bool
get_and_sort_symbols (bfd *ibfd, Elf_Internal_Sym ***psyms_out,
                      asection ***psecs_out, size_t *symcount_out)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
  size_t symcount = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
  Elf_Internal_Sym *syms;

  *psyms_out = NULL;
  *psecs_out = NULL;
  *symcount_out = 0;

  if (symcount == 0)
    return true;

  free (symtab_hdr->contents);
  symtab_hdr->contents = NULL;
  syms = bfd_elf_get_elf_syms (ibfd, symtab_hdr, symcount, 0, NULL, NULL, NULL);
  if (syms == NULL)
    return false;
  symtab_hdr->contents = (void *) syms;

  Elf_Internal_Sym **psyms = bfd_malloc ((symcount + 1) * sizeof (*psyms));
  if (psyms == NULL)
    return false;

  asection **psecs = bfd_malloc (symcount * sizeof (*psecs));
  if (psecs == NULL)
    {
      free (psyms);
      return false;
    }

  Elf_Internal_Sym **psy = psyms;
  asection **p = psecs;
  for (Elf_Internal_Sym *sy = syms; sy < syms + symcount; ++sy)
    {
      if (ELF_ST_TYPE (sy->st_info) == STT_NOTYPE
          || ELF_ST_TYPE (sy->st_info) == STT_FUNC)
        {
          asection *s = bfd_section_from_elf_index (ibfd, sy->st_shndx);
          if (s != NULL && interesting_section (s))
            {
              *p++ = s;
              *psy++ = sy;
            }
        }
    }
  *psy = NULL;
  size_t filtered_symcount = psy - psyms;

  sort_syms_syms = syms;
  sort_syms_psecs = psecs;
  qsort (psyms, filtered_symcount, sizeof (*psyms), sort_syms);

  *psyms_out = psyms;
  *psecs_out = psecs;
  *symcount_out = filtered_symcount;
  return true;
}

static bool
process_bfd_initial_pass (struct bfd_link_info *info, bfd *ibfd,
                          Elf_Internal_Sym ***psyms_out, asection ***psecs_out,
                          bool *gaps_found)
{
  extern const bfd_target spu_elf32_vec;
  if (ibfd->xvec != &spu_elf32_vec)
    return true;

  size_t symcount;
  if (!get_and_sort_symbols (ibfd, psyms_out, psecs_out, &symcount))
    return false;

  if (symcount == 0)
    {
      for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
        if (interesting_section (sec))
          {
            *gaps_found = true;
            break;
          }
      return true;
    }

  Elf_Internal_Sym **psyms = *psyms_out;
  asection **psecs = *psecs_out;
  Elf_Internal_Sym *all_syms = (Elf_Internal_Sym *) elf_tdata (ibfd)->symtab_hdr.contents;

  for (Elf_Internal_Sym **psy_start = psyms; psy_start < psyms + symcount; )
    {
      asection *s = psecs[*psy_start - all_syms];
      Elf_Internal_Sym **psy_end = psy_start + 1;
      while (psy_end < psyms + symcount && psecs[*psy_end - all_syms] == s)
        psy_end++;

      if (!alloc_stack_info (s, psy_end - psy_start))
        return false;
      psy_start = psy_end;
    }

  for (size_t i = 0; i < symcount; ++i)
    {
      Elf_Internal_Sym *sy = psyms[i];
      if (ELF_ST_TYPE (sy->st_info) == STT_FUNC)
        {
          asection *s = psecs[sy - all_syms];
          if (!maybe_insert_function (s, sy, false, true))
            return false;
        }
    }

  for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
    if (interesting_section (sec))
      *gaps_found |= check_function_ranges (sec, info);

  return true;
}

static bool
fill_gaps_with_relocs (struct bfd_link_info *info, Elf_Internal_Sym ***psym_arr, size_t num_bfds)
{
  bfd *ibfd = info->input_bfds;
  for (size_t i = 0; i < num_bfds; i++, ibfd = ibfd->link.next)
    {
      if (psym_arr[i] == NULL)
        continue;

      for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
        if (!mark_functions_via_relocs (sec, info, false))
          return false;
    }
  return true;
}

static bool
fill_gaps_with_globals (struct bfd_link_info *info,
                        Elf_Internal_Sym ***psym_arr, asection ***sec_arr,
                        size_t num_bfds)
{
  bfd *ibfd = info->input_bfds;
  for (size_t bfd_idx = 0; bfd_idx < num_bfds; bfd_idx++, ibfd = ibfd->link.next)
    {
      Elf_Internal_Sym **psyms = psym_arr[bfd_idx];
      if (psyms == NULL)
        continue;

      bool bfd_has_gaps = false;
      for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
        if (interesting_section (sec))
          {
            if (check_function_ranges (sec, info))
              {
                bfd_has_gaps = true;
                break;
              }
          }

      if (!bfd_has_gaps)
        continue;

      Elf_Internal_Sym *syms = (Elf_Internal_Sym *) elf_tdata (ibfd)->symtab_hdr.contents;
      asection **psecs = sec_arr[bfd_idx];
      for (Elf_Internal_Sym **psy = psyms; *psy != NULL; ++psy)
        {
          Elf_Internal_Sym *sy = *psy;
          if (ELF_ST_TYPE (sy->st_info) != STT_FUNC
              && ELF_ST_BIND (sy->st_info) == STB_GLOBAL)
            {
              asection *s = psecs[sy - syms];
              if (!maybe_insert_function (s, sy, false, false))
                return false;
            }
        }
    }
  return true;
}

static bool
extend_function_ranges (struct bfd_link_info *info)
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
              for (int fun_idx = sinfo->num_fun - 1; fun_idx >= 0; --fun_idx)
                {
                  sinfo->fun[fun_idx].hi = hi;
                  hi = sinfo->fun[fun_idx].lo;
                }
              sinfo->fun[0].lo = 0;
            }
          else if (!pasted_function (sec))
            {
              return false;
            }
        }
    }
  return true;
}

static bool
process_gaps (struct bfd_link_info *info, Elf_Internal_Sym ***psym_arr,
              asection ***sec_arr, size_t num_bfds)
{
  if (!fill_gaps_with_relocs (info, psym_arr, num_bfds))
    return false;
  if (!fill_gaps_with_globals (info, psym_arr, sec_arr, num_bfds))
    return false;
  return extend_function_ranges (info);
}

static bool
discover_functions (struct bfd_link_info *info)
{
  size_t num_bfds = 0;
  for (bfd *ibfd = info->input_bfds; ibfd; ibfd = ibfd->link.next)
    num_bfds++;

  if (num_bfds == 0)
    return true;

  Elf_Internal_Sym ***psym_arr = NULL;
  asection ***sec_arr = NULL;
  bool success = false;
  bool gaps = false;

  psym_arr = bfd_zmalloc (num_bfds * sizeof (*psym_arr));
  if (psym_arr == NULL)
    goto cleanup;

  sec_arr = bfd_zmalloc (num_bfds * sizeof (*sec_arr));
  if (sec_arr == NULL)
    goto cleanup;

  bfd *ibfd = info->input_bfds;
  for (size_t i = 0; i < num_bfds; i++, ibfd = ibfd->link.next)
    {
      if (!process_bfd_initial_pass (info, ibfd, &psym_arr[i], &sec_arr[i], &gaps))
        goto cleanup;
    }

  if (gaps)
    {
      if (!process_gaps (info, psym_arr, sec_arr, num_bfds))
        goto cleanup;
    }

  success = true;

cleanup:
  if (psym_arr)
    {
      for (size_t i = 0; i < num_bfds; i++)
        free (psym_arr[i]);
      free (psym_arr);
    }
  if (sec_arr)
    {
      for (size_t i = 0; i < num_bfds; i++)
        free (sec_arr[i]);
      free (sec_arr);
    }

  return success;
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

  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (ibfd->xvec != &spu_elf32_vec)
	{
	  continue;
	}

      for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
	  if (!sec_data)
	    {
	      continue;
	    }

	  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
	  if (!sinfo)
	    {
	      continue;
	    }

	  for (int i = 0; i < sinfo->num_fun; ++i)
	    {
	      if (root_only && sinfo->fun[i].non_root)
		{
		  continue;
		}

	      if (!doit (&sinfo->fun[i], info, param))
		{
		  return false;
		}
	    }
	}
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
  struct function_info *root = fun->start;
  if (root == NULL)
    {
      return true;
    }

  while (root->start != NULL)
    {
      root = root->start;
    }

  struct call_info *current_call = fun->call_list;
  fun->call_list = NULL;

  while (current_call != NULL)
    {
      struct call_info *next_call = current_call->next;
      if (!insert_callee (root, current_call))
	{
	  free (current_call);
	}
      current_call = next_call;
    }

  return true;
}

/* Mark nodes in the call graph that are called by some other node.  */

static bool
mark_non_root (struct function_info *fun,
	       struct bfd_link_info *info ATTRIBUTE_UNUSED,
	       void *param ATTRIBUTE_UNUSED)
{
  if (!fun)
    {
      return false;
    }

  if (fun->visit1)
    {
      return true;
    }

  fun->visit1 = true;

  for (struct call_info *call = fun->call_list; call; call = call->next)
    {
      if (call->fun)
	{
	  call->fun->non_root = true;
	  mark_non_root (call->fun, NULL, NULL);
	}
    }

  return true;
}

/* Remove cycles from the call graph.  Set depth of nodes.  */

static void
handle_detected_cycle (const struct function_info *from,
		       struct call_info *to_call,
		       struct bfd_link_info *info)
{
  to_call->broken_cycle = true;

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (htab->params->stack_analysis && !htab->params->auto_overlay)
    {
      const char *from_name = func_name (from);
      const char *to_name = func_name (to_call->fun);

      /* xgettext:c-format */
      info->callbacks->info (_("stack analysis will ignore the call "
			       "from %s to %s\n"),
			     from_name, to_name);
    }
}

static bool
recursively_process_call (struct call_info *call,
			  struct bfd_link_info *info,
			  unsigned int *max_depth)
{
  if (!remove_cycles (call->fun, info, &call->max_depth))
    {
      return false;
    }

  if (*max_depth < call->max_depth)
    {
      *max_depth = call->max_depth;
    }
  return true;
}

static bool
remove_cycles (struct function_info *fun,
	       struct bfd_link_info *info,
	       void *param)
{
  unsigned int *depth_ptr = (unsigned int *) param;
  unsigned int current_depth = *depth_ptr;
  unsigned int max_depth = current_depth;

  fun->depth = current_depth;
  fun->visit2 = true;
  fun->marking = true;

  for (struct call_info *call = fun->call_list; call != NULL; call = call->next)
    {
      call->max_depth = current_depth + !call->is_pasted;
      if (!call->fun->visit2)
	{
	  if (!recursively_process_call (call, info, &max_depth))
	    {
	      fun->marking = false;
	      return false;
	    }
	}
      else if (call->fun->marking)
	{
	  handle_detected_cycle (fun, call, info);
	}
    }

  fun->marking = false;
  *depth_ptr = max_depth;
  return true;
}

/* Check that we actually visited all nodes in remove_cycles.  If we
   didn't, then there is some cycle in the call graph not attached to
   any root node.  Arbitrarily choose a node in the cycle as a new
   root and break the cycle.  */

static bool
mark_detached_root (struct function_info *fun,
		    struct bfd_link_info *info,
		    void *counter_ptr)
{
  if (!fun || !counter_ptr)
    {
      return false;
    }

  if (fun->visit2)
    {
      return true;
    }

  unsigned int * const counter = (unsigned int *) counter_ptr;

  fun->non_root = false;
  *counter = 0;

  return remove_cycles (fun, info, counter_ptr);
}

/* Populate call_list for each function.  */

static bool
build_call_tree (struct bfd_link_info *info)
{
  extern const bfd_target spu_elf32_vec;
  unsigned int depth;

  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (ibfd->xvec == &spu_elf32_vec)
	{
	  for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
	    {
	      if (!mark_functions_via_relocs (sec, info, true))
		{
		  return false;
		}
	    }
	}
    }

  if (!spu_hash_table (info)->params->auto_overlay)
    {
      if (!for_each_node (transfer_calls, info, 0, false))
	{
	  return false;
	}
    }

  if (!for_each_node (mark_non_root, info, 0, false))
    {
      return false;
    }

  depth = 0;
  if (!for_each_node (remove_cycles, info, &depth, true))
    {
      return false;
    }

  return for_each_node (mark_detached_root, info, &depth, false);
}

/* qsort predicate to sort calls by priority, max_depth then count.  */

static int
sort_calls (const void *a, const void *b)
{
  const struct call_info *const *c1 = a;
  const struct call_info *const *c2 = b;

  if ((*c1)->priority != (*c2)->priority)
    return ((*c2)->priority > (*c1)->priority) ? 1 : -1;

  if ((*c1)->max_depth != (*c2)->max_depth)
    return ((*c2)->max_depth > (*c1)->max_depth) ? 1 : -1;

  if ((*c1)->count != (*c2)->count)
    return ((*c2)->count > (*c1)->count) ? 1 : -1;

  return (a < b) ? -1 : 1;
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

static char *
get_rodata_name_from_text_name (const char *text_name)
{
  char *rodata_name;
  size_t len = strlen (text_name);

  if (strcmp (text_name, ".text") == 0)
    {
      rodata_name = bfd_malloc (sizeof (".rodata"));
      if (rodata_name)
	memcpy (rodata_name, ".rodata", sizeof (".rodata"));
      return rodata_name;
    }

  if (startswith (text_name, ".text."))
    {
      const char *suffix = text_name + sizeof (".text.") - 1;
      const size_t prefix_len = sizeof (".rodata.") - 1;
      const size_t suffix_len = strlen (suffix);
      rodata_name = bfd_malloc (prefix_len + suffix_len + 1);
      if (rodata_name)
	{
	  memcpy (rodata_name, ".rodata.", prefix_len);
	  memcpy (rodata_name + prefix_len, suffix, suffix_len + 1);
	}
      return rodata_name;
    }

  if (startswith (text_name, ".gnu.linkonce.t."))
    {
      rodata_name = bfd_malloc (len + 1);
      if (rodata_name)
	{
	  memcpy (rodata_name, text_name, len + 1);
	  rodata_name[14] = 'r';
	}
      return rodata_name;
    }

  return NULL;
}

static asection *
find_rodata_section (asection *text_sec, const char *name)
{
  asection *group_sec = elf_section_data (text_sec)->next_in_group;

  if (group_sec == NULL)
    return bfd_get_section_by_name (text_sec->owner, name);

  while (group_sec != NULL && group_sec != text_sec)
    {
      if (strcmp (group_sec->name, name) == 0)
	return group_sec;
      group_sec = elf_section_data (group_sec)->next_in_group;
    }

  return NULL;
}

static unsigned int
handle_rodata_section (struct function_info *fun,
		       const struct spu_link_hash_table *htab,
		       unsigned int text_size)
{
  unsigned int rodata_size = 0;
  char *name = get_rodata_name_from_text_name (fun->sec->name);

  if (name == NULL)
    return 0;

  asection *rodata = find_rodata_section (fun->sec, name);
  fun->rodata = rodata;

  if (rodata)
    {
      rodata_size = rodata->size;
      if (htab->params->line_size != 0
	  && (text_size + rodata_size) > htab->params->line_size)
	{
	  fun->rodata = NULL;
	  rodata_size = 0;
	}
      else
	{
	  rodata->linker_mark = 1;
	  rodata->gc_mark = 1;
	  rodata->flags &= ~SEC_CODE;
	}
    }

  free (name);
  return rodata_size;
}

static bool
is_eligible_for_marking (const struct function_info *fun,
			 const struct spu_link_hash_table *htab)
{
  if (fun->sec->linker_mark)
    return false;

  return (htab->params->ovly_flavour != ovly_soft_icache
	  || htab->params->non_ia_text
	  || startswith (fun->sec->name, ".text.ia.")
	  || strcmp (fun->sec->name, ".init") == 0
	  || strcmp (fun->sec->name, ".fini") == 0);
}

static void
mark_main_and_rodata_sections (struct function_info *fun,
			       struct bfd_link_info *info,
			       struct _mos_param *mos_param)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  unsigned int total_size;

  if (!is_eligible_for_marking (fun, htab))
    return;

  fun->sec->linker_mark = 1;
  fun->sec->gc_mark = 1;
  fun->sec->segment_mark = 0;
  fun->sec->flags |= SEC_CODE;

  total_size = fun->sec->size;
  if (htab->params->auto_overlay & OVERLAY_RODATA)
    total_size += handle_rodata_section (fun, htab, total_size);

  if (mos_param->max_overlay_size < total_size)
    mos_param->max_overlay_size = total_size;
}

static bool
sort_call_list (struct function_info *fun)
{
  struct call_info *call;
  unsigned int count = 0;

  for (call = fun->call_list; call != NULL; call = call->next)
    count++;

  if (count <= 1)
    return true;

  struct call_info **calls = bfd_malloc (count * sizeof (*calls));
  if (calls == NULL)
    return false;

  count = 0;
  for (call = fun->call_list; call != NULL; call = call->next)
    calls[count++] = call;

  qsort (calls, count, sizeof (*calls), sort_calls);

  fun->call_list = NULL;
  while (count != 0)
    {
      --count;
      calls[count]->next = fun->call_list;
      fun->call_list = calls[count];
    }
  free (calls);
  return true;
}

static bool
recursively_mark_calls (struct function_info *fun,
			struct bfd_link_info *info,
			void *param)
{
  struct call_info *call;
  for (call = fun->call_list; call != NULL; call = call->next)
    {
      if (call->is_pasted)
	{
	  BFD_ASSERT (!fun->sec->segment_mark);
	  fun->sec->segment_mark = 1;
	}
      if (!call->broken_cycle
	  && !mark_overlay_section (call->fun, info, param))
	return false;
    }
  return true;
}

static void
unmark_if_entry_code (struct function_info *fun,
		      const struct bfd_link_info *info)
{
  bfd_vma start_vma = (fun->lo + fun->sec->output_offset
		       + fun->sec->output_section->vma);

  if (start_vma == info->output_bfd->start_address
      || startswith (fun->sec->output_section->name, ".ovl.init"))
    {
      fun->sec->linker_mark = 0;
      if (fun->rodata != NULL)
	fun->rodata->linker_mark = 0;
    }
}

static bool
mark_overlay_section (struct function_info *fun,
		      struct bfd_link_info *info,
		      void *param)
{
  if (fun->visit4)
    return true;
  fun->visit4 = true;

  mark_main_and_rodata_sections (fun, info, (struct _mos_param *) param);

  if (!sort_call_list (fun))
    return false;

  if (!recursively_mark_calls (fun, info, param))
    return false;

  unmark_if_entry_code (fun, info);

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
  (void) info;

  if (fun == NULL || param == NULL)
    {
      return false;
    }

  if (fun->visit5)
    {
      return true;
    }
  fun->visit5 = true;

  struct _uos_param *uos_param = param;
  bool result = true;

  const bool is_excluded = (fun->sec == uos_param->exclude_input_section
			    || fun->sec->output_section == uos_param->exclude_output_section);

  if (RECURSE_UNMARK && is_excluded)
    {
      uos_param->clearing++;
    }

  const bool should_unmark = RECURSE_UNMARK ? (uos_param->clearing > 0) : is_excluded;

  if (should_unmark)
    {
      fun->sec->linker_mark = 0;
      if (fun->rodata != NULL)
	{
	  fun->rodata->linker_mark = 0;
	}
    }

  for (struct call_info *call = fun->call_list; call != NULL; call = call->next)
    {
      if (!call->broken_cycle)
	{
	  if (!unmark_overlay_section (call->fun, info, param))
	    {
	      result = false;
	      break;
	    }
	}
    }

  if (RECURSE_UNMARK && is_excluded)
    {
      uos_param->clearing--;
    }

  return result;
}

struct _cl_param {
  unsigned int lib_size;
  asection **lib_sections;
};

/* Add sections we have marked as belonging to overlays to an array
   for consideration as non-overlay sections.  The array consist of
   pairs of sections, (text,rodata), for functions in the call graph.  */

static bool
collect_lib_sections (struct function_info *fun,
		      struct bfd_link_info *info,
		      void *param)
{
  struct _cl_param *lib_param = param;
  struct call_info *call;
  unsigned int size;
  void *rodata_to_add;

  (void) info;

  if (fun->visit6)
    return true;

  fun->visit6 = true;

  if (fun->sec->linker_mark && fun->sec->gc_mark && !fun->sec->segment_mark)
    {
      size = fun->sec->size;
      if (fun->rodata)
	size += fun->rodata->size;

      if (size <= lib_param->lib_size)
	{
	  *lib_param->lib_sections++ = fun->sec;
	  fun->sec->gc_mark = 0;

	  rodata_to_add = NULL;
	  if (fun->rodata && fun->rodata->linker_mark && fun->rodata->gc_mark)
	    {
	      rodata_to_add = fun->rodata;
	      fun->rodata->gc_mark = 0;
	    }
	  *lib_param->lib_sections++ = rodata_to_add;
	}
    }

  for (call = fun->call_list; call != NULL; call = call->next)
    {
      if (!call->broken_cycle)
	collect_lib_sections (call->fun, info, param);
    }

  return true;
}

/* qsort predicate to sort sections by call count.  */

static int
get_total_call_count (const asection *sec)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  if (sec_data && sec_data->u.i.stack_info)
    {
      struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
      int total_calls = 0;
      for (int i = 0; i < sinfo->num_fun; ++i)
        {
          total_calls += sinfo->fun[i].call_count;
        }
      return total_calls;
    }
  return 0;
}

static int
sort_lib (const void *a, const void *b)
{
  const asection *s1 = *(const asection *const *) a;
  const asection *s2 = *(const asection *const *) b;

  int call_count1 = get_total_call_count (s1);
  int call_count2 = get_total_call_count (s2);

  int delta = call_count2 - call_count1;
  if (delta != 0)
    {
      return delta;
    }

  if (a > b)
    {
      return 1;
    }
  if (a < b)
    {
      return -1;
    }
  return 0;
}

/* Remove some sections from those marked to be in overlays.  Choose
   those that are called from many places, likely library functions.  */

static void
free_dummy_caller_list (struct function_info *dummy_caller)
{
  struct call_info *call = dummy_caller->call_list;
  while (call)
    {
      struct call_info *next = call->next;
      free (call);
      call = next;
    }
  dummy_caller->call_list = NULL;
}

static unsigned int
calculate_new_stub_size (asection *sec,
			 const struct function_info *dummy_caller,
			 struct spu_link_hash_table *htab)
{
  unsigned int size = 0;
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo;

  if (!sec_data || !(sinfo = sec_data->u.i.stack_info))
    return 0;

  for (int k = 0; k < sinfo->num_fun; ++k)
    {
      for (struct call_info *call = sinfo->fun[k].call_list; call;
	   call = call->next)
	{
	  bool already_exists = false;
	  if (!call->fun->sec->linker_mark)
	    continue;

	  for (struct call_info *p = dummy_caller->call_list; p; p = p->next)
	    {
	      if (p->fun == call->fun)
		{
		  already_exists = true;
		  break;
		}
	    }
	  if (!already_exists)
	    size += ovl_stub_size (htab->params);
	}
    }
  return size;
}

static bool
add_new_stubs (asection *sec, struct function_info *dummy_caller)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo;

  if (!sec_data || !(sinfo = sec_data->u.i.stack_info))
    return true;

  for (int k = 0; k < sinfo->num_fun; ++k)
    {
      for (struct call_info *call = sinfo->fun[k].call_list; call;
	   call = call->next)
	{
	  if (call->fun->sec->linker_mark)
	    {
	      struct call_info *callee = bfd_malloc (sizeof (*callee));
	      if (!callee)
		return false;
	      *callee = *call;
	      if (!insert_callee (dummy_caller, callee))
		free (callee);
	    }
	}
    }
  return true;
}

static unsigned int
remove_obsolete_stubs (struct function_info *dummy_caller,
		       struct spu_link_hash_table *htab)
{
  unsigned int reclaimed_size = 0;
  struct call_info **p_next = &dummy_caller->call_list;
  while (*p_next)
    {
      struct call_info *current = *p_next;
      if (!current->fun->sec->linker_mark)
	{
	  reclaimed_size += ovl_stub_size (htab->params);
	  *p_next = current->next;
	  free (current);
	}
      else
	{
	  p_next = &current->next;
	}
    }
  return reclaimed_size;
}

static unsigned int
auto_ovl_lib_functions (struct bfd_link_info *info, unsigned int lib_size)
{
  asection **lib_sections = NULL;
  unsigned int lib_count = 0;
  struct function_info dummy_caller;
  unsigned int final_lib_size = (unsigned int)-1;

  memset (&dummy_caller, 0, sizeof (dummy_caller));

  extern const bfd_target spu_elf32_vec;
  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (ibfd->xvec != &spu_elf32_vec)
	continue;

      for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
	if (sec->linker_mark && sec->size < lib_size
	    && (sec->flags & SEC_CODE) != 0)
	  lib_count++;
    }

  if (lib_count == 0)
    return lib_size;

  lib_sections = bfd_malloc (lib_count * 2 * sizeof (*lib_sections));
  if (lib_sections == NULL)
    goto cleanup;

  struct _cl_param collect_lib_param;
  collect_lib_param.lib_size = lib_size;
  collect_lib_param.lib_sections = lib_sections;
  if (!for_each_node (collect_lib_sections, info, &collect_lib_param, true))
    goto cleanup;

  lib_count = (collect_lib_param.lib_sections - lib_sections) / 2;

  if (lib_count > 1)
    qsort (lib_sections, lib_count, 2 * sizeof (*lib_sections), sort_lib);

  struct spu_link_hash_table *htab = spu_hash_table (info);

  for (unsigned int i = 0; i < lib_count; i++)
    {
      asection *sec = lib_sections[2 * i];
      asection *rodata_sec = lib_sections[2 * i + 1];

      unsigned int section_pair_size = sec->size;
      if (rodata_sec)
	section_pair_size += rodata_sec->size;

      if (section_pair_size >= lib_size)
	continue;

      unsigned int new_stubs_size
	= calculate_new_stub_size (sec, &dummy_caller, htab);

      if (section_pair_size + new_stubs_size < lib_size)
	{
	  sec->linker_mark = 0;
	  if (rodata_sec)
	    rodata_sec->linker_mark = 0;

	  lib_size -= (section_pair_size + new_stubs_size);
	  lib_size += remove_obsolete_stubs (&dummy_caller, htab);

	  if (!add_new_stubs (sec, &dummy_caller))
	    goto cleanup;
	}
    }

  for (unsigned int i = 0; i < 2 * lib_count; i++)
    if (lib_sections[i])
      lib_sections[i]->gc_mark = 1;

  final_lib_size = lib_size;

cleanup:
  free_dummy_caller_list (&dummy_caller);
  free (lib_sections);

  return final_lib_size;
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
  struct call_info *call;
  asection ***ovly_sections = param;
  bool added_fun = false;

  if (fun->visit7)
    return true;

  fun->visit7 = true;

  for (call = fun->call_list; call != NULL; call = call->next)
    {
      if (!call->is_pasted && !call->broken_cycle)
	{
	  if (!collect_overlays (call->fun, info, ovly_sections))
	    return false;
	  break;
	}
    }

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
	  struct function_info *pasted_fun = fun;
	  while (pasted_fun->sec->segment_mark)
	    {
	      struct call_info *pasted_call = NULL;
	      for (call = pasted_fun->call_list; call != NULL; call = call->next)
		{
		  if (call->is_pasted)
		    {
		      pasted_call = call;
		      break;
		    }
		}

	      if (pasted_call == NULL)
		return false;

	      pasted_fun = pasted_call->fun;
	      pasted_fun->sec->gc_mark = 0;
	      if (pasted_fun->rodata)
		pasted_fun->rodata->gc_mark = 0;
	    }
	}
    }

  for (call = fun->call_list; call != NULL; call = call->next)
    {
      if (!call->broken_cycle
	  && !collect_overlays (call->fun, info, ovly_sections))
	return false;
    }

  if (added_fun)
    {
      struct _spu_elf_section_data *sec_data = spu_elf_section_data (fun->sec);
      if (sec_data != NULL && sec_data->u.i.stack_info != NULL)
	{
	  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
	  for (int i = 0; i < sinfo->num_fun; ++i)
	    {
	      if (!collect_overlays (&sinfo->fun[i], info, ovly_sections))
		return false;
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
is_not_pure_tail_call (const struct call_info *call)
{
  return !call->is_tail || call->is_pasted || call->fun->start != NULL;
}

static void
print_call_details (struct function_info *fun,
		    struct bfd_link_info *info,
		    struct function_info *max_callee)
{
  struct call_info *call;

  info->callbacks->minfo (_("  calls:\n"));
  for (call = fun->call_list; call; call = call->next)
    {
      if (call->is_pasted || call->broken_cycle)
	continue;

      const char *callee_name = func_name (call->fun);
      const char *is_max_marker = (call->fun == max_callee) ? "*" : " ";
      const char *is_tail_marker = call->is_tail ? "t" : " ";

      info->callbacks->minfo ("   %s%s %s\n", is_max_marker,
			      is_tail_marker, callee_name);
    }
}

static void
report_stack_usage (struct function_info *fun,
		    struct bfd_link_info *info,
		    const char *f1,
		    size_t local_stack,
		    size_t cum_stack,
		    struct function_info *max_callee,
		    bool has_call)
{
  if (!fun->non_root)
    info->callbacks->info ("  %s: 0x%v\n", f1, (bfd_vma) cum_stack);

  info->callbacks->minfo ("%s: 0x%v 0x%v\n",
			  f1, (bfd_vma) local_stack, (bfd_vma) cum_stack);

  if (has_call)
    print_call_details (fun, info, max_callee);
}

static bool
emit_stack_symbol (struct function_info *fun,
		   struct bfd_link_info *info,
		   const char *f1,
		   size_t cum_stack)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  struct elf_link_hash_entry *h;
  size_t name_len;
  char *name;

  name_len = sizeof ("__stack_") + 8 + 1 + strlen (f1);
  name = bfd_malloc (name_len);
  if (name == NULL)
    return false;

  if (fun->global || ELF_ST_BIND (fun->u.sym->st_info) == STB_GLOBAL)
    snprintf (name, name_len, "__stack_%s", f1);
  else
    snprintf (name, name_len, "__stack_%x_%s", fun->sec->id & 0xffffffff, f1);

  h = elf_link_hash_lookup (&htab->elf, name, true, true, false);
  free (name);

  if (h != NULL
      && (h->root.type == bfd_link_hash_new
	  || h->root.type == bfd_link_hash_undefined
	  || h->root.type == bfd_link_hash_undefweak))
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

static bool
sum_stack (struct function_info *fun,
	   struct bfd_link_info *info,
	   void *param)
{
  struct _sum_stack_param *sum_stack_param = param;
  size_t local_stack = fun->stack;
  size_t cum_stack = local_stack;
  struct function_info *max_callee = NULL;
  bool has_call = false;

  if (fun->visit3)
    {
      sum_stack_param->cum_stack = fun->stack;
      return true;
    }

  for (struct call_info *call = fun->call_list; call; call = call->next)
    {
      size_t path_stack;

      if (call->broken_cycle)
	continue;

      if (!call->is_pasted)
	has_call = true;

      if (!sum_stack (call->fun, info, sum_stack_param))
	return false;

      path_stack = sum_stack_param->cum_stack;

      /* Include caller stack for normal calls, but not for pure
	 tail calls. local_stack is this function's local usage.  */
      if (is_not_pure_tail_call (call))
	path_stack += local_stack;

      if (cum_stack < path_stack)
	{
	  cum_stack = path_stack;
	  max_callee = call->fun;
	}
    }

  sum_stack_param->cum_stack = cum_stack;
  /* Now fun->stack holds cumulative stack.  */
  fun->stack = cum_stack;
  fun->visit3 = true;

  if (!fun->non_root && sum_stack_param->overall_stack < cum_stack)
    sum_stack_param->overall_stack = cum_stack;

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (htab->params->auto_overlay)
    return true;

  const char *f1 = func_name (fun);
  if (htab->params->stack_analysis)
    report_stack_usage (fun, info, f1, local_stack, cum_stack,
			max_callee, has_call);

  if (sum_stack_param->emit_stack_syms)
    return emit_stack_symbol (fun, info, f1, cum_stack);

  return true;
}

/* SEC is part of a pasted function.  Return the call_info for the
   next section of this function.  */

static struct call_info *
find_pasted_call (asection *sec)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;

  for (int k = 0; k < sinfo->num_fun; ++k)
    {
      for (struct call_info *call = sinfo->fun[k].call_list; call != NULL; call = call->next)
        {
          if (call->is_pasted)
            {
              return call;
            }
        }
    }

  return NULL;
}

/* qsort predicate to sort bfds by file name.  */

static int
sort_bfds (const void *a, const void *b)
{
  const bfd *bfd_a = *(const bfd **)a;
  const bfd *bfd_b = *(const bfd **)b;

  return filename_cmp (bfd_get_filename (bfd_a), bfd_get_filename (bfd_b));
}

static int
print_section_info (FILE *script, asection *sec, struct bfd_link_info *info)
{
  if (sec == NULL)
    return 0;

  const char *archive_name = (sec->owner->my_archive != NULL
			      ? bfd_get_filename (sec->owner->my_archive)
			      : "");

  if (fprintf (script, "   %s%c%s (%s)\n",
	       archive_name,
	       info->path_separator,
	       bfd_get_filename (sec->owner),
	       sec->name) <= 0)
    return -1;

  return 0;
}

static struct call_info *
find_next_pasted_call (const struct function_info *fun)
{
  struct call_info *call;

  for (call = fun->call_list; call != NULL; call = call->next)
    if (call->is_pasted)
      return call;

  return NULL;
}

static int
print_pasted_call_sub_sections (FILE *script,
				asection *start_sec,
				struct bfd_link_info *info,
				asection *(*get_sub_section) (const struct function_info *))
{
  struct call_info *call = find_pasted_call (start_sec);

  while (call != NULL)
    {
      const struct function_info *call_fun = call->fun;
      asection *sub_sec = get_sub_section (call_fun);

      if (print_section_info (script, sub_sec, info) != 0)
	return -1;

      call = find_next_pasted_call (call_fun);
    }

  return 0;
}

static asection *
get_fun_sec (const struct function_info *fun)
{
  return fun->sec;
}

static asection *
get_fun_rodata (const struct function_info *fun)
{
  return fun->rodata;
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

      if (print_section_info (script, sec, info) != 0)
	return -1;

      if (sec->segment_mark)
	{
	  if (print_pasted_call_sub_sections (script, sec, info, get_fun_sec) != 0)
	    return -1;
	}
    }

  for (j = base; j < count && ovly_map[j] == ovlynum; j++)
    {
      asection *sec = ovly_sections[2 * j + 1];

      if (print_section_info (script, sec, info) != 0)
	return -1;

      sec = ovly_sections[2 * j];
      if (sec->segment_mark)
	{
	  if (print_pasted_call_sub_sections (script, sec, info, get_fun_rodata) != 0)
	    return -1;
	}
    }

  return j;
}

/* Handle --auto-overlay.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define QUADWORD_SIZE 16
#define SPU_LMA_OVLY_OFFSET_SHIFT 18

#define FPRINTF_CHECK(STREAM, ...) \
  do { \
    if (fprintf (STREAM, __VA_ARGS__) < 0) \
      return false; \
  } while (0)

static void *
safe_bfd_malloc (bfd_size_type size)
{
  void *mem = bfd_malloc (size);
  if (mem == NULL)
    bfd_set_error (bfd_error_no_memory);
  return mem;
}

static void
find_loadable_extents (struct bfd_link_info *info, unsigned int *lo, unsigned int *hi)
{
  *lo = (unsigned int) -1;
  *hi = 0;

  for (struct elf_segment_map *m = elf_seg_map (info->output_bfd); m; m = m->next)
    {
      if (m->p_type != PT_LOAD)
	continue;
      for (unsigned int i = 0; i < m->count; i++)
	{
	  asection *sec = m->sections[i];
	  if (sec->size != 0)
	    {
	      if (sec->vma < *lo)
		*lo = sec->vma;
	      unsigned int sec_hi = sec->vma + sec->size - 1;
	      if (sec_hi > *hi)
		*hi = sec_hi;
	    }
	}
    }
}

static bool
calculate_reserved_stack (struct bfd_link_info *info, unsigned int *reserved)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  *reserved = htab->params->auto_overlay_reserved;

  if (*reserved == 0)
    {
      struct _sum_stack_param ssp = {0};
      if (!for_each_node (sum_stack, info, &ssp, true))
	return false;
      *reserved = ssp.overall_stack + htab->params->extra_stack_space;
    }
  return true;
}

static unsigned int
handle_overlay_manager (struct bfd_link_info *info, struct _uos_param *uos_param)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  const char *entry = (htab->params->ovly_flavour == ovly_soft_icache
		       ? "__icache_br_handler" : "__ovly_load");

  struct elf_link_hash_entry *h = elf_link_hash_lookup (&htab->elf, entry, false, false, false);
  if (h && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) && h->def_regular)
    {
      uos_param->exclude_input_section = h->root.u.def.section;
      return 0;
    }
  return (*htab->params->spu_elf_load_ovl_mgr) ();
}

static bool
count_and_check_overlay_files (struct bfd_link_info *info, unsigned int *count,
			       unsigned int *total_overlay_size,
			       unsigned int *fixed_size)
{
  unsigned int bfd_count = 0;
  for (bfd *ibfd = info->input_bfds; ibfd; ibfd = ibfd->link.next)
    bfd_count++;

  bfd **bfd_arr = safe_bfd_malloc (bfd_count * sizeof (*bfd_arr));
  if (!bfd_arr)
    return false;

  unsigned int ovly_bfd_count = 0;
  *count = 0;
  *total_overlay_size = 0;
  for (bfd *ibfd = info->input_bfds; ibfd; ibfd = ibfd->link.next)
    {
      extern const bfd_target spu_elf32_vec;
      if (ibfd->xvec != &spu_elf32_vec)
	continue;

      unsigned int old_count = *count;
      for (asection *sec = ibfd->sections; sec; sec = sec->next)
	{
	  if (sec->linker_mark)
	    {
	      if ((sec->flags & SEC_CODE) != 0)
		(*count)++;
	      *fixed_size -= sec->size;
	      *total_overlay_size += sec->size;
	    }
	  else if ((sec->flags & (SEC_ALLOC | SEC_LOAD)) == (SEC_ALLOC | SEC_LOAD)
		   && sec->output_section->owner == info->output_bfd
		   && startswith (sec->output_section->name, ".ovl.init"))
	    {
	      *fixed_size -= sec->size;
	    }
	}
      if (*count != old_count)
	bfd_arr[ovly_bfd_count++] = ibfd;
    }

  bool ok = true;
  if (ovly_bfd_count > 1)
    {
      qsort (bfd_arr, ovly_bfd_count, sizeof (*bfd_arr), sort_bfds);
      for (unsigned int i = 1; i < ovly_bfd_count; ++i)
	if (filename_cmp (bfd_get_filename (bfd_arr[i - 1]), bfd_get_filename (bfd_arr[i])) == 0
	    && bfd_arr[i - 1]->my_archive == bfd_arr[i]->my_archive)
	  {
	    if (bfd_arr[i - 1]->my_archive)
	      info->callbacks->einfo (_("%s duplicated in %s\n"), bfd_get_filename (bfd_arr[i]), bfd_get_filename (bfd_arr[i]->my_archive));
	    else
	      info->callbacks->einfo (_("%s duplicated\n"), bfd_get_filename (bfd_arr[i]));
	    ok = false;
	  }
      if (!ok)
	{
	  info->callbacks->einfo (_("sorry, no support for duplicate object files in auto-overlay script\n"));
	  bfd_set_error (bfd_error_bad_value);
	}
    }
  free (bfd_arr);
  return ok;
}

static void
adjust_fixed_size_for_tables (struct spu_link_hash_table *htab,
			      unsigned int *fixed_size,
			      unsigned int total_overlay_size)
{
  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      unsigned int num_lines = 1U << htab->num_lines_log2;
      *fixed_size += htab->non_ovly_stub * QUADWORD_SIZE;
      *fixed_size += QUADWORD_SIZE * num_lines; /* Tag array */
      *fixed_size += QUADWORD_SIZE * num_lines; /* Rewrite "to" list */
      *fixed_size += QUADWORD_SIZE << (htab->fromelem_size_log2 + htab->num_lines_log2); /* Rewrite "from" list */
      *fixed_size += QUADWORD_SIZE; /* Pointer to __ea backing store */
    }
  else
    {
      unsigned int ovlynum = (total_overlay_size * 2 * htab->params->num_lines
			      / (htab->local_store - *fixed_size));
      *fixed_size += ovlynum * QUADWORD_SIZE + QUADWORD_SIZE + 4 + QUADWORD_SIZE;
    }
}

static void
cleanup_dummy_caller (struct function_info *dummy)
{
  while (dummy->call_list)
    {
      struct call_info *call = dummy->call_list;
      dummy->call_list = call->next;
      free (call);
    }
}

static bool
map_sections_to_overlays (struct bfd_link_info *info,
			  unsigned int count, asection **ovly_sections,
			  unsigned int fixed_size, unsigned int **ovly_map_ptr,
			  unsigned int *ovlynum_ptr)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  *ovly_map_ptr = safe_bfd_malloc (count * sizeof (unsigned int));
  if (!*ovly_map_ptr)
    return false;
  unsigned int *ovly_map = *ovly_map_ptr;

  unsigned int overlay_size = htab->params->line_size != 0
    ? htab->params->line_size
    : (htab->local_store - fixed_size) / htab->params->num_lines;
  struct function_info dummy_caller = {0};
  unsigned int base = 0;
  *ovlynum_ptr = 0;

  while (base < count)
    {
      unsigned int size = 0, rosize = 0, roalign = 0;
      unsigned int i;
      for (i = base; i < count; i++)
	{
	  asection *sec = ovly_sections[2 * i];
	  asection *rosec = ovly_sections[2 * i + 1];
	  unsigned int tmp = align_power (size, sec->alignment_power) + sec->size;
	  unsigned int rotmp = rosize;
	  unsigned int new_roalign = roalign;

	  if (rosec)
	    {
	      rotmp = align_power (rotmp, rosec->alignment_power) + rosec->size;
	      if (new_roalign < rosec->alignment_power)
		new_roalign = rosec->alignment_power;
	    }

	  struct call_info *pasty = NULL;
	  if (sec->segment_mark)
	    {
	      pasty = find_pasted_call (sec);
	      struct call_info *p = pasty;
	      while (p)
		{
		  struct function_info *call_fun = p->fun;
		  tmp = align_power (tmp, call_fun->sec->alignment_power) + call_fun->sec->size;
		  if (call_fun->rodata)
		    {
		      rotmp = align_power (rotmp, call_fun->rodata->alignment_power) + call_fun->rodata->size;
		      if (new_roalign < call_fun->rodata->alignment_power)
			new_roalign = call_fun->rodata->alignment_power;
		    }
		  p = NULL;
		  for (struct call_info *next_p = call_fun->call_list; next_p; next_p = next_p->next)
		    if (next_p->is_pasted)
		      p = next_p;
		}
	    }
	  if (align_power (tmp, new_roalign) + rotmp > overlay_size)
	    break;

	  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
	  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
	  for (unsigned int k = 0; k < (unsigned) sinfo->num_fun; ++k)
	    for (struct call_info *call = sinfo->fun[k].call_list; call; call = call->next)
	      if (!call->is_pasted && call->fun->sec->linker_mark)
		if (!copy_callee (&dummy_caller, call))
		  {
		    cleanup_dummy_caller (&dummy_caller);
		    return false;
		  }
	  while (pasty)
	    {
	      struct function_info *call_fun = pasty->fun;
	      pasty = NULL;
	      for (struct call_info *call = call_fun->call_list; call; call = call->next)
		if (call->is_pasted)
		  pasty = call;
		else if (!copy_callee (&dummy_caller, call))
		  {
		    cleanup_dummy_caller (&dummy_caller);
		    return false;
		  }
	    }

	  unsigned int num_stubs = 0;
	  for (struct call_info *call = dummy_caller.call_list; call; call = call->next)
	    {
	      unsigned int stub_delta = (htab->params->ovly_flavour == ovly_soft_icache) ? call->count : 1;
	      bool is_internal_call = false;
	      for (unsigned int k = base; k <= i; k++)
		if (call->fun->sec == ovly_sections[2 * k])
		  {
		    is_internal_call = true;
		    break;
		  }
	      if (!is_internal_call)
		num_stubs += stub_delta;
	    }
	  if (htab->params->ovly_flavour == ovly_soft_icache && num_stubs > htab->params->max_branch)
	    break;
	  if (align_power (tmp, new_roalign) + rotmp + num_stubs * ovl_stub_size (htab->params) > overlay_size)
	    break;
	  size = tmp;
	  rosize = rotmp;
	  roalign = new_roalign;
	}

      cleanup_dummy_caller (&dummy_caller);
      if (i == base)
	{
	  info->callbacks->einfo (_("%pB:%pA%s exceeds overlay size\n"),
				  ovly_sections[2 * i]->owner, ovly_sections[2 * i],
				  ovly_sections[2 * i + 1] ? " + rodata" : "");
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}
      *ovlynum_ptr += 1;
      while (base < i)
	ovly_map[base++] = *ovlynum_ptr;
    }
  return true;
}

static bool
generate_soft_icache_script (FILE *script, struct bfd_link_info *info,
			     unsigned int count, unsigned int *ovly_map,
			     asection **ovly_sections)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  FPRINTF_CHECK (script, "SECTIONS\n{\n");
  FPRINTF_CHECK (script, " . = ALIGN (%u);\n", htab->params->line_size);
  FPRINTF_CHECK (script, " .ovl.init : { *(.ovl.init) }\n");
  FPRINTF_CHECK (script, " . = ABSOLUTE (ADDR (.ovl.init));\n");

  unsigned int base = 0;
  for (unsigned int ovlynum = 1; base < count; ++ovlynum)
    {
      unsigned int indx = ovlynum - 1;
      unsigned int vma = (indx & (htab->params->num_lines - 1)) << htab->line_size_log2;
      unsigned int lma = vma + (((indx >> htab->num_lines_log2) + 1) << SPU_LMA_OVLY_OFFSET_SHIFT);
      FPRINTF_CHECK (script, " .ovly%u ABSOLUTE (ADDR (.ovl.init)) + %u : AT (LOADADDR (.ovl.init) + %u) {\n", ovlynum, vma, lma);
      base = print_one_overlay_section (script, base, count, ovlynum, ovly_map, ovly_sections, info);
      if (base == (unsigned int) -1)
	return false;
      FPRINTF_CHECK (script, "  }\n");
    }

  unsigned int total_icache_size = 1U << (htab->num_lines_log2 + htab->line_size_log2);
  FPRINTF_CHECK (script, " . = ABSOLUTE (ADDR (.ovl.init)) + %u;\n", total_icache_size);
  FPRINTF_CHECK (script, "}\nINSERT AFTER .toe;\n");
  return true;
}

static bool
generate_default_overlay_script (FILE *script, struct bfd_link_info *info,
				 unsigned int count, unsigned int *ovly_map,
				 asection **ovly_sections)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  FPRINTF_CHECK (script, "SECTIONS\n{\n");
  FPRINTF_CHECK (script, " . = ALIGN (16);\n");
  FPRINTF_CHECK (script, " .ovl.init : { *(.ovl.init) }\n");
  FPRINTF_CHECK (script, " . = ABSOLUTE (ADDR (.ovl.init));\n");

  for (unsigned int region = 1; region <= htab->params->num_lines; ++region)
    {
      unsigned int base = 0;
      while (base < count && ovly_map[base] < region)
	base++;
      if (base == count)
	break;

      if (region == 1)
	FPRINTF_CHECK (script, " OVERLAY : AT (ALIGN (LOADADDR (.ovl.init) + SIZEOF (.ovl.init), 16))\n {\n");
      else
	FPRINTF_CHECK (script, " OVERLAY :\n {\n");

      unsigned int ovlynum = region;
      while (base < count)
	{
	  FPRINTF_CHECK (script, "  .ovly%u {\n", ovlynum);
	  base = print_one_overlay_section (script, base, count, ovlynum, ovly_map, ovly_sections, info);
	  if (base == (unsigned int) -1)
	    return false;
	  FPRINTF_CHECK (script, "  }\n");

	  ovlynum += htab->params->num_lines;
	  while (base < count && ovly_map[base] < ovlynum)
	    base++;
	}
      FPRINTF_CHECK (script, " }\n");
    }
  FPRINTF_CHECK (script, "}\nINSERT BEFORE .text;\n");
  return true;
}

static bool
generate_script (FILE *script, struct bfd_link_info *info, unsigned int count,
		 unsigned int *ovly_map, asection **ovly_sections)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (htab->params->ovly_flavour == ovly_soft_icache)
    return generate_soft_icache_script (script, info, count, ovly_map, ovly_sections);
  return generate_default_overlay_script (script, info, count, ovly_map, ovly_sections);
}

static void
spu_elf_auto_overlay (struct bfd_link_info *info)
{
  unsigned int lo, hi, fixed_size, reserved;
  find_loadable_extents (info, &lo, &hi);
  fixed_size = (lo > hi) ? 0 : (hi + 1 - lo);

  if (!discover_functions (info) || !build_call_tree (info))
    goto error;

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (!calculate_reserved_stack (info, &reserved))
    goto error;

  if (fixed_size + reserved <= htab->local_store && htab->params->ovly_flavour != ovly_soft_icache)
    {
      htab->params->auto_overlay = 0;
      return;
    }

  struct _uos_param uos_param = {0};
  uos_param.exclude_output_section = bfd_get_section_by_name (info->output_bfd, ".interrupt");
  fixed_size += handle_overlay_manager (info, &uos_param);

  struct _mos_param mos_param = { .max_overlay_size = 0 };
  if (!for_each_node (mark_overlay_section, info, &mos_param, true))
    goto error;

  if ((uos_param.exclude_input_section || uos_param.exclude_output_section)
      && !for_each_node (unmark_overlay_section, info, &uos_param, true))
    goto error;

  unsigned int count, total_overlay_size;
  if (!count_and_check_overlay_files (info, &count, &total_overlay_size, &fixed_size))
    goto error;

  fixed_size += reserved;
  fixed_size += htab->non_ovly_stub * ovl_stub_size (htab->params);

  if (fixed_size + mos_param.max_overlay_size <= htab->local_store)
    adjust_fixed_size_for_tables (htab, &fixed_size, total_overlay_size);

  if (fixed_size + mos_param.max_overlay_size > htab->local_store)
    {
      info->callbacks->einfo (_("non-overlay size of 0x%v plus maximum overlay size of 0x%v exceeds local store\n"),
			      (bfd_vma) fixed_size, (bfd_vma) mos_param.max_overlay_size);
    }
  else if (fixed_size < htab->params->auto_overlay_fixed)
    {
      unsigned int max_fixed = htab->local_store - mos_param.max_overlay_size;
      if (max_fixed > htab->params->auto_overlay_fixed)
	max_fixed = htab->params->auto_overlay_fixed;
      unsigned int lib_size = auto_ovl_lib_functions (info, max_fixed - fixed_size);
      if (lib_size == (unsigned int) -1)
	goto error;
      fixed_size = max_fixed - lib_size;
    }

  asection **ovly_sections = safe_bfd_malloc (2 * count * sizeof (*ovly_sections));
  if (!ovly_sections)
    goto error;

  asection **ovly_p = ovly_sections;
  if (!for_each_node (collect_overlays, info, &ovly_p, true))
    {
      free (ovly_sections);
      goto error;
    }
  count = (size_t) (ovly_p - ovly_sections) / 2;

  unsigned int *ovly_map = NULL;
  unsigned int ovlynum;
  if (!map_sections_to_overlays (info, count, ovly_sections, fixed_size, &ovly_map, &ovlynum))
    {
      free (ovly_sections);
      free (ovly_map);
      goto error;
    }

  FILE *script = htab->params->spu_elf_open_overlay_script ();
  if (!script)
    {
      bfd_set_error (bfd_error_system_call);
      free (ovly_sections);
      free (ovly_map);
      goto error;
    }

  if (!generate_script (script, info, count, ovly_map, ovly_sections))
    {
      bfd_set_error (bfd_error_system_call);
      fclose (script);
      free (ovly_sections);
      free (ovly_map);
      goto error;
    }

  free (ovly_map);
  free (ovly_sections);
  if (fclose (script) != 0)
    {
      bfd_set_error (bfd_error_system_call);
      goto error;
    }

  if (htab->params->auto_overlay & AUTO_RELINK)
    (*htab->params->spu_elf_relink) ();

  xexit (0);

error:
  info->callbacks->fatal (_("%P: auto overlay error: %E\n"));
}

/* Provide an estimate of total stack required.  */

static bool
spu_elf_stack_analysis (struct bfd_link_info *info)
{
  if (!discover_functions (info))
    return false;

  if (!build_call_tree (info))
    return false;

  struct spu_link_hash_table *htab = spu_hash_table (info);
  const bool perform_reporting = htab->params->stack_analysis;

  if (perform_reporting)
    {
      info->callbacks->info (_("Stack size for call graph root nodes.\n"));
      info->callbacks->minfo (_("\nStack size for functions.  "
				"Annotations: '*' max stack, 't' tail call\n"));
    }

  struct _sum_stack_param sum_stack_param = {
    .emit_stack_syms = htab->params->emit_stack_syms,
    .overall_stack = 0
  };

  if (!for_each_node (sum_stack, info, &sum_stack_param, true))
    return false;

  if (perform_reporting)
    info->callbacks->info (_("Maximum stack required is 0x%v\n"),
			   (bfd_vma) sum_stack_param.overall_stack);

  return true;
}

/* Perform a final link.  */

static bool
spu_elf_final_link (bfd *output_bfd, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  struct spu_params *params = htab->params;

  if (params->auto_overlay)
    {
      spu_elf_auto_overlay (info);
    }

  const bool perform_analysis = params->stack_analysis
                             || (params->ovly_flavour == ovly_soft_icache
                                 && params->lrlive_analysis);

  if (perform_analysis)
    {
      if (!spu_elf_stack_analysis (info))
	{
	  info->callbacks->einfo (_("%X%P: stack/lrlive analysis error: %E\n"));
	}
    }

  if (!spu_elf_build_stubs (info))
    {
      info->callbacks->fatal (_("%P: can not build overlay stubs: %E\n"));
    }

  return bfd_elf_final_link (output_bfd, info);
}

/* Called when not normally emitting relocs, ie. !bfd_link_relocatable (info)
   and !info->emitrelocations.  Returns a count of special relocs
   that need to be emitted.  */

static unsigned int
spu_elf_count_relocs (struct bfd_link_info *info, asection *sec)
{
  Elf_Internal_Rela *relocs;
  unsigned int count = 0;

  relocs = _bfd_elf_link_read_relocs (sec->owner, sec, NULL, NULL,
				      info->keep_memory);
  if (relocs == NULL)
    return 0;

  const Elf_Internal_Rela *relend = relocs + sec->reloc_count;
  for (const Elf_Internal_Rela *rel = relocs; rel < relend; rel++)
    {
      const int r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
	++count;
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

  if (sfixup->reloc_count > 0)
    {
      bfd_vma last_index = sfixup->reloc_count - 1;
      bfd_vma last_base = FIXUP_GET (output_bfd, htab, last_index);

      if (qaddr == (last_base & ~(bfd_vma) 15))
	{
	  FIXUP_PUT (output_bfd, htab, last_index, last_base | bit);
	  return;
	}
    }

  if ((sfixup->reloc_count + 1) * FIXUP_RECORD_SIZE > sfixup->size)
    _bfd_error_handler (_("fatal error while creating .fixup"));

  FIXUP_PUT (output_bfd, htab, sfixup->reloc_count, qaddr | bit);
  sfixup->reloc_count++;
}

/* Apply RELOCS to CONTENTS of INPUT_SECTION from INPUT_BFD.  */

static bool
get_symbol_info (bfd *output_bfd, struct bfd_link_info *info,
                 bfd *input_bfd, asection *input_section,
                 Elf_Internal_Rela *rel, Elf_Internal_Sym *local_syms,
                 asection **local_sections, struct elf_link_hash_entry **h_p,
                 Elf_Internal_Sym **sym_p, asection **sec_p,
                 const char **sym_name_p, bfd_vma *relocation_p,
                 bool *unresolved_p)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
  unsigned int r_symndx = ELF32_R_SYM (rel->r_info);

  *h_p = NULL;
  *sym_p = NULL;
  *sec_p = NULL;
  *relocation_p = 0;
  *unresolved_p = false;

  if (r_symndx < symtab_hdr->sh_info)
    {
      *sym_p = local_syms + r_symndx;
      *sec_p = local_sections[r_symndx];
      *sym_name_p = bfd_elf_sym_name (input_bfd, symtab_hdr, *sym_p, *sec_p);
      *relocation_p = _bfd_elf_rela_local_sym (output_bfd, *sym_p, sec_p, rel);
    }
  else
    {
      if (sym_hashes == NULL)
        return false;

      struct elf_link_hash_entry *h = sym_hashes[r_symndx - symtab_hdr->sh_info];

      if (info->wrap_hash != NULL && (input_section->flags & SEC_DEBUGGING) != 0)
        h = ((struct elf_link_hash_entry *)
             unwrap_hash_lookup (info, input_bfd, &h->root));

      while (h->root.type == bfd_link_hash_indirect
             || h->root.type == bfd_link_hash_warning)
        h = (struct elf_link_hash_entry *) h->root.u.i.link;

      *h_p = h;
      *sym_name_p = h->root.root.string;

      if (h->root.type == bfd_link_hash_defined
          || h->root.type == bfd_link_hash_defweak)
        {
          *sec_p = h->root.u.def.section;
          if (*sec_p == NULL || (*sec_p)->output_section == NULL)
            *unresolved_p = true;
          else
            *relocation_p = (h->root.u.def.value
                           + (*sec_p)->output_section->vma
                           + (*sec_p)->output_offset);
        }
      else if (h->root.type != bfd_link_hash_undefweak
               && (info->unresolved_syms_in_objects != RM_IGNORE
                   || ELF_ST_VISIBILITY (h->other) != STV_DEFAULT))
        {
          int r_type = ELF32_R_TYPE (rel->r_info);
          if (!bfd_link_relocatable (info)
              && !(r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64))
            {
              bool err = ((info->unresolved_syms_in_objects == RM_DIAGNOSE
                           && !info->warn_unresolved_syms)
                          || ELF_ST_VISIBILITY (h->other) != STV_DEFAULT);
              info->callbacks->undefined_symbol
                (info, h->root.root.string, input_bfd,
                 input_section, rel->r_offset, err);
            }
        }
    }
  return true;
}

static struct got_entry *
find_got_entry (struct spu_link_hash_table *htab,
		struct got_entry **head,
		unsigned int ovl,
		bfd_vma addend,
		bfd_vma reloc_offset)
{
  for (struct got_entry *g = *head; g != NULL; g = g->next)
    {
      if (htab->params->ovly_flavour == ovly_soft_icache)
	{
	  if (g->ovl == ovl && g->br_addr == reloc_offset)
	    return g;
	}
      else
	{
	  if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
	    return g;
	}
    }
  return NULL;
}

static bool
handle_overlay_stub (struct bfd_link_info *info, bfd *input_bfd,
                     asection *input_section, Elf_Internal_Rela *rel,
                     bfd_byte *contents, struct elf_link_hash_entry *h,
                     Elf_Internal_Sym *sym, asection *sec,
                     unsigned int iovl, bool is_ea_sym, bool stubs,
                     bfd_vma *relocation_p, bfd_vma *addend_p)
{
  if (!stubs || is_ea_sym)
    return false;

  struct spu_link_hash_table *htab = spu_hash_table (info);
  enum _stub_type stub_type = needs_ovl_stub (h, sym, sec, input_section, rel,
                                              contents, info);
  if (stub_type == no_stub)
    return false;

  unsigned int ovl = (stub_type != nonovl_stub) ? iovl : 0;
  struct got_entry **head;
  if (h != NULL)
    head = &h->got.glist;
  else
    head = elf_local_got_ents (input_bfd) + ELF32_R_SYM (rel->r_info);

  bfd_vma reloc_offset = (rel->r_offset
                          + input_section->output_offset
                          + input_section->output_section->vma);

  struct got_entry *g = find_got_entry(htab, head, ovl, *addend_p, reloc_offset);
  if (g == NULL)
    abort ();

  *relocation_p = g->stub_addr;
  *addend_p = 0;
  return true;
}

static void
handle_soft_icache (struct spu_link_hash_table *htab, int r_type,
                    asection *sec, bool is_ea_sym, bfd_vma *relocation_p)
{
  if (htab->params->ovly_flavour != ovly_soft_icache
      || is_ea_sym
      || (r_type != R_SPU_ADDR16_HI
          && r_type != R_SPU_ADDR32
          && r_type != R_SPU_REL32))
    return;

  unsigned int ovl = overlay_index (sec);
  if (ovl != 0)
    {
      unsigned int set_id = ((ovl - 1) >> htab->num_lines_log2) + 1;
      *relocation_p += set_id << 18;
    }
}

static bool
process_reloc_status (bfd_reloc_status_type r, struct bfd_link_info *info,
                      struct elf_link_hash_entry *h, const char *sym_name,
                      reloc_howto_type *howto, bfd *input_bfd,
                      asection *input_section, Elf_Internal_Rela *rel)
{
  if (r == bfd_reloc_ok)
    return true;

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

  if (msg)
    (*info->callbacks->warning) (info, msg, sym_name, input_bfd,
                                 input_section, rel->r_offset);

  return false;
}

static int
finalize_relocs (asection *input_section, Elf_Internal_Rela *relocs)
{
  Elf_Internal_Rela *wrel = relocs;
  Elf_Internal_Rela *relend = relocs + input_section->reloc_count;

  for (Elf_Internal_Rela *rel = relocs; rel < relend; rel++)
    {
      int r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
        *wrel++ = *rel;
    }
  input_section->reloc_count = wrel - relocs;

  Elf_Internal_Shdr *rel_hdr = _bfd_elf_single_rel_hdr (input_section);
  rel_hdr->sh_size = input_section->reloc_count * rel_hdr->sh_entsize;
  return 2;
}

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
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection *ea = bfd_get_section_by_name (output_bfd, "._ea");
  bool stubs = (htab->stub_sec != NULL && maybe_needs_stubs (input_section));
  unsigned int iovl = overlay_index (input_section);
  bool emit_these_relocs = false;
  int ret = true;

  Elf_Internal_Rela *relend = relocs + input_section->reloc_count;
  for (Elf_Internal_Rela *rel = relocs; rel < relend; rel++)
    {
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *sym;
      asection *sec;
      const char *sym_name;
      bfd_vma relocation;
      bool unresolved_reloc;
      int r_type = ELF32_R_TYPE (rel->r_info);

      if (!get_symbol_info (output_bfd, info, input_bfd, input_section, rel,
			    local_syms, local_sections, &h, &sym, &sec,
			    &sym_name, &relocation, &unresolved_reloc))
	return false;

      reloc_howto_type *howto = elf_howto_table + r_type;
      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, R_SPU_NONE,
					 howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      if (r_type == R_SPU_ADD_PIC && h != NULL
	  && !(h->def_regular || ELF_COMMON_DEF_P (h)))
	{
	  bfd_byte *loc = contents + rel->r_offset;
	  loc[0] = 0x1c;
	  loc[1] = 0x00;
	  loc[2] &= 0x3f;
	}

      bool is_ea_sym = (ea != NULL && sec != NULL && sec->output_section == ea);
      bfd_vma addend = rel->r_addend;

      if (!handle_overlay_stub (info, input_bfd, input_section, rel, contents,
				h, sym, sec, iovl, is_ea_sym, stubs,
				&relocation, &addend))
	{
	  handle_soft_icache (htab, r_type, sec, is_ea_sym, &relocation);
	}

      if (htab->params->emit_fixups && (input_section->flags & SEC_ALLOC) != 0
	  && r_type == R_SPU_ADDR32)
	{
	  bfd_vma offset = (rel->r_offset + input_section->output_section->vma
			    + input_section->output_offset);
	  spu_elf_emit_fixup (output_bfd, info, offset);
	}

      if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
	{
	  if (is_ea_sym)
	    {
	      rel->r_addend += (relocation - ea->vma
				+ elf_section_data(ea)->this_hdr.sh_offset);
	      rel->r_info = ELF32_R_INFO (0, r_type);
	    }
	  emit_these_relocs = true;
	  continue;
	}

      if (is_ea_sym)
	unresolved_reloc = true;

      if (unresolved_reloc
	  && _bfd_elf_section_offset (output_bfd, info, input_section,
				      rel->r_offset) != (bfd_vma) -1)
	{
	  _bfd_error_handler (_("%pB(%s+%#" PRIx64 "): "
				"unresolvable %s relocation against symbol `%s'"),
			      input_bfd, bfd_section_name (input_section),
			      (uint64_t) rel->r_offset, howto->name, sym_name);
	  ret = false;
	}

      bfd_reloc_status_type r =
	_bfd_final_link_relocate (howto, input_bfd, input_section, contents,
				  rel->r_offset, relocation, addend);

      if (!process_reloc_status (r, info, h, sym_name, howto, input_bfd,
				 input_section, rel))
	ret = false;
    }

  if (ret && emit_these_relocs && !info->emitrelocations)
    return finalize_relocs (input_section, relocs);

  return ret;
}

static bool spu_elf_finish_dynamic_sections(bfd *output_bfd ATTRIBUTE_UNUSED,
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
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (h == NULL || htab->stub_sec == NULL || bfd_link_relocatable (info))
    {
      return 1;
    }

  bool is_defined_type = (h->root.type == bfd_link_hash_defined
			  || h->root.type == bfd_link_hash_defweak);

  if (!is_defined_type || !h->def_regular
      || !startswith (h->root.root.string, "_SPUEAR_"))
    {
      return 1;
    }

  for (struct got_entry *g = h->got.glist; g != NULL; g = g->next)
    {
      bool match;
      if (htab->params->ovly_flavour == ovly_soft_icache)
	{
	  match = (g->br_addr == g->stub_addr);
	}
      else
	{
	  match = (g->addend == 0 && g->ovl == 0);
	}

      if (match)
	{
	  asection *output_sec = htab->stub_sec[0]->output_section;
	  sym->st_shndx = _bfd_elf_section_from_bfd_section (output_sec->owner,
							     output_sec);
	  sym->st_value = g->stub_addr;
	  break;
	}
    }

  return 1;
}

static int spu_plugin = 0;

void spu_elf_plugin(int plugin_status)
{
    spu_plugin = plugin_status;
}

/* Set ELF header e_type for plugins.  */

static bool
spu_elf_init_file_header (bfd *abfd, struct bfd_link_info *info)
{
  if (!_bfd_elf_init_file_header (abfd, info))
    return false;

  if (spu_plugin)
    {
      Elf_Internal_Ehdr *i_ehdrp = elf_elfheader (abfd);
      if (i_ehdrp == NULL)
        return false;

      i_ehdrp->e_type = ET_DYN;
    }

  return true;
}

/* We may add an extra PT_LOAD segment for .toe.  We also need extra
   segments for overlays.  */

static int
spu_elf_additional_program_headers (bfd *abfd, struct bfd_link_info *info)
{
  int count = 0;

  if (info)
    {
      const struct spu_link_hash_table *htab = spu_hash_table (info);
      if (htab->num_overlays > 0)
        {
          count = htab->num_overlays + 1;
        }
    }

  const asection *toe_section = bfd_get_section_by_name (abfd, ".toe");
  if (toe_section && (toe_section->flags & SEC_LOAD))
    {
      count++;
    }

  return count;
}

/* Remove .toe section from other PT_LOAD segments and put it in
   a segment of its own.  Put overlays in separate segments too.  */

static bool
spu_elf_modify_segment_map (bfd *abfd, struct bfd_link_info *info)
{
  if (info == NULL)
    return true;

  {
    asection *toe = bfd_get_section_by_name (abfd, ".toe");
    struct elf_segment_map *m;

    for (m = elf_seg_map (abfd); m != NULL; m = m->next)
      {
        if (m->p_type != PT_LOAD || m->count <= 1)
          continue;

        for (unsigned int i = 0; i < m->count; ++i)
          {
            asection *s = m->sections[i];
            if (s != toe && spu_elf_section_data (s)->u.o.ovl_index == 0)
              continue;

            if (i + 1 < m->count)
              {
                unsigned int after_count = m->count - (i + 1);
                size_t alloc_size = sizeof (struct elf_segment_map);
                if (after_count > 1)
                  alloc_size += (after_count - 1) * sizeof (asection *);

                struct elf_segment_map *after_seg = bfd_zalloc (abfd, alloc_size);
                if (after_seg == NULL)
                  return false;

                after_seg->p_type = PT_LOAD;
                after_seg->count = after_count;
                memcpy (after_seg->sections, m->sections + i + 1,
                        after_count * sizeof (asection *));
                after_seg->next = m->next;
                m->next = after_seg;
              }

            if (i > 0)
              {
                struct elf_segment_map *special_seg =
                  bfd_zalloc (abfd, sizeof (struct elf_segment_map));
                if (special_seg == NULL)
                  return false;

                special_seg->p_type = PT_LOAD;
                special_seg->count = 1;
                special_seg->sections[0] = s;
                special_seg->next = m->next;
                m->next = special_seg;
                m->count = i;
              }
            else
              {
                m->count = 1;
              }
            break;
          }
      }
  }

  {
    struct elf_segment_map *overlay_list_head = NULL;
    struct elf_segment_map **overlay_list_tail_p = &overlay_list_head;
    struct elf_segment_map **map_p = &elf_seg_map (abfd);
    struct elf_segment_map **first_load_p = NULL;

    while (*map_p != NULL)
      {
        struct elf_segment_map *current = *map_p;
        bool is_overlay_seg =
          (current->p_type == PT_LOAD && current->count == 1
           && spu_elf_section_data (current->sections[0])->u.o.ovl_index != 0);

        if (current->p_type == PT_LOAD && first_load_p == NULL)
          first_load_p = map_p;

        if (is_overlay_seg)
          {
            current->no_sort_lma = 1;
            *map_p = current->next;
            *overlay_list_tail_p = current;
            overlay_list_tail_p = &current->next;
          }
        else
          {
            map_p = &current->next;
          }
      }
    *overlay_list_tail_p = NULL;

    if (overlay_list_head != NULL)
      {
        struct elf_segment_map **insert_p = first_load_p;
        if (insert_p == NULL)
          insert_p = &elf_seg_map (abfd);
        else if ((*insert_p)->p_type == PT_LOAD && (*insert_p)->includes_filehdr)
          insert_p = &(*insert_p)->next;

        *overlay_list_tail_p = *insert_p;
        *insert_p = overlay_list_head;
      }
  }

  return true;
}

/* Tweak the section type of .note.spu_name.  */

static bool
spu_elf_fake_sections (bfd *obfd ATTRIBUTE_UNUSED,
		       Elf_Internal_Shdr *hdr,
		       asection *sec)
{
  if (hdr && sec && sec->name)
    {
      if (strcmp (sec->name, SPU_PTNOTE_SPUNAME) == 0)
	{
	  hdr->sh_type = SHT_NOTE;
	}
    }
  return true;
}

/* Tweak phdrs before writing them out.  */

static void
spu_elf_handle_overlays (bfd *abfd,
			 struct bfd_link_info *info,
			 Elf_Internal_Phdr *phdr)
{
  enum
  {
    OVLY_TABLE_ENTRY_SIZE = 16,
    OVLY_TABLE_FILE_OFF_OFFSET = 8,
    OVL_INIT_OFFSET = 4
  };
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (htab->num_overlays == 0)
    return;

  struct elf_segment_map *m;
  unsigned int i;
  for (i = 0, m = elf_seg_map (abfd); m; ++i, m = m->next)
    {
      if (m->count == 0)
	continue;

      unsigned int ovl_index =
	spu_elf_section_data (m->sections[0])->u.o.ovl_index;
      if (ovl_index == 0)
	continue;

      phdr[i].p_flags |= PF_OVERLAY;

      if (htab->ovtab != NULL
	  && htab->ovtab->size != 0
	  && htab->params->ovly_flavour != ovly_soft_icache)
	{
	  bfd_byte *p = htab->ovtab->contents;
	  unsigned int off =
	    ovl_index * OVLY_TABLE_ENTRY_SIZE + OVLY_TABLE_FILE_OFF_OFFSET;
	  bfd_put_32 (htab->ovtab->owner, phdr[i].p_offset, p + off);
	}
    }

  if (htab->init != NULL && htab->init->size != 0)
    {
      bfd_vma val =
	elf_section_data (htab->ovl_sec[0])->this_hdr.sh_offset;
      bfd_put_32 (htab->init->owner, val,
		  htab->init->contents + OVL_INIT_OFFSET);
    }
}

static void
spu_elf_round_up_load_segments (Elf_Internal_Phdr *phdr, unsigned int count)
{
  enum { SPU_SEGMENT_ALIGNMENT_MASK = 15 };
  Elf_Internal_Phdr *last = NULL;
  bool can_round_up = true;
  unsigned int i;

  for (i = count; i > 0;)
    {
      --i;
      if (phdr[i].p_type != PT_LOAD)
	continue;

      unsigned int file_adjust = -phdr[i].p_filesz & SPU_SEGMENT_ALIGNMENT_MASK;
      if (file_adjust != 0 && last != NULL)
	{
	  bfd_vma current_file_end = phdr[i].p_offset + phdr[i].p_filesz;
	  if (current_file_end + file_adjust > last->p_offset)
	    {
	      can_round_up = false;
	      break;
	    }
	}

      unsigned int mem_adjust = -phdr[i].p_memsz & SPU_SEGMENT_ALIGNMENT_MASK;
      if (mem_adjust != 0 && last != NULL && phdr[i].p_filesz != 0)
	{
	  bfd_vma current_mem_end = phdr[i].p_vaddr + phdr[i].p_memsz;
	  if (current_mem_end <= last->p_vaddr
	      && current_mem_end + mem_adjust > last->p_vaddr)
	    {
	      can_round_up = false;
	      break;
	    }
	}

      if (phdr[i].p_filesz != 0)
	last = &phdr[i];
    }

  if (can_round_up)
    {
      for (i = 0; i < count; ++i)
	{
	  if (phdr[i].p_type == PT_LOAD)
	    {
	      phdr[i].p_filesz +=
		-phdr[i].p_filesz & SPU_SEGMENT_ALIGNMENT_MASK;
	      phdr[i].p_memsz +=
		-phdr[i].p_memsz & SPU_SEGMENT_ALIGNMENT_MASK;
	    }
	}
    }
}

static bool
spu_elf_modify_headers (bfd *abfd, struct bfd_link_info *info)
{
  if (info != NULL)
    {
      const struct elf_backend_data *bed = get_elf_backend_data (abfd);
      struct elf_obj_tdata *tdata = elf_tdata (abfd);
      Elf_Internal_Phdr *phdr = tdata->phdr;
      unsigned int count = elf_program_header_size (abfd) / bed->s->sizeof_phdr;

      spu_elf_handle_overlays (abfd, info, phdr);
      spu_elf_round_up_load_segments (phdr, count);
    }

  return _bfd_elf_modify_headers (abfd, info);
}

static int
count_fixups_in_section (bfd *ibfd, asection *isec, bool keep_memory)
{
  if (((isec->flags & SEC_ALLOC) == 0)
      || ((isec->flags & SEC_RELOC) == 0)
      || (isec->reloc_count == 0))
    return 0;

  Elf_Internal_Rela *relocs =
    _bfd_elf_link_read_relocs (ibfd, isec, NULL, NULL, keep_memory);
  if (relocs == NULL)
    return -1;

  int fixup_count = 0;
  bfd_vma base_end = 0;
  const Elf_Internal_Rela *rela_end = relocs + isec->reloc_count;

  for (Elf_Internal_Rela *rela = relocs; rela < rela_end; rela++)
    {
      if (ELF32_R_TYPE (rela->r_info) == R_SPU_ADDR32
	  && rela->r_offset >= base_end)
	{
	  base_end = (rela->r_offset & ~(bfd_vma) 15) + 16;
	  fixup_count++;
	}
    }
  return fixup_count;
}

bool
spu_elf_size_sections (bfd *obfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (!htab->params->emit_fixups)
    return true;

  int total_fixup_count = 0;
  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour)
	continue;

      for (asection *isec = ibfd->sections; isec != NULL; isec = isec->next)
	{
	  int count = count_fixups_in_section (ibfd, isec, info->keep_memory);
	  if (count < 0)
	    return false;
	  total_fixup_count += count;
	}
    }

  asection *sfixup = htab->sfixup;
  size_t size = (total_fixup_count + 1) * FIXUP_RECORD_SIZE;

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
