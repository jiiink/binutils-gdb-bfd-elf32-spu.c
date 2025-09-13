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
  switch (code)
    {
    case BFD_RELOC_NONE:
      return R_SPU_NONE;
    case BFD_RELOC_SPU_IMM10W:
      return R_SPU_ADDR10;
    case BFD_RELOC_SPU_IMM16W:
      return R_SPU_ADDR16;
    case BFD_RELOC_SPU_LO16:
      return R_SPU_ADDR16_LO;
    case BFD_RELOC_SPU_HI16:
      return R_SPU_ADDR16_HI;
    case BFD_RELOC_SPU_IMM18:
      return R_SPU_ADDR18;
    case BFD_RELOC_SPU_PCREL16:
      return R_SPU_REL16;
    case BFD_RELOC_SPU_IMM7:
      return R_SPU_ADDR7;
    case BFD_RELOC_SPU_IMM8:
      return R_SPU_NONE;
    case BFD_RELOC_SPU_PCREL9a:
      return R_SPU_REL9;
    case BFD_RELOC_SPU_PCREL9b:
      return R_SPU_REL9I;
    case BFD_RELOC_SPU_IMM10:
      return R_SPU_ADDR10I;
    case BFD_RELOC_SPU_IMM16:
      return R_SPU_ADDR16I;
    case BFD_RELOC_32:
      return R_SPU_ADDR32;
    case BFD_RELOC_32_PCREL:
      return R_SPU_REL32;
    case BFD_RELOC_SPU_PPU32:
      return R_SPU_PPU32;
    case BFD_RELOC_SPU_PPU64:
      return R_SPU_PPU64;
    case BFD_RELOC_SPU_ADD_PIC:
      return R_SPU_ADD_PIC;
    default:
      return (enum elf_spu_reloc_type) -1;
    }
}

static bool
spu_elf_info_to_howto (bfd *abfd,
		       arelent *cache_ptr,
		       Elf_Internal_Rela *dst)
{
  enum elf_spu_reloc_type r_type = (enum elf_spu_reloc_type) ELF32_R_TYPE (dst->r_info);

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
  if (r_name == NULL)
  {
    return NULL;
  }

  size_t i;

  for (i = 0; i < sizeof(elf_howto_table) / sizeof(*elf_howto_table); i++)
  {
    if (elf_howto_table[i].name != NULL
	&& strcasecmp (elf_howto_table[i].name, r_name) == 0)
    {
      return &elf_howto_table[i];
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
  bfd_size_type octets;
  bfd_vma insn_val_for_encoding; /* Value prepared for bitfield insertion */
  long long val_calc;             /* For signed intermediate arithmetic */
  long insn_word;                 /* The 32-bit instruction word */

  /* If this is a relocatable link, delegate to the generic function.
     Adjustments will be done at final link time. */
  if (output_bfd != NULL)
    return bfd_elf_generic_reloc (abfd, reloc_entry, symbol, data,
				  input_section, output_bfd, error_message);

  /* Ensure the relocation address is within the section boundaries. */
  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;

  /* Calculate the byte offset within the section data for the instruction. */
  octets = reloc_entry->address * OCTETS_PER_BYTE (abfd, input_section);

  /* Calculate the symbol's effective address.
     Initialize with 0 and then add symbol value if not a common section. */
  val_calc = 0;
  if (!bfd_is_com_section (symbol->section))
    val_calc = symbol->value;

  /* Add the output section's virtual memory address if applicable. */
  if (symbol->section->output_section)
    val_calc += symbol->section->output_section->vma;

  /* Add the relocation addend. */
  val_calc += reloc_entry->addend;

  /* Make the value PC-relative.
     Subtract the program counter, which is the start address of the current
     instruction within the output section. Explicitly cast to long long
     to ensure correct arithmetic for potentially large addresses. */
  val_calc -= ((long long) input_section->output_section->vma
               + (long long) input_section->output_offset);

  /* Apply the architecture-specific scaling (right shift by 2).
     This operation is performed on the signed value. */
  val_calc >>= 2;

  /* Check for overflow against the 9-bit signed range [-256, 255]. */
  if (val_calc > 255 || val_calc < -256)
    return bfd_reloc_overflow;

  /* Read the original 32-bit instruction word from the data buffer. */
  insn_word = bfd_get_32 (abfd, (bfd_byte *) data + octets);

  /* Convert the signed calculated value into its 9-bit unsigned
     representation (0-511) for bit field extraction and insertion. */
  insn_val_for_encoding = (bfd_vma) (val_calc & 0x1FF); /* Mask to keep only the relevant 9 bits */

  /* Prepare the bits for insertion into the instruction word.
     This involves splitting the 9-bit value and placing its parts
     at specific locations within a temporary BFD_VMA, which will
     then be filtered by dst_mask.
     Bits 0-6 remain in place.
     Bits 7 and 8 are replicated and shifted to two different higher positions. */
  insn_val_for_encoding = (insn_val_for_encoding & 0x7f)           /* Bits 0-6 */
                          | ((insn_val_for_encoding & 0x180) << 7)  /* Bits 7 and 8 shifted to positions 14 & 15 */
                          | ((insn_val_for_encoding & 0x180) << 16); /* Bits 7 and 8 shifted to positions 23 & 24 */

  /* Clear the target bit fields in the instruction word using the destination mask. */
  insn_word &= ~reloc_entry->howto->dst_mask;
  /* Set the target bit fields in the instruction word with the prepared value.
     The destination mask ensures only the relevant bits from insn_val_for_encoding are applied. */
  insn_word |= insn_val_for_encoding & reloc_entry->howto->dst_mask;

  /* Write the modified 32-bit instruction word back to the data buffer. */
  bfd_put_32 (abfd, insn_word, (bfd_byte *) data + octets);

  return bfd_reloc_ok;
}

static bool
spu_elf_new_section_hook (bfd *abfd, asection *sec)
{
  struct _spu_elf_section_data *section_data_ptr = bfd_zalloc (abfd, sizeof (*section_data_ptr));
  if (section_data_ptr == NULL)
    return false;

  sec->used_by_bfd = section_data_ptr;

  return _bfd_elf_new_section_hook (abfd, sec);
}

/* Set up overlay info for executables.  */

static bool
spu_elf_object_p (bfd *abfd)
{
  if ((abfd->flags & (EXEC_P | DYNAMIC)) != 0)
    {
      Elf_Internal_Ehdr *ehdr = elf_elfheader (abfd);
      if (ehdr == NULL || ehdr->e_phnum == 0)
        {
          return true;
        }

      Elf_Internal_Phdr *phdr_base = elf_tdata (abfd)->phdr;
      if (phdr_base == NULL)
        {
          return true;
        }

      unsigned int num_ovl = 0;
      unsigned int num_buf = 0;
      Elf_Internal_Phdr *last_phdr = NULL;

      for (unsigned int i = 0; i < ehdr->e_phnum; ++i)
	    {
	      Elf_Internal_Phdr *current_phdr = phdr_base + i;

	      if (current_phdr->p_type == PT_LOAD && (current_phdr->p_flags & PF_OVERLAY) != 0)
	        {
	          ++num_ovl;
	          if (last_phdr == NULL || ((last_phdr->p_vaddr ^ current_phdr->p_vaddr) & 0x3ffff) != 0)
	            {
	              ++num_buf;
	            }
	          last_phdr = current_phdr;

	          unsigned int num_sections = elf_numsections (abfd);
	          Elf_Internal_Shdr **sections = elf_elfsections (abfd);
              if (sections == NULL)
                  {
                      continue; 
                  }

	          for (unsigned int j = 1; j < num_sections; ++j)
	            {
	              Elf_Internal_Shdr *shdr = sections[j];

	              if (shdr != NULL && shdr->bfd_section != NULL
	                  && ELF_SECTION_SIZE (shdr, current_phdr) != 0
	                  && ELF_SECTION_IN_SEGMENT (shdr, current_phdr))
	                {
	                  asection *sec = shdr->bfd_section;
	                  spu_elf_section_data (sec)->u.o.ovl_index = num_ovl;
	                  spu_elf_section_data (sec)->u.o.ovl_buf = num_buf;
	                }
	            }
	        }
	    }
    }
  return true;
}

/* Specially mark defined symbols named _EAR_* with BSF_KEEP so that
   strip --strip-unneeded will not remove them.  */

static void
spu_elf_backend_symbol_processing (bfd *abfd ATTRIBUTE_UNUSED, asymbol *sym)
{
  if (sym == NULL)
    {
      return;
    }

  if (sym->name != NULL
      && sym->section != bfd_abs_section_ptr
      && startswith (sym->name, "_EAR_"))
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
  if (info == NULL)
    {
      bfd_set_error (bfd_error_system_call);
      return;
    }

  if (params == NULL)
    {
      bfd_set_error (bfd_error_bad_value);
      return;
    }

#define IS_POWER_OF_2(N) ((N) > 0 && (((N) & ((N) - 1)) == 0))

  if (!IS_POWER_OF_2(params->line_size))
    {
      bfd_set_error (bfd_error_bad_value);
      return;
    }
  if (!IS_POWER_OF_2(params->num_lines))
    {
      bfd_set_error (bfd_error_bad_value);
      return;
    }
  if (!IS_POWER_OF_2(params->max_branch))
    {
      bfd_set_error (bfd_error_bad_value);
      return;
    }

#undef IS_POWER_OF_2

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (htab == NULL)
    {
      bfd_set_error (bfd_error_no_memory);
      return;
    }

  htab->params = params;
  htab->line_size_log2 = bfd_log2 (params->line_size);
  htab->num_lines_log2 = bfd_log2 (params->num_lines);

  bfd_vma temp_max_branch_log2 = bfd_log2 (params->max_branch);
  htab->fromelem_size_log2 = temp_max_branch_log2 > 4 ? temp_max_branch_log2 - 4 : 0;
}

/* Find the symbol for the given R_SYMNDX in IBFD and set *HP and *SYMP
   to (hash, NULL) for global symbols, and (NULL, sym) for locals.  Set
   *SYMSECP to the symbol's section.  *LOCSYMSP caches local syms.  */

static Elf_Internal_Sym *
load_local_symbols_if_needed (bfd *ibfd,
                              Elf_Internal_Shdr *symtab_hdr,
                              Elf_Internal_Sym **locsymsp)
{
  if (*locsymsp != NULL)
    return *locsymsp;

  Elf_Internal_Sym *locsyms = (Elf_Internal_Sym *) symtab_hdr->contents;
  if (locsyms == NULL)
    {
      locsyms = bfd_elf_get_elf_syms (ibfd, symtab_hdr,
                                      symtab_hdr->sh_info,
                                      0, NULL, NULL, NULL);
      if (locsyms == NULL)
        return NULL;
    }
  *locsymsp = locsyms;
  return locsyms;
}

static bool
get_sym_h (struct elf_link_hash_entry **hp,
	   Elf_Internal_Sym **symp,
	   asection **symsecp,
	   Elf_Internal_Sym **locsymsp,
	   unsigned long r_symndx,
	   bfd *ibfd)
{
  if (hp != NULL)
    *hp = NULL;
  if (symp != NULL)
    *symp = NULL;
  if (symsecp != NULL)
    *symsecp = NULL;

  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;

  if (r_symndx < symtab_hdr->sh_info)
    {
      Elf_Internal_Sym *locsyms = load_local_symbols_if_needed(ibfd, symtab_hdr, locsymsp);
      if (locsyms == NULL)
        return false;

      Elf_Internal_Sym *sym = locsyms + r_symndx;

      if (symp != NULL)
	*symp = sym;

      if (symsecp != NULL)
	*symsecp = bfd_section_from_elf_index (ibfd, sym->st_shndx);
    }
  else
    {
      struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (ibfd);
      if (sym_hashes == NULL)
        return false;

      unsigned long hash_ndx = r_symndx - symtab_hdr->sh_info;
      struct elf_link_hash_entry *h = sym_hashes[hash_ndx];

      while (h->root.type == bfd_link_hash_indirect
	     || h->root.type == bfd_link_hash_warning)
	{
	  h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      if (hp != NULL)
	*hp = h;

      if (symsecp != NULL)
	{
	  asection *symsec = NULL;
	  if (h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	    symsec = h->root.u.def.section;
	  *symsecp = symsec;
	}
    }

  return true;
}

/* Create the note section if not already present.  This is done early so
   that the linker maps the sections to the right place in the output.  */

bool
create_spu_ptnote_spuname_section(bfd *ibfd, struct bfd_link_info *info)
{
  asection *s;
  const char *output_filename;
  size_t name_len;
  size_t size;
  bfd_byte *data;
  flagword flags;

  /* Helper macro for rounding up to the nearest multiple of 'align'. */
#define SPU_NOTE_ALIGNMENT 4
#define ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))

  output_filename = bfd_get_filename (info->output_bfd);
  if (output_filename == NULL)
    {
      /* It's an error if the output BFD has no filename, as we need it
         for the SPU_PTNOTE_SPUNAME section. */
      return false;
    }

  flags = SEC_LOAD | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
  s = bfd_make_section_anyway_with_flags (ibfd, SPU_PTNOTE_SPUNAME, flags);
  if (s == NULL)
    return false;

  if (!bfd_set_section_alignment (s, SPU_NOTE_ALIGNMENT))
    return false;

  /* Because we didn't set SEC_LINKER_CREATED we need to set the proper section type. */
  elf_section_type (s) = SHT_NOTE;

  name_len = strlen (output_filename) + 1; /* +1 for null terminator */

  /* ELF Note section structure: 3 DWords for header + name + description
     n_namesz (4 bytes), n_descsz (4 bytes), n_type (4 bytes) */
  const size_t NOTE_HEADER_SIZE = 12;

  size_t plugin_name_padded_size = ALIGN_UP(sizeof (SPU_PLUGIN_NAME), SPU_NOTE_ALIGNMENT);
  size_t filename_padded_size = ALIGN_UP(name_len, SPU_NOTE_ALIGNMENT);

  size = NOTE_HEADER_SIZE + plugin_name_padded_size + filename_padded_size;

  if (!bfd_set_section_size (s, size))
    return false;

  data = bfd_zalloc (ibfd, size);
  if (data == NULL)
    return false;

  /* Populate the note header */
  bfd_put_32 (ibfd, sizeof (SPU_PLUGIN_NAME), data + 0); /* n_namesz */
  bfd_put_32 (ibfd, name_len, data + 4);                 /* n_descsz */
  bfd_put_32 (ibfd, 1, data + 8);                        /* n_type (arbitrary, often 1 for NT_VERSION or similar) */

  /* Copy plugin name, ensuring alignment */
  memcpy (data + NOTE_HEADER_SIZE, SPU_PLUGIN_NAME, sizeof (SPU_PLUGIN_NAME));

  /* Copy filename, ensuring alignment */
  memcpy (data + NOTE_HEADER_SIZE + plugin_name_padded_size, output_filename, name_len);

  s->contents = data;
  s->alloced = 1; /* Indicate BFD owns the memory block */
  return true;
#undef ALIGN_UP
#undef SPU_NOTE_ALIGNMENT
}

bool
spu_elf_create_sections (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd = NULL;

  /* First, try to find an existing SPU_PTNOTE_SPUNAME section in any input BFD. */
  for (bfd *current_ibfd = info->input_bfds; current_ibfd != NULL; current_ibfd = current_ibfd->link.next)
    {
      if (bfd_get_section_by_name (current_ibfd, SPU_PTNOTE_SPUNAME) != NULL)
        {
          ibfd = current_ibfd;
          break;
        }
    }

  /* If the section was not found, create it. */
  if (ibfd == NULL)
    {
      /* We need an input BFD to attach the new section to. Use the first one. */
      ibfd = info->input_bfds;
      if (ibfd == NULL)
        {
          /* No input BFDs available to attach the section to. This indicates
             a malformed input `info` structure for this specific operation. */
          return false;
        }

      if (!create_spu_ptnote_spuname_section(ibfd, info))
        return false;
    }

  /* Handle the .fixup section if required. */
  if (htab->params->emit_fixups)
    {
      asection *s_fixup;
      flagword fixup_flags;
      bfd *fixup_target_bfd = ibfd; /* Default to the BFD where SPU_PTNOTE_SPUNAME was found/created */

      if (htab->elf.dynobj != NULL)
        {
          fixup_target_bfd = htab->elf.dynobj;
        }
      else
        {
          htab->elf.dynobj = fixup_target_bfd; /* Assign if not set */
        }

      fixup_flags = (SEC_LOAD | SEC_ALLOC | SEC_READONLY | SEC_HAS_CONTENTS
                     | SEC_IN_MEMORY | SEC_LINKER_CREATED);

      s_fixup = bfd_make_section_anyway_with_flags (fixup_target_bfd, ".fixup", fixup_flags);
      if (s_fixup == NULL)
        return false;

      if (!bfd_set_section_alignment (s_fixup, 2)) /* Original code used 2, maintain it. */
        return false;

      htab->sfixup = s_fixup;
    }

  return true;
}

/* qsort predicate to sort sections by vma.  */

static int
sort_sections (const void *a, const void *b)
{
  const asection *const *section1_ptr = (const asection *const *)a;
  const asection *const *section2_ptr = (const asection *const *)b;

  const asection *section1 = *section1_ptr;
  const asection *section2 = *section2_ptr;

  if (section1->vma < section2->vma)
    return -1;
  if (section1->vma > section2->vma)
    return 1;

  if (section1->index < section2->index)
    return -1;
  if (section1->index > section2->index)
    return 1;

  return 0;
}

/* Identify overlays in the output bfd, and number them.
   Returns 0 on error, 1 if no overlays, 2 if overlays.  */

int
spu_elf_find_overlays (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection **alloc_sec = NULL;
  unsigned int n = 0;
  unsigned int ovl_index = 0;
  unsigned int num_buf = 0;
  asection *s;
  bfd_vma ovl_end_tracker;
  static const char *const entry_names[2][2] = {
    { "__ovly_load", "__icache_br_handler" },
    { "__ovly_return", "__icache_call_handler" }
  };
  int ret_val = 0;

  if (info->output_bfd->section_count < 2)
    return 1;

  alloc_sec = bfd_malloc (info->output_bfd->section_count * sizeof (*alloc_sec));
  if (alloc_sec == NULL)
    return 0;

  for (s = info->output_bfd->sections; s != NULL; s = s->next)
    if ((s->flags & SEC_ALLOC) && s->size != 0
	&& !((s->flags & SEC_THREAD_LOCAL) && !(s->flags & SEC_LOAD)))
      alloc_sec[n++] = s;

  if (n == 0)
    {
      ret_val = 1;
      goto cleanup_alloc_sec;
    }

  qsort (alloc_sec, n, sizeof (*alloc_sec), sort_sections);

  ovl_end_tracker = alloc_sec[0]->vma + alloc_sec[0]->size;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      unsigned int first_ovl_sec_idx = n;
      bfd_vma cache_base_vma = 0;
      bfd_vma global_cache_end_vma = 0;

      for (unsigned int k = 1; k < n; k++)
        {
          s = alloc_sec[k];
          if (s->vma < ovl_end_tracker)
            {
              first_ovl_sec_idx = k - 1;
              cache_base_vma = alloc_sec[first_ovl_sec_idx]->vma;
              global_cache_end_vma = cache_base_vma
                                     + ((bfd_vma) 1 << (htab->num_lines_log2 + htab->line_size_log2));
              break;
            }
          else
            {
              ovl_end_tracker = s->vma + s->size;
            }
        }

      if (first_ovl_sec_idx == n)
        {
          ret_val = 1;
          goto cleanup_alloc_sec;
        }

      unsigned int current_sec_idx = first_ovl_sec_idx;
      unsigned int prev_buf = 0;
      unsigned int set_id = 0;

      for (; current_sec_idx < n; current_sec_idx++)
        {
          s = alloc_sec[current_sec_idx];
          if (s->vma >= global_cache_end_vma)
            break;

          if (!startswith(s->name, ".ovl.init"))
            {
              if ((s->vma - cache_base_vma) & (htab->params->line_size - 1))
                {
                  info->callbacks->einfo (_("%X%P: overlay section %pA "
                                            "does not start on a cache line\n"),
                                          s);
                  bfd_set_error (bfd_error_bad_value);
                  goto cleanup_alloc_sec;
                }
              else if (s->size > htab->params->line_size)
                {
                  info->callbacks->einfo (_("%X%P: overlay section %pA "
                                            "is larger than a cache line\n"),
                                          s);
                  bfd_set_error (bfd_error_bad_value);
                  goto cleanup_alloc_sec;
                }

              num_buf = ((s->vma - cache_base_vma) >> htab->line_size_log2) + 1;
              set_id = (num_buf == prev_buf) ? set_id + 1 : 0;
              prev_buf = num_buf;

              alloc_sec[ovl_index++] = s;
              spu_elf_section_data(s)->u.o.ovl_index = (set_id << htab->num_lines_log2) + num_buf;
              spu_elf_section_data(s)->u.o.ovl_buf = num_buf;
            }
        }

      for ( ; current_sec_idx < n; current_sec_idx++)
        {
          s = alloc_sec[current_sec_idx];
          if (s->vma < global_cache_end_vma)
            {
              info->callbacks->einfo (_("%X%P: overlay section %pA "
                                        "is not in cache area\n"),
                                      alloc_sec[current_sec_idx-1]);
              bfd_set_error (bfd_error_bad_value);
              goto cleanup_alloc_sec;
            }
        }
    }
  else
    {
      for (unsigned int k = 1; k < n; k++)
	{
	  s = alloc_sec[k];
	  if (s->vma < ovl_end_tracker)
	    {
	      asection *s0 = alloc_sec[k - 1];

	      if (spu_elf_section_data (s0)->u.o.ovl_index == 0)
		{
		  ++num_buf;
		  if (!startswith (s0->name, ".ovl.init"))
		    {
		      alloc_sec[ovl_index] = s0;
		      spu_elf_section_data (s0)->u.o.ovl_index = ++ovl_index;
		    }
		  spu_elf_section_data (s0)->u.o.ovl_buf = num_buf;
		}

	      if (!startswith (s->name, ".ovl.init"))
		{
		  alloc_sec[ovl_index] = s;
		  spu_elf_section_data (s)->u.o.ovl_index = ++ovl_index;
		  spu_elf_section_data (s)->u.o.ovl_buf = num_buf;
		  if (s0->vma != s->vma)
		    {
		      info->callbacks->einfo (_("%X%P: overlay sections %pA "
						"and %pA do not start at the "
						"same address\n"),
					      s0, s);
		      bfd_set_error (bfd_error_bad_value);
		      goto cleanup_alloc_sec;
		    }
		}
	      if (ovl_end_tracker < s->vma + s->size)
		ovl_end_tracker = s->vma + s->size;
	      if (ovl_end_tracker < s0->vma + s0->size)
		ovl_end_tracker = s0->vma + s0->size;
	    }
	  else
	    {
	      ovl_end_tracker = s->vma + s->size;
	    }
	}
    }

  htab->num_overlays = ovl_index;
  htab->num_buf = num_buf;

  if (ovl_index == 0)
    {
      ret_val = 1;
      goto cleanup_alloc_sec;
    }

  for (unsigned int k = 0; k < 2; k++)
    {
      const char *name = entry_names[k][htab->params->ovly_flavour];
      struct elf_link_hash_entry *h = elf_link_hash_lookup (&htab->elf, name, true, false, false);
      if (h == NULL)
	{
	  bfd_set_error (bfd_error_no_memory);
	  goto cleanup_alloc_sec;
	}

      if (h->root.type == bfd_link_hash_new)
	{
	  h->root.type = bfd_link_hash_undefined;
	  h->ref_regular = 1;
	  h->ref_regular_nonweak = 1;
	  h->non_elf = 0;
	}
      htab->ovly_entry[k] = h;
    }

  htab->ovl_sec = alloc_sec;
  return 2;

cleanup_alloc_sec:
  if (alloc_sec != NULL)
    free (alloc_sec);
  return ret_val;
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

#define BRANCH_BYTE0_MASK 0xec
#define BRANCH_BYTE0_VALUE 0x20
#define BRANCH_BYTE1_MASK 0x80
#define BRANCH_BYTE1_VALUE 0x00

static bool
is_branch (const unsigned char *insn)
{
  if (insn == NULL)
  {
    return false;
  }

  return ((insn[0] & BRANCH_BYTE0_MASK) == BRANCH_BYTE0_VALUE &&
          (insn[1] & BRANCH_BYTE1_MASK) == BRANCH_BYTE1_VALUE);
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

static const unsigned char INDIRECT_BRANCH_OPCODE_MASK = 0xef;
static const unsigned char INDIRECT_BRANCH_OPCODE_VALUE = 0x25;
static const unsigned char MOD_RM_BYTE_CONTROL_MASK = 0x80;
static const unsigned char MOD_RM_BYTE_EXPECTED_VALUE = 0x00;

static bool
is_indirect_branch (const unsigned char *insn)
{
  if (insn == NULL) {
    return false;
  }

  const unsigned char first_byte = insn[0];
  const unsigned char second_byte = insn[1];

  bool first_byte_condition = (first_byte & INDIRECT_BRANCH_OPCODE_MASK) == INDIRECT_BRANCH_OPCODE_VALUE;
  bool second_byte_condition = (second_byte & MOD_RM_BYTE_CONTROL_MASK) == MOD_RM_BYTE_EXPECTED_VALUE;

  return first_byte_condition && second_byte_condition;
}

/* Return true for branch hint instructions.
   hbra  0001000..
   hbrr  0001001..  */

static bool
is_hint (const unsigned char *insn)
{
  if (insn == NULL) {
    return false;
  }

  static const unsigned char HINT_OPCODE_MASK = 0xfc;
  static const unsigned char HINT_OPCODE_VALUE = 0x10;

  return (insn[0] & HINT_OPCODE_MASK) == HINT_OPCODE_VALUE;
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

  if (input_section->name != NULL && strcmp (input_section->name, ".eh_frame") == 0)
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
  enum elf_spu_reloc_type r_type;
  unsigned int sym_type;
  enum _stub_type ret = no_stub;

  if (sym_sec == NULL
      || sym_sec->output_section == bfd_abs_section_ptr
      || spu_elf_section_data (sym_sec->output_section) == NULL)
    return ret;

  if (h != NULL)
    {
      if (h == htab->ovly_entry[0] || h == htab->ovly_entry[1])
	return ret;

      if (startswith (h->root.root.string, "setjmp")
	  && (h->root.root.string[6] == '\0' || h->root.root.string[6] == '@'))
	ret = call_ovl_stub;
    }

  if (h != NULL)
    sym_type = h->type;
  else
    sym_type = ELF_ST_TYPE (sym->st_info);

  r_type = ELF32_R_TYPE (irela->r_info);

  bool branch = false;
  bool hint = false;
  bool call = false;
  bfd_byte instruction_bytes_local[4];
  bfd_byte *current_instruction_ptr = contents;
  bool contents_was_null = (contents == NULL);

  if (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16)
    {
      if (current_instruction_ptr == NULL)
	{
	  if (!bfd_get_section_contents (input_section->owner,
					 input_section,
					 instruction_bytes_local,
					 irela->r_offset, 4))
	    return stub_error;
	  current_instruction_ptr = instruction_bytes_local;
	}
      else
	{
	  current_instruction_ptr += irela->r_offset;
	}

      branch = is_branch (current_instruction_ptr);
      hint = is_hint (current_instruction_ptr);

      if (branch || hint)
	{
	  call = (current_instruction_ptr[0] & 0xfd) == 0x31;

	  if (call && sym_type != STT_FUNC && !contents_was_null)
	    {
	      const char *sym_name;
	      if (h != NULL)
		sym_name = h->root.root.string;
	      else
		{
		  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_section->owner)->symtab_hdr;
		  sym_name = bfd_elf_sym_name (input_section->owner, symtab_hdr, sym, sym_sec);
		}
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("warning: call to non-function symbol %s defined in %pB"),
		 sym_name, sym_sec->owner);
	    }
	}
    }

  bool is_code_section = (sym_sec->flags & SEC_CODE) != 0;
  if ((!branch && htab->params->ovly_flavour == ovly_soft_icache)
      || (sym_type != STT_FUNC && !(branch || hint) && !is_code_section))
    return no_stub;

  struct spu_elf_section_data_struct *sym_sec_data = spu_elf_section_data (sym_sec->output_section);
  struct spu_elf_section_data_struct *input_sec_data = spu_elf_section_data (input_section->output_section);

  if (sym_sec_data->u.o.ovl_index == 0 && !htab->params->non_overlay_stubs)
    return ret;

  if (sym_sec_data->u.o.ovl_index != input_sec_data->u.o.ovl_index)
    {
      unsigned int lrlive = 0;
      if (branch)
	lrlive = (current_instruction_ptr[1] & 0x70) >> 4;

      if (!lrlive && (call || sym_type == STT_FUNC))
	ret = call_ovl_stub;
      else
	ret = br000_ovl_stub + lrlive;
    }

  if (!(branch || hint)
      && sym_type == STT_FUNC
      && htab->params->ovly_flavour != ovly_soft_icache)
    ret = nonovl_stub;

  return ret;
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
  struct got_entry *g = NULL;
  struct got_entry **head;
  bfd_vma addend = 0;

  if (stub_type != nonovl_stub)
    ovl = spu_elf_section_data (isec->output_section)->u.o.ovl_index;

  if (h != NULL)
    {
      head = &h->got.glist;
    }
  else
    {
      if (irela == NULL)
        return false;

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

  if (irela != NULL)
    addend = irela->r_addend;

  if (ovl == 0)
    {
      for (g = *head; g != NULL; g = g->next)
        if (g->addend == addend && g->ovl == 0)
          break;

      if (g == NULL)
        {
          struct got_entry **current_node_ptr = head;
          while (*current_node_ptr != NULL)
            {
              struct got_entry *entry_to_check = *current_node_ptr;
              if (entry_to_check->addend == addend)
                {
                  *current_node_ptr = entry_to_check->next;
                  htab->stub_count[entry_to_check->ovl] -= 1;
                  free(entry_to_check);
                }
              else
                {
                  current_node_ptr = &entry_to_check->next;
                }
            }
        }
    }
  else
    {
      for (g = *head; g != NULL; g = g->next)
        if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
          break;
    }

  if (g == NULL)
    {
      g = bfd_malloc (sizeof (*g));
      if (g == NULL)
        return false;

      g->ovl = ovl;
      g->addend = addend;
      g->stub_addr = (bfd_vma) -1;
      g->next = *head;
      *head = g;

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
  if (params == (void *)0) {
    return 0;
  }

  const unsigned int BASE_SIZE = 16U;
  const unsigned int BITS_IN_UINT = sizeof(unsigned int) * 8; 

  unsigned int ovly_flavour = params->ovly_flavour;
  unsigned int compact_stub = params->compact_stub;

  if (ovly_flavour >= BITS_IN_UINT - 4) {
    return 0;
  }

  unsigned int intermediate_value = BASE_SIZE << ovly_flavour;

  if (compact_stub >= BITS_IN_UINT) {
    return 0;
  }

  return intermediate_value >> compact_stub;
}

static unsigned int
ovl_stub_size_log2 (struct spu_elf_params *params)
{
  if (params == NULL)
    {
      return 4;
    }

  int calculated_log2_size = 4 + (int)params->ovly_flavour - (int)params->compact_stub;

  if (calculated_log2_size < 0)
    {
      return 0;
    }

  return (unsigned int)calculated_log2_size;
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
get_section_address_internal(asection *sec, bfd_vma *address)
{
  if (!sec || !sec->output_section)
    return false;
  *address = sec->output_section->vma + sec->output_offset;
  return true;
}

struct got_entry_result
{
  struct got_entry *g;
  bool stub_already_done;
  bool error;
};

static struct got_entry_result
get_or_create_got_entry_logic (struct bfd_link_info *info,
                               bfd *ibfd,
                               asection *isec,
                               struct elf_link_hash_entry *h,
                               const Elf_Internal_Rela *irela,
                               unsigned int ovl,
                               bfd_vma addend)
{
  struct got_entry_result result = { .g = NULL, .stub_already_done = false, .error = false };
  struct spu_link_hash_table *htab = spu_hash_table (info);
  struct got_entry **head;

  if (h != NULL)
    {
      head = &h->got.glist;
    }
  else
    {
      if (irela == NULL)
        {
          info->callbacks->einfo (_("linker internal error: irela is NULL when using local GOT entries.\n"));
          result.error = true;
          return result;
        }
      struct got_entry **local_got_ents_ptr = elf_local_got_ents (ibfd);
      if (local_got_ents_ptr == NULL)
        {
          info->callbacks->einfo (_("linker internal error: elf_local_got_ents returned NULL.\n"));
          result.error = true;
          return result;
        }
      head = local_got_ents_ptr + ELF32_R_SYM (irela->r_info);
    }

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      result.g = bfd_malloc (sizeof (*(result.g)));
      if (result.g == NULL)
        {
          info->callbacks->einfo (_("memory allocation failed for got_entry.\n"));
          result.error = true;
          return result;
        }
      result.g->ovl = ovl;
      result.g->br_addr = 0;
      if (irela != NULL)
        {
          bfd_vma isec_addr;
          if (!get_section_address_internal(isec, &isec_addr))
            {
              info->callbacks->einfo (_("linker internal error: invalid section address for isec.\n"));
              bfd_free(result.g);
              result.error = true;
              return result;
            }
          result.g->br_addr = irela->r_offset + isec_addr;
        }
      result.g->next = *head;
      *head = result.g;
    }
  else
    {
      for (result.g = *head; result.g != NULL; result.g = result.g->next)
        if (result.g->addend == addend && (result.g->ovl == ovl || result.g->ovl == 0))
          break;

      if (result.g == NULL)
        {
          info->callbacks->einfo (_("linker internal error: required GOT entry not found for non-soft_icache flavour (addend 0x%v, ovl %u).\n"), addend, ovl);
          result.error = true;
          return result;
        }

      if (result.g->ovl == 0 && ovl != 0)
        {
          result.stub_already_done = true;
          return result;
        }

      if (result.g->stub_addr != (bfd_vma) -1)
        {
          result.stub_already_done = true;
          return result;
        }
    }
  return result;
}

static unsigned int
calculate_lrlive (struct bfd_link_info *info,
                  struct spu_link_hash_table *htab,
                  asection *isec,
                  const Elf_Internal_Rela *irela,
                  enum _stub_type stub_type)
{
  unsigned int lrlive = 0;

  if (stub_type == nonovl_stub)
    return lrlive;

  if (stub_type == call_ovl_stub)
    {
      lrlive = 5;
    }
  else if (!htab->params->lrlive_analysis)
    {
      lrlive = 1;
    }
  else if (irela != NULL)
    {
      struct function_info *caller;
      bfd_vma off_in_func;

      caller = find_function (isec, irela->r_offset, info);
      if (caller == NULL)
        {
          info->callbacks->einfo (_("linker internal error: find_function failed for lrlive analysis at %pA:0x%v. Using default lrlive.\n"),
                                  isec, irela->r_offset);
          return 0;
        }

      if (caller->start == NULL)
        {
          off_in_func = irela->r_offset;
        }
      else
        {
          struct function_info *found_caller_with_frame_info = NULL;
          struct function_info *current_caller = caller;

          while (current_caller != NULL)
            {
              if (current_caller->lr_store != (bfd_vma) -1 || current_caller->sp_adjust != (bfd_vma) -1)
                found_caller_with_frame_info = current_caller;
              current_caller = current_caller->start;
            }
          if (found_caller_with_frame_info != NULL)
            caller = found_caller_with_frame_info;
          off_in_func = (bfd_vma) -1;
        }

      bfd_vma effective_offset_for_lrlive = (off_in_func == (bfd_vma) -1) ? irela->r_offset : off_in_func;

      if (effective_offset_for_lrlive > caller->sp_adjust)
        {
          if (effective_offset_for_lrlive > caller->lr_store)
            {
              lrlive = 1;
            }
          else
            {
              lrlive = 4;
            }
        }
      else if (effective_offset_for_lrlive > caller->lr_store)
        {
          lrlive = 3;
          info->callbacks->einfo (_("%pA:0x%v linker internal error: lrlive analysis detected prologue split. Assuming lrlive=0.\n"),
                                  isec, irela->r_offset);
          lrlive = 0;
        }
      else
        {
          lrlive = 5;
        }

      if (stub_type > br000_ovl_stub && (unsigned int)(stub_type - br000_ovl_stub) != lrlive)
        {
          info->callbacks->einfo (_("%pA:0x%v lrlive .brinfo (%u) differs from analysis (%u)\n"),
                                  isec, irela->r_offset, (unsigned int)(stub_type - br000_ovl_stub), lrlive);
        }
    }

  if (stub_type > br000_ovl_stub)
    lrlive = stub_type - br000_ovl_stub;

  return lrlive;
}

static bool
generate_normal_stub_instructions (struct bfd_link_info *info,
                                   struct spu_link_hash_table *htab,
                                   asection *sec,
                                   bfd_vma dest_vma_full,
                                   bfd_vma to,
                                   bfd_vma from,
                                   unsigned int dest_ovl)
{
  if (htab->params->compact_stub)
    {
      if (!BRA_STUBS)
        bfd_put_32 (sec->owner, BRSL + (((to - from) << 5) & 0x007fff80) + 75,
                    sec->contents + sec->size);
      else
        bfd_put_32 (sec->owner, BRASL + ((to << 5) & 0x007fff80) + 75,
                    sec->contents + sec->size);
      bfd_put_32 (sec->owner, (dest_vma_full & 0x3ffff) | (dest_ovl << 18),
                  sec->contents + sec->size + 4);
    }
  else
    {
      bfd_put_32 (sec->owner, ILA + ((dest_ovl << 7) & 0x01ffff80) + 78,
                  sec->contents + sec->size);
      bfd_put_32 (sec->owner, LNOP,
                  sec->contents + sec->size + 4);
      bfd_put_32 (sec->owner, ILA + ((dest_vma_full << 7) & 0x01ffff80) + 79,
                  sec->contents + sec->size + 8);
      if (!BRA_STUBS)
        bfd_put_32 (sec->owner, BR + (((to - (from + 12)) << 5) & 0x007fff80),
                    sec->contents + sec->size + 12);
      else
        bfd_put_32 (sec->owner, BRA + ((to << 5) & 0x007fff80),
                    sec->contents + sec->size + 12);
    }
  return true;
}

static bool
generate_soft_icache_stub_instructions (struct bfd_link_info *info,
                                        struct spu_link_hash_table *htab,
                                        bfd *ibfd,
                                        asection *isec,
                                        enum _stub_type stub_type,
                                        struct got_entry *g,
                                        asection *sec,
                                        bfd_vma dest,
                                        bfd_vma *to_ptr,
                                        const Elf_Internal_Rela *irela,
                                        unsigned int ovl,
                                        unsigned int dest_ovl)
{
  unsigned int lrlive = calculate_lrlive (info, htab, isec, irela, stub_type);

  if (ovl == 0)
    {
      if (htab->ovly_entry == NULL || htab->ovly_entry[1] == NULL || htab->ovly_entry[1]->root.u.def.section == NULL)
        {
          info->callbacks->einfo (_("linker internal error: overlay entry 1 or its section is NULL for soft_icache non-overlay stub.\n"));
          return false;
        }
      if (!get_section_address_internal(htab->ovly_entry[1]->root.u.def.section, to_ptr))
        {
          info->callbacks->einfo (_("linker internal error: invalid section address for overlay entry 1's section.\n"));
          return false;
        }
      *to_ptr += htab->ovly_entry[1]->root.u.def.value;
    }

  g->stub_addr += 4;
  bfd_vma br_dest = g->stub_addr;
  if (irela == NULL)
    {
      if (stub_type != nonovl_stub)
        {
          info->callbacks->einfo (_("linker internal error: unexpected stub_type (%d) for irela == NULL. Expected nonovl_stub.\n"), stub_type);
          return false;
        }
      g->br_addr = g->stub_addr;
      br_dest = *to_ptr;
    }

  unsigned int set_id = ((dest_ovl - 1) >> htab->num_lines_log2) + 1;
  bfd_put_32 (sec->owner, (set_id << 18) | (dest & 0x3ffff),
              sec->contents + sec->size);
  bfd_put_32 (sec->owner, BRASL + ((*to_ptr << 5) & 0x007fff80) + 75,
              sec->contents + sec->size + 4);
  bfd_put_32 (sec->owner, (lrlive << 29) | (g->br_addr & 0x3ffff),
              sec->contents + sec->size + 8);
  bfd_vma patt = dest ^ br_dest;
  if (irela != NULL && ELF32_R_TYPE (irela->r_info) == R_SPU_REL16)
    patt = (dest - g->br_addr) ^ (br_dest - g->br_addr);
  bfd_put_32 (sec->owner, (patt << 5) & 0x007fff80,
              sec->contents + sec->size + 12);

  if (ovl == 0)
    sec->size += 16;
  return true;
}

static bool
create_stub_symbol (struct bfd_link_info *info,
                    struct spu_link_hash_table *htab,
                    struct got_entry *g,
                    struct elf_link_hash_entry *h,
                    const Elf_Internal_Rela *irela,
                    asection *sec,
                    asection *dest_sec)
{
  if (!htab->params->emit_stub_syms)
    return true;

  size_t required_len;
  char *name;
  int add_val = 0;

  required_len = 8 + sizeof (".ovl_call.") - 1;
  if (h != NULL)
    required_len += strlen (h->root.root.string);
  else
    required_len += 8 + 1 + 8;

  if (irela != NULL)
    add_val = (int) irela->r_addend;
  if (add_val != 0)
    required_len += 1 + 8;
  required_len += 1;

  name = bfd_malloc (required_len);
  if (name == NULL)
    {
      info->callbacks->einfo (_("memory allocation failed for stub symbol name.\n"));
      return false;
    }

  int current_len = 0;
  int written_len;

  written_len = snprintf (name + current_len, required_len - current_len, "%08x.ovl_call.", g->ovl);
  if (written_len < 0 || (size_t)written_len >= required_len - current_len)
    {
      info->callbacks->einfo (_("linker internal error: snprintf failed for stub symbol name prefix.\n"));
      bfd_free (name);
      return false;
    }
  current_len += written_len;

  if (h != NULL)
    {
      written_len = snprintf (name + current_len, required_len - current_len, "%s", h->root.root.string);
    }
  else
    {
      if (irela == NULL)
        {
          info->callbacks->einfo (_("linker internal error: irela is NULL when constructing symbol name without hash entry.\n"));
          bfd_free (name);
          return false;
        }
      written_len = snprintf (name + current_len, required_len - current_len, "%x:%x",
                              (unsigned int) (dest_sec->id & 0xffffffff),
                              (unsigned int) (ELF32_R_SYM (irela->r_info) & 0xffffffff));
    }
  if (written_len < 0 || (size_t)written_len >= required_len - current_len)
    {
      info->callbacks->einfo (_("linker internal error: snprintf failed for stub symbol name base.\n"));
      bfd_free (name);
      return false;
    }
  current_len += written_len;

  if (add_val != 0)
    {
      written_len = snprintf (name + current_len, required_len - current_len, "+%x", add_val);
      if (written_len < 0 || (size_t)written_len >= required_len - current_len)
        {
          info->callbacks->einfo (_("linker internal error: snprintf failed for stub symbol name addend.\n"));
          bfd_free (name);
          return false;
        }
    }

  struct elf_link_hash_entry *new_h = elf_link_hash_lookup (&htab->elf, name, true, true, false);
  bfd_free (name);
  if (new_h == NULL)
    {
      info->callbacks->einfo (_("linker internal error: elf_link_hash_lookup failed for stub symbol.\n"));
      return false;
    }

  if (new_h->root.type == bfd_link_hash_new)
    {
      new_h->root.type = bfd_link_hash_defined;
      new_h->root.u.def.section = sec;
      new_h->size = ovl_stub_size (htab->params);
      new_h->root.u.def.value = sec->size - new_h->size;
      new_h->type = STT_FUNC;
      new_h->ref_regular = 1;
      new_h->def_regular = 1;
      new_h->ref_regular_nonweak = 1;
      new_h->forced_local = 1;
      new_h->non_elf = 0;
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
  unsigned int ovl;
  struct got_entry *g;
  asection *sec;
  bfd_vma addend, from_addr, to_addr, dest_vma_full;
  unsigned int dest_ovl;
  struct spu_elf_section_data *isec_output_data;

  if (!info || !htab || !htab->params || !ibfd || !isec || !dest_sec)
    {
      if (info && info->callbacks->einfo)
        info->callbacks->einfo (_("linker internal error: build_stub received NULL input parameters.\n"));
      return false;
    }

  if (irela == NULL && h == NULL)
    {
      info->callbacks->einfo (_("linker internal error: build_stub received NULL irela and NULL hash entry. Cannot determine GOT entry.\n"));
      return false;
    }

  if (isec->output_section == NULL)
    {
      info->callbacks->einfo (_("linker internal error: input section '%s' has no output section.\n"), isec->name);
      return false;
    }
  isec_output_data = spu_elf_section_data (isec->output_section);
  if (!isec_output_data)
    {
      info->callbacks->einfo (_("linker internal error: failed to get SPU section data for input section's output section '%s'.\n"), isec->output_section->name);
      return false;
    }

  ovl = 0;
  if (stub_type != nonovl_stub)
    ovl = isec_output_data->u.o.ovl_index;

  addend = 0;
  if (irela != NULL)
    addend = irela->r_addend;

  struct got_entry_result got_res = get_or_create_got_entry_logic (info, ibfd, isec, h, irela, ovl, addend);
  if (got_res.error)
    return false;
  if (got_res.stub_already_done)
    return true;
  g = got_res.g;

  if (g == NULL)
    {
      info->callbacks->einfo (_("linker internal error: get_or_create_got_entry_logic returned NULL got_entry without error flag.\n"));
      return false;
    }

  sec = htab->stub_sec[ovl];
  if (!sec)
    {
      info->callbacks->einfo (_("linker internal error: stub_sec[%u] is NULL.\n"), ovl);
      return false;
    }
  if (!sec->contents)
    {
      info->callbacks->einfo (_("linker internal error: stub section '%s' has no contents.\n"), sec->name);
      return false;
    }

  bfd_vma dest_sec_addr;
  if (!get_section_address_internal(dest_sec, &dest_sec_addr)) {
    info->callbacks->einfo (_("linker internal error: invalid section address for destination section '%s'.\n"), dest_sec->name);
    return false;
  }
  dest_vma_full = dest + dest_sec_addr;

  bfd_vma sec_addr;
  if (!get_section_address_internal(sec, &sec_addr)) {
    info->callbacks->einfo (_("linker internal error: invalid section address for stub section '%s'.\n"), sec->name);
    return false;
  }
  from_addr = sec->size + sec_addr;
  g->stub_addr = from_addr;

  if (htab->ovly_entry == NULL || htab->ovly_entry[0] == NULL || htab->ovly_entry[0]->root.u.def.section == NULL)
    {
      info->callbacks->einfo (_("linker internal error: overlay entry 0 or its section is NULL.\n"));
      return false;
    }
  bfd_vma ovly0_sec_addr;
  if (!get_section_address_internal(htab->ovly_entry[0]->root.u.def.section, &ovly0_sec_addr))
    {
      info->callbacks->einfo (_("linker internal error: invalid section address for overlay entry 0's section '%s'.\n"), htab->ovly_entry[0]->root.u.def.section->name);
      return false;
    }
  to_addr = htab->ovly_entry[0]->root.u.def.value + ovly0_sec_addr;

  if (((dest_vma_full | to_addr | from_addr) & 3) != 0)
    {
      htab->stub_err = 1;
      info->callbacks->einfo (_("linker error: unaligned stub address or destination (dest: 0x%v, to: 0x%v, from: 0x%v).\n"),
                              dest_vma_full, to_addr, from_addr);
      return false;
    }

  if (dest_sec->output_section == NULL)
    {
      info->callbacks->einfo (_("linker internal error: destination section '%s' has no output section.\n"), dest_sec->name);
      return false;
    }
  struct spu_elf_section_data *dest_sec_output_data = spu_elf_section_data (dest_sec->output_section);
  if (!dest_sec_output_data)
    {
      info->callbacks->einfo (_("linker internal error: failed to get SPU section data for destination section's output section '%s'.\n"), dest_sec->output_section->name);
      return false;
    }
  dest_ovl = dest_sec_output_data->u.o.ovl_index;

  if (htab->params->ovly_flavour == ovly_normal)
    {
      if (!generate_normal_stub_instructions (info, htab, sec, dest_vma_full, to_addr, from_addr, dest_ovl))
        return false;
    }
  else if (htab->params->ovly_flavour == ovly_soft_icache
           && htab->params->compact_stub)
    {
      if (!generate_soft_icache_stub_instructions (info, htab, ibfd, isec, stub_type, g, sec,
                                                   dest, &to_addr, irela, ovl, dest_ovl))
        return false;
    }
  else
    {
      info->callbacks->einfo (_("linker internal error: unsupported overlay flavour (%d) or stub combination (compact_stub: %d).\n"),
                              htab->params->ovly_flavour, htab->params->compact_stub);
      return false;
    }

  sec->size += ovl_stub_size (htab->params);

  if (!create_stub_symbol (info, htab, g, h, irela, sec, dest_sec))
    return false;

  return true;
}

/* Called via elf_link_hash_traverse to allocate stubs for any _SPUEAR_
   symbols.  */

static bool
allocate_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info = (struct bfd_link_info *)inf;
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (!htab)
    {
      return true;
    }

  if (!(h->root.type == bfd_link_hash_defined
        || h->root.type == bfd_link_hash_defweak))
    {
      return true;
    }

  if (!h->def_regular)
    {
      return true;
    }

  if (!startswith (h->root.root.string, "_SPUEAR_"))
    {
      return true;
    }

  asection *sym_sec = h->root.u.def.section;
  if (!sym_sec)
    {
      return true;
    }

  if (sym_sec->output_section == bfd_abs_section_ptr)
    {
      return true;
    }

  struct spu_elf_section_data *sec_data = spu_elf_section_data (sym_sec->output_section);
  if (!sec_data)
    {
      return true;
    }

  bool needs_stub_for_overlay = (sec_data->u.o.ovl_index != 0);

  bool non_overlay_stubs_enabled = false;
  if (htab->params)
    {
      non_overlay_stubs_enabled = htab->params->non_overlay_stubs;
    }

  if (!needs_stub_for_overlay && !non_overlay_stubs_enabled)
    {
      return true;
    }

  return count_stub (htab, NULL, NULL, nonovl_stub, h, NULL);
}

static bool
build_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info = inf;
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection *sym_sec;

  if (htab == NULL || htab->params == NULL)
    return true;

  if (!(h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak))
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

  struct spu_elf_section_data *sec_data = spu_elf_section_data (sym_sec->output_section);
  if (sec_data == NULL)
    return true;

  bool is_overlay_stub = (sec_data->u.o.ovl_index != 0);
  bool non_overlay_stubs_enabled = htab->params->non_overlay_stubs;

  if (!is_overlay_stub && !non_overlay_stubs_enabled)
    return true;

  return build_stub (info, NULL, NULL, nonovl_stub, h, NULL,
                     h->root.u.def.value, sym_sec);
}

/* Size or build stubs.  */

extern const bfd_target spu_elf32_vec;

static bool
process_single_relocation_in_section(
    struct spu_link_hash_table *htab,
    bfd *ibfd,
    asection *isec,
    Elf_Internal_Shdr *symtab_hdr,
    Elf_Internal_Sym **local_syms_ptr,
    Elf_Internal_Rela *irela,
    bool build,
    struct bfd_link_info *info)
{
    enum elf_spu_reloc_type r_type;
    unsigned int r_indx;
    asection *sym_sec;
    Elf_Internal_Sym *sym;
    struct elf_link_hash_entry *h;
    enum _stub_type stub_type;

    r_type = ELF32_R_TYPE (irela->r_info);
    r_indx = ELF32_R_SYM (irela->r_info);

    if (r_type >= R_SPU_max)
    {
        bfd_set_error (bfd_error_bad_value);
        return false;
    }

    if (!get_sym_h (&h, &sym, &sym_sec, local_syms_ptr, r_indx, ibfd))
    {
        return false;
    }

    stub_type = needs_ovl_stub (h, sym, sym_sec, isec, irela, NULL, info);
    if (stub_type == no_stub)
    {
        return true;
    }
    else if (stub_type == stub_error)
    {
        return false;
    }

    if (htab->stub_count == NULL)
    {
        bfd_size_type amt = (htab->num_overlays + 1) * sizeof (*htab->stub_count);
        htab->stub_count = bfd_zmalloc (amt);
        if (htab->stub_count == NULL)
        {
            return false;
        }
    }

    if (!build)
    {
        if (!count_stub (htab, ibfd, isec, stub_type, h, irela))
        {
            return false;
        }
    }
    else
    {
        bfd_vma dest;
        if (h != NULL)
            dest = h->root.u.def.value;
        else
            dest = sym->st_value;
        dest += irela->r_addend;
        if (!build_stub (info, ibfd, isec, stub_type, h, irela, dest, sym_sec))
        {
            return false;
        }
    }
    return true;
}

static bool
process_stubs (struct bfd_link_info *info, bool build)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd;
  bool overall_success = true;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      Elf_Internal_Shdr *symtab_hdr = NULL;
      asection *isec;
      Elf_Internal_Sym *local_syms = NULL;
      bool bfd_iteration_success = true;

      if (ibfd->xvec != &spu_elf32_vec)
	continue;

      symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
      if (symtab_hdr->sh_info == 0)
	continue;

      for (isec = ibfd->sections; isec != NULL; isec = isec->next)
	{
	  Elf_Internal_Rela *internal_relocs = NULL;
	  bool section_iteration_success = true;

	  if ((isec->flags & SEC_RELOC) == 0 || isec->reloc_count == 0)
	    continue;

	  if (!maybe_needs_stubs (isec))
	    continue;

	  internal_relocs = _bfd_elf_link_read_relocs (ibfd, isec, NULL, NULL,
						       info->keep_memory);
	  if (internal_relocs == NULL)
	    {
	      bfd_iteration_success = false;
	      overall_success = false;
	      break; /* Break from section loop due to error */
	    }

	  Elf_Internal_Rela *irela_end = internal_relocs + isec->reloc_count;
	  for (Elf_Internal_Rela *irela = internal_relocs; irela < irela_end; irela++)
	    {
	      if (!process_single_relocation_in_section(htab, ibfd, isec, symtab_hdr, &local_syms, irela, build, info))
		{
		  section_iteration_success = false;
		  bfd_iteration_success = false;
		  overall_success = false;
		  break; /* Break from relocation loop due to error */
		}
	    }

	  /* Section cleanup for internal_relocs */
	  if (internal_relocs != NULL && elf_section_data (isec)->relocs != internal_relocs)
	    free (internal_relocs);

	  if (!section_iteration_success)
	    break; /* Propagate error, break from current section loop */
	}

      /* BFD cleanup for local_syms */
      if (local_syms != NULL && symtab_hdr->contents != (unsigned char *) local_syms)
	{
	  if (!info->keep_memory)
	    free (local_syms);
	  else
	    symtab_hdr->contents = (unsigned char *) local_syms;
	}

      if (!bfd_iteration_success)
	break; /* Propagate error, break from current bfd loop */
    }

  return overall_success;
}

/* Allocate space for overlay call and return stubs.
   Return 0 on error, 1 if no overlays, 2 otherwise.  */

static asection *
create_and_align_section (bfd *ibfd, const char *name, flagword flags,
                          unsigned int alignment)
{
  asection *sec = bfd_make_section_anyway_with_flags (ibfd, name, flags);
  if (sec == NULL)
    return NULL;
  if (!bfd_set_section_alignment (sec, alignment))
    return NULL;
  return sec;
}

int
spu_elf_size_stubs (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab;
  bfd *ibfd;
  bfd_size_type amt;
  flagword common_stub_sec_flags;
  unsigned int i;
  asection *stub_section;
  unsigned int stub_alignment;

  if (!process_stubs (info, false))
    return 0;

  htab = spu_hash_table (info);
  elf_link_hash_traverse (&htab->elf, allocate_spuear_stubs, info);
  if (htab->stub_err)
    return 0;

  ibfd = info->input_bfds;
  if (htab->stub_count != NULL)
    {
      amt = (htab->num_overlays + 1) * sizeof (*htab->stub_sec);
      htab->stub_sec = bfd_zmalloc (amt);
      if (htab->stub_sec == NULL)
        return 0;

      common_stub_sec_flags = (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_READONLY
                               | SEC_HAS_CONTENTS | SEC_IN_MEMORY);
      stub_alignment = ovl_stub_size_log2 (htab->params);

      stub_section = create_and_align_section (ibfd, ".stub", common_stub_sec_flags, stub_alignment);
      if (stub_section == NULL)
        return 0;
      htab->stub_sec[0] = stub_section;
      stub_section->size = (bfd_size_type)htab->stub_count[0] * ovl_stub_size (htab->params);
      if (htab->params->ovly_flavour == ovly_soft_icache)
        stub_section->size += (bfd_size_type)htab->stub_count[0] * 16;

      for (i = 0; i < htab->num_overlays; ++i)
        {
          asection *osec = htab->ovl_sec[i];
          unsigned int ovl_index = spu_elf_section_data (osec)->u.o.ovl_index;
          stub_section = create_and_align_section (ibfd, ".stub", common_stub_sec_flags, stub_alignment);
          if (stub_section == NULL)
            return 0;
          htab->stub_sec[ovl_index] = stub_section;
          stub_section->size = (bfd_size_type)htab->stub_count[ovl_index] * ovl_stub_size (htab->params);
        }
    }

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      flagword ovtab_flags;

      ovtab_flags = SEC_ALLOC;
      htab->ovtab = create_and_align_section (ibfd, ".ovtab", ovtab_flags, 4);
      if (htab->ovtab == NULL)
        return 0;

      htab->ovtab->size = (bfd_size_type) (32 + (16U << htab->fromelem_size_log2)) << htab->num_lines_log2;

      ovtab_flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
      htab->init = create_and_align_section (ibfd, ".ovini", ovtab_flags, 4);
      if (htab->init == NULL)
        return 0;

      htab->init->size = 16;
    }
  else if (htab->stub_count == NULL)
    {
      return 1;
    }
  else
    {
      flagword ovtab_flags;

      ovtab_flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
      htab->ovtab = create_and_align_section (ibfd, ".ovtab", ovtab_flags, 4);
      if (htab->ovtab == NULL)
        return 0;

      htab->ovtab->size = (bfd_size_type)htab->num_overlays * 16 + 16 + (bfd_size_type)htab->num_buf * 4;
    }

  htab->toe = create_and_align_section (ibfd, ".toe", SEC_ALLOC, 4);
  if (htab->toe == NULL)
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

  if (htab == NULL || htab->params == NULL || htab->params->place_spu_section == NULL)
    {
      return;
    }

  void (*place_spu_section_handler) (asection *, asection *, const char *) = htab->params->place_spu_section;

  if (htab->stub_sec != NULL)
    {
      place_spu_section_handler (htab->stub_sec[0], NULL, ".text");

      for (i = 0; i < htab->num_overlays; ++i)
	{
	  asection *osec = htab->ovl_sec[i];
	  unsigned int ovl = spu_elf_section_data (osec)->u.o.ovl_index;
	  place_spu_section_handler (htab->stub_sec[ovl], osec, NULL);
	}
    }

  if (htab->params->ovly_flavour == ovly_soft_icache)
    place_spu_section_handler (htab->init, NULL, ".ovl.init");

  if (htab->ovtab != NULL)
    {
      const char *ovout = ".data";
      if (htab->params->ovly_flavour == ovly_soft_icache)
	ovout = ".bss";
      place_spu_section_handler (htab->ovtab, NULL, ovout);
    }

  if (htab->toe != NULL)
    place_spu_section_handler (htab->toe, NULL, ".toe");
}

/* Functions to handle embedded spu_ovl.o object.  */

static void *
ovl_mgr_open (struct bfd *nbfd ATTRIBUTE_UNUSED, void *stream)
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
  size_t bytes_to_read;
  size_t stream_size;
  size_t current_offset;
  size_t requested_bytes;

  if (stream == NULL || buf == NULL) {
    return 0;
  }

  os = (struct _ovl_stream *) stream;

  if (os->start == NULL || os->end == NULL || os->start > os->end) {
    return 0;
  }

  if (nbytes < 0 || offset < 0) {
      return 0;
  }
  
  current_offset = (size_t)offset;
  requested_bytes = (size_t)nbytes;

  stream_size = (size_t)((const char *) os->end - (const char *) os->start);

  if (current_offset >= stream_size) {
    return 0;
  }

  size_t remaining_in_stream = stream_size - current_offset;
  bytes_to_read = (requested_bytes < remaining_in_stream) ? requested_bytes : remaining_in_stream;

  memcpy (buf, (const char *) os->start + current_offset, bytes_to_read);

  return (file_ptr) bytes_to_read;
}

static int
ovl_mgr_stat (struct bfd *abfd ATTRIBUTE_UNUSED,
	      void *stream,
	      struct stat *sb)
{
  struct _ovl_stream *os;

  if (sb == NULL)
    return -1;

  memset (sb, 0, sizeof (*sb));

  if (stream == NULL)
    return -1;

  os = (struct _ovl_stream *) stream;

  if (os->start == NULL || os->end == NULL || os->end < os->start)
    {
      return -1;
    }

  sb->st_size = (const char *) os->end - (const char *) os->start;
  return 0;
}

bool
spu_elf_open_builtin_lib (bfd **ovl_bfd, const struct _ovl_stream *stream)
{
  if (ovl_bfd == NULL)
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
  if (sec == NULL || sec->output_section == bfd_abs_section_ptr) {
    return 0;
  }

  struct spu_elf_section_data *data = spu_elf_section_data (sec->output_section);
  if (data == NULL) {
    return 0;
  }

  return data->u.o.ovl_index;
}

/* Define an STT_OBJECT symbol.  */

static struct elf_link_hash_entry *
define_ovtab_symbol (struct spu_link_hash_table *htab, const char *name)
{
  struct elf_link_hash_entry *h;

  h = elf_link_hash_lookup (&htab->elf, name, true, false, false);
  if (h == NULL)
    {
      return NULL;
    }

  if (h->root.type == bfd_link_hash_defined && h->def_regular)
    {
      if (h->root.u.def.section->owner != NULL)
        {
          _bfd_error_handler (_("%pB is not allowed to define %s"),
                              h->root.u.def.section->owner,
                              h->root.root.string);
          bfd_set_error (bfd_error_bad_value);
          return NULL;
        }
      else
        {
          _bfd_error_handler (_("you are not allowed to define %s in a script"),
                              h->root.root.string);
          bfd_set_error (bfd_error_bad_value);
          return NULL;
        }
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

static const unsigned int SPU_OVLY_ENTRY_COUNT = 2;
static const unsigned int SPU_OVLY_TABLE_ENTRY_SIZE = 16;
static const unsigned int SPU_OVLY_ALIGNMENT = 16;
static const unsigned int SPU_OVLY_VMA_OFFSET = 0;
static const unsigned int SPU_OVLY_SIZE_OFFSET = 4;
static const unsigned int SPU_OVLY_BUF_OFFSET = 12;
static const unsigned int SPU_OVLY_BUF_ENTRY_SIZE = 4;
static const unsigned int SPU_ICACHE_TAG_ARRAY_BASE_MULTIPLIER = 16;
static const unsigned int SPU_ICACHE_REWRITE_BASE_MULTIPLIER = 16;
static const unsigned int SPU_ICACHE_FILEOFF_SIZE = 8;
static const bfd_byte SPU_OVLY_TABLE_NON_OVERLAY_MARKER = 1;

static bool
report_bfd_error (const char *msg, bfd_error_type err_type)
{
  _bfd_error_handler (_(msg));
  bfd_set_error (err_type);
  return false;
}

static bool
report_bfd_error_format (const char *fmt, const char *arg, bfd_error_type err_type)
{
  _bfd_error_handler (_(fmt), arg);
  bfd_set_error (err_type);
  return false;
}

static struct elf_link_hash_entry *
define_ovtab_symbol_and_check (struct spu_link_hash_table *htab, const char *name)
{
  struct elf_link_hash_entry *h = define_ovtab_symbol (htab, name);
  if (h == NULL)
    report_bfd_error_format ("failed to define symbol %s", name, bfd_error_no_memory);
  return h;
}

static bool
validate_overlay_section_entries (struct spu_link_hash_table *htab)
{
  if (htab->num_overlays == 0)
    return true;

  unsigned int i;
  for (i = 0; i < SPU_OVLY_ENTRY_COUNT; i++)
    {
      struct elf_link_hash_entry *h = htab->ovly_entry[i];
      if (h != NULL
	  && (h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	  && h->def_regular)
	{
	  asection *s = h->root.u.def.section->output_section;
	  if (s != NULL && spu_elf_section_data (s)->u.o.ovl_index)
	    {
	      return report_bfd_error_format ("%s in overlay section",
					      h->root.root.string,
					      bfd_error_bad_value);
	    }
	}
    }
  return true;
}

static bool
allocate_and_process_stub_sections (struct bfd_link_info *info,
				    struct spu_link_hash_table *htab)
{
  if (htab->stub_sec == NULL)
    return true;

  unsigned int i;
  for (i = 0; i <= htab->num_overlays; i++)
    {
      asection *stub_sec = htab->stub_sec[i];
      if (stub_sec->size != 0)
	{
	  stub_sec->contents = bfd_zalloc (stub_sec->owner, stub_sec->size);
	  if (stub_sec->contents == NULL)
	    return report_bfd_error ("Failed to allocate stub section contents", bfd_error_no_memory);
	  stub_sec->alloced = 1;
	  stub_sec->rawsize = stub_sec->size;
	  stub_sec->size = 0;
	}
    }

  process_stubs (info, true);

  if (htab->stub_err)
    return report_bfd_error ("overlay stub relocation overflow", bfd_error_bad_value);

  elf_link_hash_traverse (&htab->elf, build_spuear_stubs, info);

  if (htab->stub_err)
    return report_bfd_error ("overlay stub relocation overflow", bfd_error_bad_value);

  for (i = 0; i <= htab->num_overlays; i++)
    {
      asection *stub_sec = htab->stub_sec[i];
      if (stub_sec->size != stub_sec->rawsize)
	{
	  return report_bfd_error ("stubs don't match calculated size",
				    bfd_error_bad_value);
	}
      stub_sec->rawsize = 0;
    }

  return true;
}

static bool
allocate_ovtab_contents (struct spu_link_hash_table *htab)
{
  if (htab->ovtab == NULL || htab->ovtab->size == 0)
    return true;

  htab->ovtab->contents = bfd_zalloc (htab->ovtab->owner, htab->ovtab->size);
  if (htab->ovtab->contents == NULL)
    return report_bfd_error ("Failed to allocate overlay table contents", bfd_error_no_memory);
  htab->ovtab->alloced = 1;
  return true;
}

static bool
populate_icache_symbols (struct spu_link_hash_table *htab)
{
  bfd_vma off = 0;
  struct elf_link_hash_entry *h;

  bfd_vma tag_array_size = SPU_ICACHE_TAG_ARRAY_BASE_MULTIPLIER << htab->num_lines_log2;
  bfd_vma rewrite_size = SPU_ICACHE_REWRITE_BASE_MULTIPLIER << htab->num_lines_log2;
  bfd_vma rewrite_from_size = SPU_ICACHE_REWRITE_BASE_MULTIPLIER << (htab->fromelem_size_log2 + htab->num_lines_log2);
  bfd_vma cache_line_size = 1 << htab->line_size_log2;
  bfd_vma cache_size = 1 << (htab->num_lines_log2 + htab->line_size_log2);

  h = define_ovtab_symbol_and_check (htab, "__icache_tag_array");
  if (h == NULL) return false;
  h->root.u.def.value = 0;
  h->size = tag_array_size;
  off = h->size;

  h = define_ovtab_symbol_and_check (htab, "__icache_tag_array_size");
  if (h == NULL) return false;
  h->root.u.def.value = tag_array_size;
  h->root.u.def.section = bfd_abs_section_ptr;

  h = define_ovtab_symbol_and_check (htab, "__icache_rewrite_to");
  if (h == NULL) return false;
  h->root.u.def.value = off;
  h->size = rewrite_size;
  off += h->size;

  h = define_ovtab_symbol_and_check (htab, "__icache_rewrite_to_size");
  if (h == NULL) return false;
  h->root.u.def.value = rewrite_size;
  h->root.u.def.section = bfd_abs_section_ptr;

  h = define_ovtab_symbol_and_check (htab, "__icache_rewrite_from");
  if (h == NULL) return false;
  h->root.u.def.value = off;
  h->size = rewrite_from_size;
  off += h->size;

  h = define_ovtab_symbol_and_check (htab, "__icache_rewrite_from_size");
  if (h == NULL) return false;
  h->root.u.def.value = rewrite_from_size;
  h->root.u.def.section = bfd_abs_section_ptr;

  h = define_ovtab_symbol_and_check (htab, "__icache_log2_fromelemsize");
  if (h == NULL) return false;
  h->root.u.def.value = htab->fromelem_size_log2;
  h->root.u.def.section = bfd_abs_section_ptr;

  h = define_ovtab_symbol_and_check (htab, "__icache_base");
  if (h == NULL) return false;
  h->root.u.def.value = htab->ovl_sec[0]->vma;
  h->root.u.def.section = bfd_abs_section_ptr;
  h->size = htab->num_buf << htab->line_size_log2;

  h = define_ovtab_symbol_and_check (htab, "__icache_linesize");
  if (h == NULL) return false;
  h->root.u.def.value = cache_line_size;
  h->root.u.def.section = bfd_abs_section_ptr;

  h = define_ovtab_symbol_and_check (htab, "__icache_log2_linesize");
  if (h == NULL) return false;
  h->root.u.def.value = htab->line_size_log2;
  h->root.u.def.section = bfd_abs_section_ptr;

  h = define_ovtab_symbol_and_check (htab, "__icache_neg_log2_linesize");
  if (h == NULL) return false;
  h->root.u.def.value = -htab->line_size_log2;
  h->root.u.def.section = bfd_abs_section_ptr;

  h = define_ovtab_symbol_and_check (htab, "__icache_cachesize");
  if (h == NULL) return false;
  h->root.u.def.value = cache_size;
  h->root.u.def.section = bfd_abs_section_ptr;

  h = define_ovtab_symbol_and_check (htab, "__icache_log2_cachesize");
  if (h == NULL) return false;
  h->root.u.def.value = htab->num_lines_log2 + htab->line_size_log2;
  h->root.u.def.section = bfd_abs_section_ptr;

  h = define_ovtab_symbol_and_check (htab, "__icache_neg_log2_cachesize");
  if (h == NULL) return false;
  h->root.u.def.value = -(htab->num_lines_log2 + htab->line_size_log2);
  h->root.u.def.section = bfd_abs_section_ptr;

  if (htab->init != NULL && htab->init->size != 0)
    {
      htab->init->contents = bfd_zalloc (htab->init->owner, htab->init->size);
      if (htab->init->contents == NULL)
	return report_bfd_error ("Failed to allocate icache init contents", bfd_error_no_memory);
      htab->init->alloced = 1;

      h = define_ovtab_symbol_and_check (htab, "__icache_fileoff");
      if (h == NULL) return false;
      h->root.u.def.value = 0;
      h->root.u.def.section = htab->init;
      h->size = SPU_ICACHE_FILEOFF_SIZE;
    }

  return true;
}

static bool
populate_normal_ovtab_and_symbols (struct bfd_link_info *info,
				   struct spu_link_hash_table *htab)
{
  bfd_byte *p = htab->ovtab->contents;
  struct elf_link_hash_entry *h;
  asection *s;
  bfd *obfd = htab->ovtab->output_section->owner;

  p[7] = SPU_OVLY_TABLE_NON_OVERLAY_MARKER;

  for (s = obfd->sections; s != NULL; s = s->next)
    {
      unsigned int ovl_index = spu_elf_section_data (s)->u.o.ovl_index;

      if (ovl_index != 0)
	{
	  unsigned long off = (unsigned long)ovl_index * SPU_OVLY_TABLE_ENTRY_SIZE;
	  unsigned int ovl_buf = spu_elf_section_data (s)->u.o.ovl_buf;

	  bfd_put_32 (htab->ovtab->owner, s->vma, p + off + SPU_OVLY_VMA_OFFSET);
	  bfd_put_32 (htab->ovtab->owner,
		      (s->size + SPU_OVLY_ALIGNMENT - 1) & ~(SPU_OVLY_ALIGNMENT - 1),
		      p + off + SPU_OVLY_SIZE_OFFSET);
	  bfd_put_32 (htab->ovtab->owner, ovl_buf, p + off + SPU_OVLY_BUF_OFFSET);
	}
    }

  h = define_ovtab_symbol_and_check (htab, "_ovly_table");
  if (h == NULL) return false;
  h->root.u.def.value = SPU_OVLY_TABLE_ENTRY_SIZE;
  h->size = htab->num_overlays * SPU_OVLY_TABLE_ENTRY_SIZE;

  h = define_ovtab_symbol_and_check (htab, "_ovly_table_end");
  if (h == NULL) return false;
  h->root.u.def.value = htab->num_overlays * SPU_OVLY_TABLE_ENTRY_SIZE + SPU_OVLY_TABLE_ENTRY_SIZE;
  h->size = 0;

  h = define_ovtab_symbol_and_check (htab, "_ovly_buf_table");
  if (h == NULL) return false;
  h->root.u.def.value = htab->num_overlays * SPU_OVLY_TABLE_ENTRY_SIZE + SPU_OVLY_TABLE_ENTRY_SIZE;
  h->size = htab->num_buf * SPU_OVLY_BUF_ENTRY_SIZE;

  h = define_ovtab_symbol_and_check (htab, "_ovly_buf_table_end");
  if (h == NULL) return false;
  h->root.u.def.value = htab->num_overlays * SPU_OVLY_TABLE_ENTRY_SIZE + SPU_OVLY_TABLE_ENTRY_SIZE + htab->num_buf * SPU_OVLY_BUF_ENTRY_SIZE;
  h->size = 0;

  return true;
}

static bool
define_ear_symbol (struct spu_link_hash_table *htab)
{
  struct elf_link_hash_entry *h = define_ovtab_symbol_and_check (htab, "_EAR_");
  if (h == NULL) return false;
  h->root.u.def.section = htab->toe;
  h->root.u.def.value = 0;
  h->size = SPU_OVLY_TABLE_ENTRY_SIZE;

  return true;
}

static bool
spu_elf_build_stubs (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (!validate_overlay_section_entries (htab))
    return false;

  if (!allocate_and_process_stub_sections (info, htab))
    return false;

  if (!allocate_ovtab_contents (htab))
    return false;

  if (htab->ovtab == NULL || htab->ovtab->size == 0)
    return true;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      if (!populate_icache_symbols (htab))
	return false;
    }
  else
    {
      if (!populate_normal_ovtab_and_symbols (info, htab))
	return false;
    }

  if (!define_ear_symbol (htab))
    return false;

  return true;
}

/* Check that all loadable section VMAs lie in the range
   LO .. HI inclusive, and stash some parameters for --auto-overlay.  */

asection *
spu_elf_check_vma (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table(info);
  bfd *output_bfd = info->output_bfd;

  bfd_vma local_store_hi = htab->params->local_store_hi;
  bfd_vma local_store_lo = htab->params->local_store_lo;

  if (local_store_hi >= local_store_lo)
    htab->local_store = local_store_hi - local_store_lo + 1;
  else
    htab->local_store = 0;

  for (struct elf_segment_map *segment_map = elf_seg_map(output_bfd);
       segment_map != NULL;
       segment_map = segment_map->next)
  {
    if (segment_map->p_type == PT_LOAD)
    {
      for (unsigned int i = 0; i < segment_map->count; ++i)
      {
        asection *section = segment_map->sections[i];

        if (section->size == 0)
        {
          continue;
        }

        bfd_vma section_start_vma = section->vma;
        bfd_vma section_end_vma = section->vma + section->size - 1;

        if (section_start_vma < local_store_lo || section_end_vma > local_store_hi)
        {
          return section;
        }
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
  if (sec == NULL || lr_store == NULL || sp_adjust == NULL) {
    return -1;
  }

  int32_t reg_values[128];
  memset (reg_values, 0, sizeof (reg_values));

  *lr_store = (bfd_vma) -1;
  *sp_adjust = (bfd_vma) -1;

  while (offset + 4 <= sec->size)
    {
      unsigned char instruction_bytes[4];
      int rt_reg, ra_reg;
      uint32_t immediate_val;

      if (!bfd_get_section_contents (sec->owner, sec, instruction_bytes, offset, 4)) {
	    break;
      }

      rt_reg = instruction_bytes[3] & 0x7f;
      ra_reg = ((instruction_bytes[2] & 0x3f) << 1) | (instruction_bytes[3] >> 7);

      immediate_val = (instruction_bytes[1] << 9) | (instruction_bytes[2] << 1) | (instruction_bytes[3] >> 7);

      if (instruction_bytes[0] == 0x24 /* stqd */)
	{
	  if (rt_reg == 0 /* lr */ && ra_reg == 1 /* sp */) {
	    *lr_store = offset;
	  }
	}
      else if (instruction_bytes[0] == 0x1c /* ai */)
	{
	  immediate_val >>= 7;
	  immediate_val = (immediate_val ^ 0x200) - 0x200;
	  reg_values[rt_reg] = reg_values[ra_reg] + (int32_t)immediate_val;

	  if (rt_reg == 1 /* sp */)
	    {
	      if (reg_values[rt_reg] > 0) {
		    break;
          }
	      *sp_adjust = offset;
	      return reg_values[rt_reg];
	    }
	}
      else if (instruction_bytes[0] == 0x18 && (instruction_bytes[1] & 0xe0) == 0 /* a */)
	{
	  int rb_reg = ((instruction_bytes[1] & 0x1f) << 2) | ((instruction_bytes[2] & 0xc0) >> 6);
	  reg_values[rt_reg] = reg_values[ra_reg] + reg_values[rb_reg];

	  if (rt_reg == 1 /* sp */)
	    {
	      if (reg_values[rt_reg] > 0) {
		    break;
          }
	      *sp_adjust = offset;
	      return reg_values[rt_reg];
	    }
	}
      else if (instruction_bytes[0] == 0x08 && (instruction_bytes[1] & 0xe0) == 0 /* sf */)
	{
	  int rb_reg = ((instruction_bytes[1] & 0x1f) << 2) | ((instruction_bytes[2] & 0xc0) >> 6);
	  reg_values[rt_reg] = reg_values[rb_reg] - reg_values[ra_reg];

	  if (rt_reg == 1 /* sp */)
	    {
	      if (reg_values[rt_reg] > 0) {
		    break;
          }
	      *sp_adjust = offset;
	      return reg_values[rt_reg];
	    }
	}
      else if ((instruction_bytes[0] & 0xfc) == 0x40 /* il, ilh, ilhu, ila */)
	{
	  if (instruction_bytes[0] >= 0x42 /* ila */)
	    immediate_val |= (instruction_bytes[0] & 1) << 17;
	  else
	    {
	      immediate_val &= 0xffff;

	      if (instruction_bytes[0] == 0x40 /* il */)
		{
		  if ((instruction_bytes[1] & 0x80) != 0) {
		    immediate_val = (immediate_val ^ 0x8000) - 0x8000;
          }
		}
	      else if ((instruction_bytes[1] & 0x80) == 0 /* ilhu */) {
		    immediate_val <<= 16;
          }
	    }
	  reg_values[rt_reg] = (int32_t)immediate_val;
	}
      else if (instruction_bytes[0] == 0x60 && (instruction_bytes[1] & 0x80) != 0 /* iohl */)
	{
	  reg_values[rt_reg] |= (int32_t)(immediate_val & 0xffff);
	}
      else if (instruction_bytes[0] == 0x04 /* ori */)
	{
	  immediate_val >>= 7;
	  immediate_val = (immediate_val ^ 0x200) - 0x200;
	  reg_values[rt_reg] = reg_values[ra_reg] | (int32_t)immediate_val;
	}
      else if (instruction_bytes[0] == 0x32 && (instruction_bytes[1] & 0x80) != 0 /* fsmbi */)
	{
	  reg_values[rt_reg] = (  ((immediate_val & 0x8000) ? (int32_t)0xff000000 : 0)
		                     | ((immediate_val & 0x4000) ? (int32_t)0x00ff0000 : 0)
		                     | ((immediate_val & 0x2000) ? (int32_t)0x0000ff00 : 0)
		                     | ((immediate_val & 0x1000) ? (int32_t)0x000000ff : 0));
	}
      else if (instruction_bytes[0] == 0x16 /* andbi */)
	{
	  uint32_t andbi_imm = immediate_val >> 7;
	  andbi_imm &= 0xff;
	  andbi_imm |= andbi_imm << 8;
	  andbi_imm |= andbi_imm << 16;
	  reg_values[rt_reg] = reg_values[ra_reg] & (int32_t)andbi_imm;
	}
      else if (instruction_bytes[0] == 0x33 && immediate_val == 1 /* brsl .+4 */)
	{
	  reg_values[rt_reg] = 0;
	}
      else if (is_branch (instruction_bytes) || is_indirect_branch (instruction_bytes))
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
  Elf_Internal_Sym *const *s1_ref = a;
  Elf_Internal_Sym *const *s2_ref = b;

  Elf_Internal_Sym *s1 = *s1_ref;
  Elf_Internal_Sym *s2 = *s2_ref;

  asection *sec1, *sec2;
  bfd_signed_vma delta;
  ptrdiff_t idx1, idx2;

  idx1 = s1 - sort_syms_syms;
  idx2 = s2 - sort_syms_syms;

  sec1 = sort_syms_psecs[idx1];
  sec2 = sort_syms_psecs[idx2];

  if (sec1 != sec2)
    return (int)sec1->index - (int)sec2->index;

  delta = s1->st_value - s2->st_value;
  if (delta != 0)
    return delta < 0 ? -1 : 1;

  delta = s2->st_size - s1->st_size;
  if (delta != 0)
    return delta < 0 ? -1 : 1;

  return s1 < s2 ? -1 : 1;
}

/* Allocate a struct spu_elf_stack_info with MAX_FUN struct function_info
   entries for section SEC.  */

static struct spu_elf_stack_info *
alloc_stack_info (asection *sec, int max_fun)
{
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *stack_info = NULL;
  bfd_size_type base_size;
  bfd_size_type func_info_element_size;
  bfd_size_type num_additional_elements;
  bfd_size_type additional_elements_bytes;
  bfd_size_type total_allocation_size;
  const bfd_size_type MAX_BFD_SIZE_TYPE = (bfd_size_type)-1;

  if (max_fun <= 0)
  {
    return NULL;
  }

  sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL)
  {
    return NULL;
  }

  base_size = sizeof (struct spu_elf_stack_info);
  func_info_element_size = sizeof (struct function_info);
  
  num_additional_elements = (bfd_size_type)(max_fun - 1);

  if (num_additional_elements > 0 && MAX_BFD_SIZE_TYPE / num_additional_elements < func_info_element_size)
  {
    return NULL;
  }

  additional_elements_bytes = num_additional_elements * func_info_element_size;

  if (MAX_BFD_SIZE_TYPE - additional_elements_bytes < base_size)
  {
    return NULL;
  }

  total_allocation_size = base_size + additional_elements_bytes;

  stack_info = bfd_zmalloc (total_allocation_size);

  if (stack_info != NULL)
  {
    stack_info->max_fun = max_fun;
    sec_data->u.i.stack_info = stack_info;
  }
  
  return stack_info;
}

/* Add a new struct function_info describing a (part of a) function
   starting at SYM_H.  Keep the array sorted by address.  */

static void
get_symbol_info (void *sym_h, bool global, bfd_vma *off_ptr, bfd_vma *size_ptr)
{
  if (!global)
    {
      Elf_Internal_Sym *sym = (Elf_Internal_Sym *) sym_h;
      *off_ptr = sym->st_value;
      *size_ptr = sym->st_size;
    }
  else
    {
      struct elf_link_hash_entry *h = (struct elf_link_hash_entry *) sym_h;
      *off_ptr = h->root.u.def.value;
      *size_ptr = h->size;
    }
}

static const int INITIAL_FUNCTION_CAPACITY = 20;
static const int FUNCTION_GROWTH_ADD = 20;
static const int FUNCTION_GROWTH_SHIFT = 1;

static struct function_info *
maybe_insert_function (asection *sec,
		       void *sym_h,
		       bool global,
		       bool is_func)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  bfd_vma off, size;
  int insert_idx;

  if (sinfo == NULL)
    {
      sinfo = alloc_stack_info (sec, INITIAL_FUNCTION_CAPACITY);
      if (sinfo == NULL)
	return NULL;
    }

  get_symbol_info(sym_h, global, &off, &size);

  for (insert_idx = sinfo->num_fun; --insert_idx >= 0; )
    if (sinfo->fun[insert_idx].lo <= off)
      break;

  if (insert_idx >= 0)
    {
      if (sinfo->fun[insert_idx].lo == off)
	{
	  if (global && !sinfo->fun[insert_idx].global)
	    {
	      sinfo->fun[insert_idx].global = true;
	      sinfo->fun[insert_idx].u.h = sym_h;
	    }
	  if (is_func)
	    sinfo->fun[insert_idx].is_func = true;
	  return &sinfo->fun[insert_idx];
	}
      else if (sinfo->fun[insert_idx].hi > off && size == 0)
	{
	  return &sinfo->fun[insert_idx];
	}
    }

  if (sinfo->num_fun >= sinfo->max_fun)
    {
      bfd_size_type base_size = sizeof (struct spu_elf_stack_info);
      bfd_size_type old_total_size_bytes = base_size + (sinfo->max_fun - 1) * sizeof (struct function_info);

      sinfo->max_fun += FUNCTION_GROWTH_ADD + (sinfo->max_fun >> FUNCTION_GROWTH_SHIFT);
      if (sinfo->max_fun < INITIAL_FUNCTION_CAPACITY)
        sinfo->max_fun = INITIAL_FUNCTION_CAPACITY;

      bfd_size_type new_total_size_bytes = base_size + (sinfo->max_fun - 1) * sizeof (struct function_info);

      sinfo = bfd_realloc (sinfo, new_total_size_bytes);
      if (sinfo == NULL)
	return NULL;

      memset ((char *) sinfo + old_total_size_bytes, 0,
              new_total_size_bytes - old_total_size_bytes);
      sec_data->u.i.stack_info = sinfo;
    }

  insert_idx++;

  if (insert_idx < sinfo->num_fun)
    {
      memmove (&sinfo->fun[insert_idx + 1], &sinfo->fun[insert_idx],
	       (sinfo->num_fun - insert_idx) * sizeof (sinfo->fun[insert_idx]));
    }

  sinfo->fun[insert_idx].is_func = is_func;
  sinfo->fun[insert_idx].global = global;
  sinfo->fun[insert_idx].sec = sec;

  if (global)
    sinfo->fun[insert_idx].u.h = sym_h;
  else
    sinfo->fun[insert_idx].u.sym = sym_h;

  sinfo->fun[insert_idx].lo = off;
  sinfo->fun[insert_idx].hi = off + size;
  sinfo->fun[insert_idx].lr_store = -1;
  sinfo->fun[insert_idx].sp_adjust = -1;

  sinfo->fun[insert_idx].stack = -find_function_stack_adjust (
                                    sec,
                                    off,
                                    &sinfo->fun[insert_idx].lr_store,
                                    &sinfo->fun[insert_idx].sp_adjust
                                  );

  sinfo->num_fun += 1;

  return &sinfo->fun[insert_idx];
}

/* Return the name of FUN.  */

static const char *
func_name (struct function_info *fun)
{
  /* + for the '+' character, 8 for the 32-bit hex value (e.g., FFFFFFFF),
   * + 1 for the null terminator. */
#define DYN_NAME_SUFFIX_SIZE (1 + 8 + 1)

  /* Input validation for 'fun' */
  if (fun == NULL)
    return "(null)";

  /* Traverse linked list to find the 'start' (root) function_info */
  while (fun->start != NULL)
    fun = fun->start;

  /* Handle global functions */
  if (fun->global)
    {
      /* Defensive check for fun->u.h */
      if (fun->u.h == NULL)
        return "(null)";
      return fun->u.h->root.root.string;
    }

  /* From here, we are dealing with non-global functions. */
  asection *sec = fun->sec;

  /* Defensive checks for critical pointers before use */
  if (sec == NULL)
    return "(null)";

  /* Critical check before accessing fun->u.sym->st_name or st_value */
  if (fun->u.sym == NULL)
    return "(null)";

  /* Handle functions with no name (st_name == 0) */
  if (fun->u.sym->st_name == 0)
    {
      /* Defensive check for sec->name */
      if (sec->name == NULL)
        return "(null)";

      size_t len = strlen (sec->name);
      /* Ensure sufficient buffer size for "<sec_name>+<hex_value>\0" */
      char *name_buffer = bfd_malloc (len + DYN_NAME_SUFFIX_SIZE);
      if (name_buffer == NULL)
	return "(null)"; /* Consistent error return */

      /* sprintf is used as in original code; buffer size calculation ensures safety. */
      sprintf (name_buffer, "%s+%lx", sec->name,
	       (unsigned long) (fun->u.sym->st_value & 0xffffffff));
      return name_buffer; /* Caller is expected to bfd_free this. */
    }
  
  /* Handle functions with a name (st_name != 0) */
  bfd *ibfd = sec->owner;
  if (ibfd == NULL) /* Defensive check */
    return "(null)";

  /* Check if elf_tdata returns a valid pointer before dereferencing.
   * elf_tdata is typically a macro that accesses bfd->tdata, which could be NULL. */
  struct bfd_elf_section_data *elf_data = elf_tdata (ibfd);
  if (elf_data == NULL)
    return "(null)";

  Elf_Internal_Shdr *symtab_hdr = &elf_data->symtab_hdr;
  
  /* bfd_elf_sym_name is assumed to return an internal, non-owned string. */
  const char *sym_name = bfd_elf_sym_name (ibfd, symtab_hdr, fun->u.sym, sec);
  
  if (sym_name == NULL) /* If the BFD function unexpectedly returns NULL */
    return "(null)";

  return sym_name;
#undef DYN_NAME_SUFFIX_SIZE
}

/* Read the instruction at OFF in SEC.  Return true iff the instruction
   is a nop, lnop, or stop 0 (all zero insn).  */

#define NOP_PATTERN_1_BYTE0_MASK  0xbf
#define NOP_PATTERN_1_BYTE0_VALUE 0x00
#define NOP_PATTERN_1_BYTE1_MASK  0xe0
#define NOP_PATTERN_1_BYTE1_VALUE 0x20

static bool
is_nop (asection *sec, bfd_vma off)
{
  unsigned char insn_bytes[4];
  const size_t instruction_size = sizeof(insn_bytes);

  if (sec->size < instruction_size || off > sec->size - instruction_size)
    return false;

  if (!bfd_get_section_contents (sec->owner, sec, insn_bytes, off, instruction_size))
    return false;

  bool pattern_1_matches = ((insn_bytes[0] & NOP_PATTERN_1_BYTE0_MASK) == NOP_PATTERN_1_BYTE0_VALUE &&
                            (insn_bytes[1] & NOP_PATTERN_1_BYTE1_MASK) == NOP_PATTERN_1_BYTE1_VALUE);

  bool pattern_2_matches = (insn_bytes[0] == 0x00 &&
                            insn_bytes[1] == 0x00 &&
                            insn_bytes[2] == 0x00 &&
                            insn_bytes[3] == 0x00);

  return pattern_1_matches || pattern_2_matches;
}

/* Extend the range of FUN to cover nop padding up to LIMIT.
   Return TRUE iff some instruction other than a NOP was found.  */

static bool
insns_at_end (struct function_info *fun, bfd_vma limit)
{
  if (fun == NULL || fun->sec == NULL)
    {
      return false;
    }

  const bfd_vma instruction_alignment_size = 4;

  bfd_vma current_offset = (fun->hi + instruction_alignment_size - 1) & ~(instruction_alignment_size - 1);

  // If the calculated starting offset is already at or beyond the limit,
  // we cannot find any instructions within the valid range.
  // In this case, fun->hi should be set to the limit.
  if (current_offset >= limit)
    {
      fun->hi = limit;
      return false;
    }

  while (current_offset < limit && is_nop (fun->sec, current_offset))
    {
      current_offset += instruction_alignment_size;
    }

  if (current_offset < limit)
    {
      // A non-NOP instruction was found before reaching the limit.
      fun->hi = current_offset;
      return true;
    }
  else
    {
      // All instructions up to the limit were NOPs, or current_offset reached/exceeded limit.
      fun->hi = limit;
      return false;
    }
}

/* Check and fix overlapping function ranges.  Return TRUE iff there
   are gaps in the current info we have about functions in SEC.  */

static bool
check_function_ranges (asection *sec, struct bfd_link_info *info)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  bool gaps_found = false;

  if (sinfo == NULL)
    {
      return false;
    }

  struct spu_elf_func_info *functions = sinfo->fun;
  int num_functions = sinfo->num_fun;

  for (int i = 1; i < num_functions; ++i)
    {
      struct spu_elf_func_info *prev_func = &functions[i - 1];
      struct spu_elf_func_info *curr_func = &functions[i];

      if (prev_func->hi > curr_func->lo)
        {
          const char *f1 = func_name (prev_func);
          const char *f2 = func_name (curr_func);
          info->callbacks->einfo (_("warning: %s overlaps %s\n"), f1, f2);
          prev_func->hi = curr_func->lo;
        }
      else if (insns_at_end (prev_func, curr_func->lo))
        {
          gaps_found = true;
        }
    }

  if (num_functions == 0)
    {
      gaps_found = true;
    }
  else
    {
      if (functions[0].lo != 0)
        {
          gaps_found = true;
        }

      struct spu_elf_func_info *last_func = &functions[num_functions - 1];
      if (last_func->hi > sec->size)
        {
          const char *f1 = func_name (last_func);
          info->callbacks->einfo (_("warning: %s exceeds section size\n"), f1);
          last_func->hi = sec->size;
        }
      else if (insns_at_end (last_func, sec->size))
        {
          gaps_found = true;
        }
    }

  return gaps_found;
}

/* Search current function info for a function that contains address
   OFFSET in section SEC.  */

static struct function_info *
find_function (asection *sec, bfd_vma offset, struct bfd_link_info *info)
{
  if (info == NULL || info->callbacks == NULL) {
    bfd_set_error (bfd_error_invalid_operation);
    return NULL;
  }

  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL) {
    info->callbacks->einfo (_("%pA: SPU ELF section data not found\n"), sec);
    bfd_set_error (bfd_error_bad_value);
    return NULL;
  }

  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL) {
    info->callbacks->einfo (_("%pA: SPU ELF stack info not found in section data\n"), sec);
    bfd_set_error (bfd_error_bad_value);
    return NULL;
  }

  if (sinfo->num_fun < 0) {
      info->callbacks->einfo (_("%pA: SPU ELF stack info has invalid negative number of functions: %d\n"), sec, sinfo->num_fun);
      bfd_set_error (bfd_error_bad_value);
      return NULL;
  }

  if (sinfo->num_fun > 0 && sinfo->fun == NULL) {
      info->callbacks->einfo (_("%pA: SPU ELF stack info indicates %d functions but 'fun' array is NULL\n"), sec, sinfo->num_fun);
      bfd_set_error (bfd_error_bad_value);
      return NULL;
  }

  int lo = 0;
  int hi = sinfo->num_fun;

  while (lo < hi)
    {
      int mid = lo + (hi - lo) / 2;
      if (offset < sinfo->fun[mid].lo)
	hi = mid;
      else if (offset >= sinfo->fun[mid].hi)
	lo = mid + 1;
      else
	return &sinfo->fun[mid];
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
  if (caller == NULL || callee == NULL)
    {
      return false;
    }

  struct call_info **pp;
  struct call_info *p;

  for (pp = &caller->call_list; (p = *pp) != NULL; pp = &p->next)
    {
      if (p->fun == callee->fun)
        {
          p->is_tail = p->is_tail && callee->is_tail;

          if (!p->is_tail)
            {
              if (p->fun != NULL)
                {
                  p->fun->start = NULL;
                  p->fun->is_func = true;
                }
            }

          p->count += callee->count;

          *pp = p->next;
          p->next = caller->call_list;
          caller->call_list = p;

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
  if (s == NULL)
    {
      return false;
    }

  bool is_output_section_not_abs = (s->output_section != bfd_abs_section_ptr);

  const unsigned int required_flags_mask = SEC_ALLOC | SEC_LOAD | SEC_CODE;
  const unsigned int forbidden_flags_mask = SEC_IN_MEMORY;

  bool has_all_required_flags = ((s->flags & required_flags_mask) == required_flags_mask);
  bool has_no_forbidden_flags = ((s->flags & forbidden_flags_mask) == 0);
  bool are_flags_correct = has_all_required_flags && has_no_forbidden_flags;

  bool is_size_non_zero = (s->size != 0);

  return is_output_section_not_abs
         && are_flags_correct
         && is_size_non_zero;
}

/* Rummage through the relocs for SEC, looking for function calls.
   If CALL_TREE is true, fill in call graph.  If CALL_TREE is false,
   mark destination symbols on calls as being functions.  Also
   look at branches, which may be tail calls or go to hot/cold
   section part of same function.  */

static void
handle_function_start_merge (struct function_info *caller_fun,
                             struct function_info *callee_fun,
                             asection *sec, asection *sym_sec)
{
  if (sec->owner != sym_sec->owner)
    {
      callee_fun->start = NULL;
      callee_fun->is_func = true;
    }
  else
    {
      struct function_info *caller_root_fun = caller_fun;
      while (caller_root_fun->start)
	caller_root_fun = caller_root_fun->start;

      struct function_info *callee_root_fun = callee_fun;
      while (callee_root_fun->start)
	callee_root_fun = callee_root_fun->start;

      if (caller_root_fun != callee_root_fun)
	{
	  if (callee_fun->start == NULL)
	    {
	      callee_fun->start = caller_root_fun;
	    }
	  else
	    {
	      callee_fun->start = NULL;
	      callee_fun->is_func = true;
	    }
	}
    }
}

static bool
process_branch_instruction_reloc (asection *sec,
                                  struct bfd_link_info *info,
                                  const Elf_Internal_Rela *irela,
                                  asection *sym_sec,
                                  bool *p_is_call_instruction,
                                  unsigned int *p_priority,
                                  bool *p_is_branch_reloc_type_flag,
                                  bool *p_warned_non_code_call,
                                  bool *p_error_occurred)
{
  unsigned char insn[4];
  if (!bfd_get_section_contents (sec->owner, sec, insn, irela->r_offset, 4))
    {
      *p_error_occurred = true;
      return false;
    }

  if (is_branch (insn))
    {
      *p_is_call_instruction = (insn[0] & 0xfd) == 0x31;

      unsigned int current_priority = insn[1] & 0x0f;
      current_priority <<= 8;
      current_priority |= insn[2];
      current_priority <<= 8;
      current_priority |= insn[3];
      *p_priority = current_priority >> 7;

      if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE)) != (SEC_ALLOC | SEC_LOAD | SEC_CODE))
	{
	  if (!*p_warned_non_code_call)
	    {
	      info->callbacks->einfo
		(_("%pB(%pA+0x%v): call to non-code section"
		   " %pB(%pA), analysis incomplete\n"),
		 sec->owner, sec, irela->r_offset,
		 sym_sec->owner, sym_sec);
	      *p_warned_non_code_call = true;
	    }
	  return false;
	}
    }
  else
    {
      *p_is_branch_reloc_type_flag = false;
      if (is_hint (insn))
	return false;
    }
  return true;
}

static bool
process_non_branch_reloc_type_logic (struct bfd_link_info *info,
                                     const Elf_Internal_Sym *sym,
                                     const struct elf_link_hash_entry *h,
                                     const asection *sym_sec,
                                     int call_tree)
{
  unsigned int sym_type = (h != NULL) ? h->type : ELF_ST_TYPE (sym->st_info);

  if (sym_type == STT_FUNC)
    {
      if (call_tree && spu_hash_table (info)->params->auto_overlay)
	spu_hash_table (info)->non_ovly_stub += 1;
      return false;
    }
  if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE)) != (SEC_ALLOC | SEC_LOAD | SEC_CODE))
    return false;

  return true;
}

static bool
insert_function_non_call_tree (const Elf_Internal_Rela *irela,
                               asection *sym_sec,
                               Elf_Internal_Sym *orig_sym,
                               struct elf_link_hash_entry *h,
                               bfd_vma val,
                               bool is_call_instruction)
{
  Elf_Internal_Sym *temp_sym_ptr = NULL;
  bool temp_sym_allocated = false;

  if (irela->r_addend != 0)
    {
      temp_sym_ptr = bfd_zmalloc (sizeof (*temp_sym_ptr));
      if (temp_sym_ptr == NULL)
	return false;
      temp_sym_ptr->st_value = val;
      temp_sym_ptr->st_shndx = _bfd_elf_section_from_bfd_section (sym_sec->owner, sym_sec);
      temp_sym_allocated = true;
    }

  struct function_info *fun = NULL;
  if (temp_sym_ptr != NULL)
    fun = maybe_insert_function (sym_sec, temp_sym_ptr, false, is_call_instruction);
  else
    fun = maybe_insert_function (sym_sec, h, true, is_call_instruction);

  if (fun == NULL)
    {
      if (temp_sym_allocated)
	free (temp_sym_ptr);
      return false;
    }

  if (temp_sym_allocated && fun->u.sym != temp_sym_ptr)
    free (temp_sym_ptr);

  return true;
}

static bool
mark_functions_via_relocs (asection *sec,
			   struct bfd_link_info *info,
			   int call_tree)
{
  Elf_Internal_Rela *internal_relocs = NULL;
  bool success = true;
  static bool warned_non_code_call = false;

  if (!interesting_section (sec) || sec->reloc_count == 0)
    return true;

  internal_relocs = _bfd_elf_link_read_relocs (sec->owner, sec, NULL, NULL, info->keep_memory);
  if (internal_relocs == NULL)
    return false;

  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (sec->owner)->symtab_hdr;
  void *psyms = &symtab_hdr->contents;

  for (unsigned int i = 0; i < sec->reloc_count; ++i)
    {
      Elf_Internal_Rela *irela = &internal_relocs[i];

      enum elf_spu_reloc_type r_type = ELF32_R_TYPE (irela->r_info);
      unsigned int r_indx = ELF32_R_SYM (irela->r_info);

      asection *sym_sec = NULL;
      Elf_Internal_Sym *sym = NULL;
      struct elf_link_hash_entry *h = NULL;

      if (!get_sym_h (&h, &sym, &sym_sec, psyms, r_indx, sec->owner))
	{
	  success = false;
	  break;
	}

      if (sym_sec == NULL || sym_sec->output_section == bfd_abs_section_ptr)
	continue;

      bool is_branch_reloc_type_flag = (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16);
      bool is_call_instruction = false;
      unsigned int priority = 0;

      if (is_branch_reloc_type_flag)
	{
	  bool error_in_helper = false;
	  if (!process_branch_instruction_reloc (sec, info, irela, sym_sec,
						 &is_call_instruction, &priority,
						 &is_branch_reloc_type_flag,
						 &warned_non_code_call, &error_in_helper))
	    {
	      if (error_in_helper)
		{
		  success = false;
		  break;
		}
	      else
		continue;
	    }
	}

      if (!is_branch_reloc_type_flag)
	{
	  if (!process_non_branch_reloc_type_logic (info, sym, h, sym_sec, call_tree))
	    continue;
	}

      bfd_vma val = (h != NULL) ? h->root.u.def.value : sym->st_value;
      val += irela->r_addend;

      if (!call_tree)
	{
	  if (!insert_function_non_call_tree (irela, sym_sec, sym, h, val, is_call_instruction))
	    {
	      success = false;
	      break;
	    }
	  continue;
	}

      struct function_info *caller = find_function (sec, irela->r_offset, info);
      if (caller == NULL)
	{
	  success = false;
	  break;
	}

      struct call_info *callee = bfd_malloc (sizeof (*callee));
      if (callee == NULL)
	{
	  success = false;
	  break;
	}

      callee->fun = find_function (sym_sec, val, info);
      if (callee->fun == NULL)
	{
	  bfd_free (callee);
	  success = false;
	  break;
	}

      callee->is_tail = !is_call_instruction;
      callee->is_pasted = false;
      callee->broken_cycle = false;
      callee->priority = priority;
      callee->count = is_branch_reloc_type_flag ? 1 : 0;

      if (callee->fun->last_caller != sec)
	{
	  callee->fun->last_caller = sec;
	  callee->fun->call_count += 1;
	}

      if (!insert_callee (caller, callee))
	bfd_free (callee);
      else if (!is_call_instruction && !callee->fun->is_func && callee->fun->stack == 0)
	{
	  handle_function_start_merge (caller, callee->fun, sec, sym_sec);
	}
    }

  if (!info->keep_memory)
    bfd_free (internal_relocs);

  return success;
}

/* Handle something like .init or .fini, which has a piece of a function.
   These sections are pasted together to form a single function.  */

static bool
pasted_function (asection *sec)
{
  struct bfd_link_order *l;
  Elf_Internal_Sym *fake = NULL;
  struct function_info *fun = NULL;
  struct function_info *fun_start = NULL;
  struct call_info *callee = NULL;

  bool success = false;

  fake = bfd_zmalloc (sizeof (*fake));
  if (fake == NULL)
    goto cleanup;

  fake->st_value = 0;
  fake->st_size = sec->size;
  fake->st_shndx = _bfd_elf_section_from_bfd_section (sec->owner, sec);

  fun = maybe_insert_function (sec, fake, false, false);
  if (!fun)
    goto cleanup;

  bfd_free (fake);
  fake = NULL;

  for (l = sec->output_section->map_head.link_order; l != NULL; l = l->next)
    {
      if (l->u.indirect.section == sec)
	{
	  if (fun_start != NULL)
	    {
	      callee = bfd_malloc (sizeof *callee);
	      if (callee == NULL)
		goto cleanup;

	      fun->start = fun_start;
	      callee->fun = fun;
	      callee->is_tail = true;
	      callee->is_pasted = true;
	      callee->broken_cycle = false;
	      callee->priority = 0;
	      callee->count = 1;

	      if (!insert_callee (fun_start, callee))
		{
		  bfd_free (callee);
		  callee = NULL;
		}
	      success = true;
	      goto cleanup;
	    }
	  break;
	}

      if (l->type == bfd_indirect_link_order)
	{
	  struct _spu_elf_section_data *sec_data = spu_elf_section_data (l->u.indirect.section);
	  if (sec_data != NULL)
	    {
	      struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
	      if (sinfo != NULL && sinfo->num_fun != 0)
		{
		  fun_start = &sinfo->fun[sinfo->num_fun - 1];
		}
	    }
	}
    }

  success = true;

cleanup:
  if (fake != NULL)
    bfd_free (fake);

  return success;
}

/* Map address ranges in code sections to functions.  */

static Elf_Internal_Sym *sort_syms_syms;
static asection **sort_syms_psecs;

struct bfd_per_file_data {
  Elf_Internal_Sym **psyms;
  asection **psecs;
};

static bool
discover_functions (struct bfd_link_info *info)
{
  bfd *ibfd;
  int bfd_count = 0;
  struct bfd_per_file_data *all_bfd_data = NULL;
  bool overall_gaps_found = false;
  bool success_result = false;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    bfd_count++;

  if (bfd_count == 0)
    return true;

  all_bfd_data = bfd_zmalloc (bfd_count * sizeof (*all_bfd_data));
  if (all_bfd_data == NULL)
    goto cleanup;

  for (int i = 0; i < bfd_count; ++i)
    {
      all_bfd_data[i].psyms = NULL;
      all_bfd_data[i].psecs = NULL;
    }

  int current_bfd_idx = 0;
  for (ibfd = info->input_bfds;
       ibfd != NULL;
       ibfd = ibfd->link.next, current_bfd_idx++)
    {
      extern const bfd_target spu_elf32_vec;
      Elf_Internal_Shdr *symtab_hdr;
      size_t symcount_total;
      Elf_Internal_Sym *syms_full_list;
      Elf_Internal_Sym **current_psyms;
      asection **current_psecs;
      asection *sec;

      if (ibfd->xvec != &spu_elf32_vec)
	{
	  if (!overall_gaps_found)
	    for (sec = ibfd->sections; sec != NULL && !overall_gaps_found; sec = sec->next)
	      if (interesting_section (sec))
		{
		  overall_gaps_found = true;
		  break;
		}
	  continue;
	}

      symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
      symcount_total = symtab_hdr->sh_size / symtab_hdr->sh_entsize;

      if (symcount_total == 0)
	{
	  if (!overall_gaps_found)
	    for (sec = ibfd->sections; sec != NULL && !overall_gaps_found; sec = sec->next)
	      if (interesting_section (sec))
		{
		  overall_gaps_found = true;
		  break;
		}
	  continue;
	}

      if (symtab_hdr->contents != NULL)
        free (symtab_hdr->contents);
      symtab_hdr->contents = NULL;

      syms_full_list = bfd_elf_get_elf_syms (ibfd, symtab_hdr, symcount_total, 0,
                                             NULL, NULL, NULL);
      if (syms_full_list == NULL)
	goto cleanup;
      symtab_hdr->contents = (void *) syms_full_list;

      current_psyms = bfd_malloc ((symcount_total + 1) * sizeof (*current_psyms));
      if (current_psyms == NULL)
	goto cleanup;
      all_bfd_data[current_bfd_idx].psyms = current_psyms;

      current_psecs = bfd_malloc (symcount_total * sizeof (*current_psecs));
      if (current_psecs == NULL)
	goto cleanup;
      all_bfd_data[current_bfd_idx].psecs = current_psecs;

      Elf_Internal_Sym **psy_write_ptr = current_psyms;
      asection **p_write_ptr = current_psecs;

      for (Elf_Internal_Sym *sy_read_ptr = syms_full_list;
           sy_read_ptr < syms_full_list + symcount_total;
           ++sy_read_ptr)
	{
	  if (ELF_ST_TYPE (sy_read_ptr->st_info) == STT_NOTYPE
	      || ELF_ST_TYPE (sy_read_ptr->st_info) == STT_FUNC)
	    {
	      asection *s = bfd_section_from_elf_index (ibfd, sy_read_ptr->st_shndx);
	      if (s != NULL && interesting_section (s))
		{
		  *p_write_ptr++ = s;
		  *psy_write_ptr++ = sy_read_ptr;
		}
	    }
	}
      size_t symcount_filtered = psy_write_ptr - current_psyms;
      *psy_write_ptr = NULL;

      sort_syms_syms = syms_full_list;
      sort_syms_psecs = current_psecs;
      qsort (current_psyms, symcount_filtered, sizeof (*current_psyms), sort_syms);

      Elf_Internal_Sym **psy_iter = current_psyms;
      while (*psy_iter != NULL)
	{
	  asection *s = current_psecs[*psy_iter - syms_full_list];
	  Elf_Internal_Sym **psy_group_end = psy_iter;

	  while (*psy_group_end != NULL && current_psecs[*psy_group_end - syms_full_list] == s)
	    ++psy_group_end;

	  if (!alloc_stack_info (s, psy_group_end - psy_iter))
	    goto cleanup;
	  psy_iter = psy_group_end;
	}

      for (psy_iter = current_psyms; *psy_iter != NULL; ++psy_iter)
	{
	  Elf_Internal_Sym *sy = *psy_iter;
	  if (ELF_ST_TYPE (sy->st_info) == STT_FUNC)
	    {
	      asection *s = current_psecs[sy - syms_full_list];
	      if (!maybe_insert_function (s, sy, false, true))
		goto cleanup;
	    }
	}

      for (sec = ibfd->sections; sec != NULL && !overall_gaps_found; sec = sec->next)
	if (interesting_section (sec))
	  overall_gaps_found |= check_function_ranges (sec, info);
    }

  if (overall_gaps_found)
    {
      current_bfd_idx = 0;
      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next, current_bfd_idx++)
	{
	  if (all_bfd_data[current_bfd_idx].psyms == NULL)
	    continue;

	  for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
	    if (!mark_functions_via_relocs (sec, info, false))
	      goto cleanup;
	}

      current_bfd_idx = 0;
      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next, current_bfd_idx++)
	{
	  struct bfd_per_file_data *current_data = &all_bfd_data[current_bfd_idx];
	  Elf_Internal_Sym **psyms = current_data->psyms;
	  asection **psecs = current_data->psecs;
          Elf_Internal_Shdr *symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
          Elf_Internal_Sym *syms = (Elf_Internal_Sym *) symtab_hdr->contents;

	  if (psyms == NULL)
	    continue;

	  overall_gaps_found = false;
	  for (asection *sec = ibfd->sections; sec != NULL && !overall_gaps_found; sec = sec->next)
	    if (interesting_section (sec))
	      overall_gaps_found |= check_function_ranges (sec, info);

	  if (!overall_gaps_found)
	    continue;

	  for (Elf_Internal_Sym **psy_iter = psyms; *psy_iter != NULL; ++psy_iter)
	    {
	      Elf_Internal_Sym *sy = *psy_iter;
	      asection *s = psecs[sy - syms];

	      if (ELF_ST_TYPE (sy->st_info) != STT_FUNC
		  && ELF_ST_BIND (sy->st_info) == STB_GLOBAL)
		{
		  if (!maybe_insert_function (s, sy, false, false))
		    goto cleanup;
		}
	    }
	}

      if (overall_gaps_found)
      {
        for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
	  {
	    extern const bfd_target spu_elf32_vec;
	    if (ibfd->xvec != &spu_elf32_vec)
	      continue;

	    for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
	      if (interesting_section (sec))
		{
		  struct _spu_elf_section_data *sec_data;
		  struct spu_elf_stack_info *sinfo;

		  sec_data = spu_elf_section_data (sec);
		  sinfo = sec_data->u.i.stack_info;
		  if (sinfo != NULL && sinfo->num_fun != 0)
		    {
		      bfd_vma hi = sec->size;
		      for (int fun_idx = sinfo->num_fun; fun_idx-- > 0; )
			{
			  sinfo->fun[fun_idx].hi = hi;
			  hi = sinfo->fun[fun_idx].lo;
			}
		      sinfo->fun[0].lo = 0;
		    }
		  else if (!pasted_function (sec))
		    goto cleanup;
		}
	  }
      }
    }

  success_result = true;

cleanup:
  if (all_bfd_data != NULL)
    {
      for (int i = 0; i < bfd_count; ++i)
	{
	  if (all_bfd_data[i].psyms != NULL)
	    free (all_bfd_data[i].psyms);
	  if (all_bfd_data[i].psecs != NULL)
	    free (all_bfd_data[i].psecs);
	}
      free (all_bfd_data);
    }

  return success_result;
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
  bfd *ibfd;
  extern const bfd_target spu_elf32_vec;

  if (info == NULL || doit == NULL)
    {
      return false;
    }

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (ibfd->xvec != &spu_elf32_vec)
	{
	  continue;
	}

      for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  struct _spu_elf_section_data *sec_data;
	  struct spu_elf_stack_info *sinfo;

	  sec_data = spu_elf_section_data(sec);
	  if (sec_data == NULL)
	    {
	      continue;
	    }

	  sinfo = sec_data->u.i.stack_info;
	  if (sinfo == NULL)
	    {
	      continue;
	    }

	  for (int i = 0; i < sinfo->num_fun; ++i)
	    {
	      if (root_only && sinfo->fun[i].non_root)
		{
		  continue;
		}

	      if (!doit(&sinfo->fun[i], info, param))
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
  struct function_info *target_function = fun->start;

  if (target_function != NULL)
    {
      while (target_function->start != NULL)
	{
	  target_function = target_function->start;
	}

      struct call_info *current_call = fun->call_list;
      fun->call_list = NULL;

      while (current_call != NULL)
	{
	  struct call_info *next_call = current_call->next;

	  if (!insert_callee(target_function, current_call))
	    {
	      free(current_call);
	    }

	  current_call = next_call;
	}
    }
  return true;
}

/* Mark nodes in the call graph that are called by some other node.  */

#include <stdbool.h>

static bool mark_non_root_internal(struct function_info *fun);

static bool
mark_non_root_internal (struct function_info *fun)
{
  struct call_info *call;

  if (!fun)
    return false;

  if (fun->visit1)
    return true;
  fun->visit1 = true;
  for (call = fun->call_list; call; call = call->next)
    {
      if (!call->fun)
        return false;

      call->fun->non_root = true;
      if (!mark_non_root_internal (call->fun))
        return false;
    }
  return true;
}

static bool
mark_non_root (struct function_info *fun,
	       struct bfd_link_info *info ATTRIBUTE_UNUSED,
	       void *param ATTRIBUTE_UNUSED)
{
  return mark_non_root_internal(fun);
}

/* Remove cycles from the call graph.  Set depth of nodes.  */

static bool
remove_cycles (struct function_info *fun,
               struct bfd_link_info *info,
               unsigned int *current_depth_out)
{
  unsigned int current_depth = *current_depth_out;
  unsigned int max_depth_in_subtree = current_depth;

  fun->depth = current_depth;
  fun->visit2 = true;
  fun->marking = true;

  struct call_info *call_iterator = fun->call_list;
  while (call_iterator != NULL)
    {
      call_iterator->max_depth = current_depth + (call_iterator->is_pasted ? 0 : 1);

      if (!call_iterator->fun->visit2)
        {
          if (!remove_cycles (call_iterator->fun, info, &call_iterator->max_depth))
            {
              return false;
            }
          if (max_depth_in_subtree < call_iterator->max_depth)
            {
              max_depth_in_subtree = call_iterator->max_depth;
            }
        }
      else if (call_iterator->fun->marking)
        {
          struct spu_link_hash_table *htab = spu_hash_table (info);

          if (htab != NULL && htab->params != NULL)
            {
              if (!htab->params->auto_overlay && htab->params->stack_analysis)
                {
                  const char *f1 = func_name (fun);
                  const char *f2 = func_name (call_iterator->fun);

                  info->callbacks->info (_("stack analysis will ignore the call "
                                           "from %s to %s\n"),
                                         f1, f2);
                }
            }

          call_iterator->broken_cycle = true;
        }
      call_iterator = call_iterator->next;
    }

  fun->marking = false;
  *current_depth_out = max_depth_in_subtree;
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
  if (fun == NULL) {
    return false;
  }

  if (fun->visit2) {
    return true;
  }

  fun->non_root = false;

  unsigned int *param_ptr = (unsigned int *) param;
  if (param_ptr == NULL) {
    return false;
  }

  *param_ptr = 0;

  return remove_cycles (fun, info, param);
}

/* Populate call_list for each function.  */

static bool
build_call_tree (struct bfd_link_info *info)
{
  extern const bfd_target spu_elf32_vec;
  bfd *ibfd;
  unsigned int depth;

  if (info == NULL)
    return false;

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

  if (!spu_hash_table (info)->params->auto_overlay
      && !for_each_node (transfer_calls, info, 0, false))
    return false;

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
  const struct call_info *const *call_ptr1 = (const struct call_info *const *)a;
  const struct call_info *const *call_ptr2 = (const struct call_info *const *)b;

  const struct call_info *call1 = *call_ptr1;
  const struct call_info *call2 = *call_ptr2;

  if (call1->priority != call2->priority)
  {
    return call2->priority - call1->priority;
  }

  if (call1->max_depth != call2->max_depth)
  {
    return call2->max_depth - call1->max_depth;
  }

  if (call1->count != call2->count)
  {
    return call2->count - call1->count;
  }

  return (char *)call_ptr1 - (char *)call_ptr2;
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
get_rodata_section_name_alloc (const char *text_sec_name, char **name_out)
{
  *name_out = NULL;
  size_t text_len = strlen (text_sec_name);
  char *rodata_name = NULL;

  if (strcmp (text_sec_name, ".text") == 0)
    {
      rodata_name = bfd_malloc (sizeof (".rodata"));
      if (rodata_name == NULL) return false;
      memcpy (rodata_name, ".rodata", sizeof (".rodata"));
    }
  else if (startswith (text_sec_name, ".text."))
    {
      size_t suffix_len = text_len - strlen (".text.");
      rodata_name = bfd_malloc (strlen (".rodata.") + suffix_len + 1);
      if (rodata_name == NULL) return false;
      strcpy (rodata_name, ".rodata.");
      strcat (rodata_name, text_sec_name + strlen (".text."));
    }
  else if (startswith (text_sec_name, ".gnu.linkonce.t."))
    {
      rodata_name = bfd_malloc (text_len + 1);
      if (rodata_name == NULL) return false;
      memcpy (rodata_name, text_sec_name, text_len + 1);
      rodata_name[strlen (".gnu.linkonce.") + 1] = 'r';
    }
  *name_out = rodata_name;
  return true;
}

static asection *
find_associated_rodata_section (asection *text_sec, const char *rodata_name)
{
  asection *rodata = NULL;
  asection *group_sec_head = elf_section_data (text_sec)->next_in_group;

  if (group_sec_head == NULL)
    {
      rodata = bfd_get_section_by_name (text_sec->owner, rodata_name);
    }
  else
    {
      asection *current_sec_in_group = group_sec_head;
      while (current_sec_in_group != NULL)
        {
          if (strcmp (current_sec_in_group->name, rodata_name) == 0)
            {
              rodata = current_sec_in_group;
              break;
            }
          current_sec_in_group = elf_section_data (current_sec_in_group)->next_in_group;
        }
    }
  return rodata;
}

static bool
apply_rodata_marks (struct function_info *fun, struct spu_link_hash_table *htab,
		    unsigned int *current_size_ptr)
{
  char *rodata_name = NULL;
  if (!get_rodata_section_name_alloc (fun->sec->name, &rodata_name))
    return false;

  if (rodata_name == NULL)
    return true;

  asection *rodata = find_associated_rodata_section (fun->sec, rodata_name);
  free (rodata_name);

  fun->rodata = rodata;
  if (fun->rodata)
    {
      unsigned int new_size = *current_size_ptr + fun->rodata->size;
      if (htab->params->line_size != 0 && new_size > htab->params->line_size)
	{
	  fun->rodata = NULL;
	}
      else
	{
	  *current_size_ptr = new_size;
	  fun->rodata->linker_mark = 1;
	  fun->rodata->gc_mark = 1;
	  fun->rodata->flags &= ~SEC_CODE;
	}
    }
  return true;
}

static bool
should_mark_section_for_overlay (struct function_info *fun, struct spu_link_hash_table *htab)
{
  if (fun->sec->linker_mark)
    return false;

  return (htab->params->ovly_flavour != ovly_soft_icache
	  || htab->params->non_ia_text
	  || startswith (fun->sec->name, ".text.ia.")
	  || strcmp (fun->sec->name, ".init") == 0
	  || strcmp (fun->sec->name, ".fini") == 0);
}

static bool
sort_function_calls (struct function_info *fun)
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

  unsigned int i = 0;
  for (call = fun->call_list; call != NULL; call = call->next)
    calls[i++] = call;

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
should_unmark_section_for_entry_point (struct function_info *fun, struct bfd_link_info *info)
{
  if (fun->lo + fun->sec->output_offset + fun->sec->output_section->vma
      == info->output_bfd->start_address)
    return true;

  if (startswith (fun->sec->output_section->name, ".ovl.init"))
    return true;

  return false;
}

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

  if (should_mark_section_for_overlay (fun, htab))
    {
      unsigned int current_section_size;

      fun->sec->linker_mark = 1;
      fun->sec->gc_mark = 1;
      fun->sec->segment_mark = 0;
      fun->sec->flags |= SEC_CODE;

      current_section_size = fun->sec->size;
      if (htab->params->auto_overlay & OVERLAY_RODATA)
	{
	  if (!apply_rodata_marks (fun, htab, &current_section_size))
	    return false;
	}

      if (mos_param->max_overlay_size < current_section_size)
	mos_param->max_overlay_size = current_section_size;
    }

  if (!sort_function_calls (fun))
    return false;

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

  if (should_unmark_section_for_entry_point (fun, info))
    {
      fun->sec->linker_mark = 0;
      if (fun->rodata != NULL)
	fun->rodata->linker_mark = 0;
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

static bool
unmark_overlay_section (struct function_info *fun,
			struct bfd_link_info *info,
			void *param)
{
  struct call_info *call;
  struct _uos_param *uos_param = (struct _uos_param *) param;
  bool current_section_is_excluded;
  bool should_unmark_this_function;

  // If 'fun' is NULL, there's no function information to process.
  // This can happen if 'call->fun' is NULL during a recursive call.
  // Returning 'true' signifies that nothing needed to be unmarked for this null entry, and no error occurred.
  if (fun == NULL)
    return true;

  // If this function has already been visited in the current pass, skip it.
  if (fun->visit5)
    return true;

  fun->visit5 = true;

  // Essential null checks for dereferenced parameters and members.
  // If 'uos_param' or 'fun->sec' are NULL, we cannot safely proceed with the core logic.
  // This enhances reliability by preventing potential null pointer dereferences.
  // Returning 'false' signals an unrecoverable error for this processing branch.
  if (uos_param == NULL || fun->sec == NULL)
    return false;

  // Determine if the current function's section matches the excluded sections.
  current_section_is_excluded = (fun->sec == uos_param->exclude_input_section
                                 || fun->sec->output_section == uos_param->exclude_output_section);

  // If RECURSE_UNMARK is enabled, update the 'clearing' counter.
  // 'bool' values implicitly convert to 0 or 1 for arithmetic operations.
  if (RECURSE_UNMARK)
    uos_param->clearing += current_section_is_excluded;

  // Determine whether the 'linker_mark' for the current function should be cleared.
  // The logic is made explicit using if/else instead of a complex ternary operator.
  if (RECURSE_UNMARK)
    {
      // If recursion is active, unmark if any function in the current call path (including this one)
      // has been identified as an excluded section (clearing counter > 0).
      should_unmark_this_function = (uos_param->clearing > 0);
    }
  else
    {
      // If recursion is not active, unmark only if the current section itself is excluded.
      should_unmark_this_function = current_section_is_excluded;
    }

  // Apply the unmarking if determined necessary.
  if (should_unmark_this_function)
    {
      fun->sec->linker_mark = 0;
      // 'fun->rodata' is defensively checked before dereferencing.
      if (fun->rodata)
	fun->rodata->linker_mark = 0;
    }

  // Recursively process all functions called by the current function.
  for (call = fun->call_list; call != NULL; call = call->next)
    {
      // Prevent recursion into broken cycles and ensure 'call->fun' is valid.
      // The check 'call->fun != NULL' is crucial to prevent potential null pointer
      // dereferences in the recursive call, improving reliability.
      if (!call->broken_cycle && call->fun != NULL)
        {
          if (!unmark_overlay_section (call->fun, info, param))
            return false; // Propagate error from a recursive call.
        }
    }

  // If RECURSE_UNMARK is enabled, decrement the 'clearing' counter upon returning
  // from recursion, to correctly manage the exclusion scope.
  if (RECURSE_UNMARK)
    uos_param->clearing -= current_section_is_excluded;

  return true; // Indicate successful processing for this function and its subtree.
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
  struct _cl_param *lib_param = (struct _cl_param *)param;
  struct call_info *call;
  unsigned int size;

  if (fun->visit6)
  {
    return true;
  }

  fun->visit6 = true;

  if (!fun->sec->linker_mark || !fun->sec->gc_mark || fun->sec->segment_mark)
  {
    return true;
  }

  size = fun->sec->size;
  if (fun->rodata)
  {
    size += fun->rodata->size;
  }

  if (size <= lib_param->lib_size)
  {
    *lib_param->lib_sections++ = fun->sec;
    fun->sec->gc_mark = 0;

    if (fun->rodata && fun->rodata->linker_mark && fun->rodata->gc_mark)
    {
      *lib_param->lib_sections++ = fun->rodata;
      fun->rodata->gc_mark = 0;
    }
    else
    {
      *lib_param->lib_sections++ = NULL;
    }
  }

  for (call = fun->call_list; call != NULL; call = call->next)
  {
    if (!call->broken_cycle)
    {
      collect_lib_sections (call->fun, info, param);
    }
  }

  return true;
}

/* qsort predicate to sort sections by call count.  */

static int
calculate_section_call_count_sum(const asection *sec)
{
  if (sec == NULL) {
    return 0;
  }

  struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
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

static int
sort_lib (const void *a, const void *b)
{
  asection *const *s1_ptr = (asection *const *)a;
  asection *const *s2_ptr = (asection *const *)b;

  asection *s1 = *s1_ptr;
  asection *s2 = *s2_ptr;

  int s1_total_call_count = calculate_section_call_count_sum(s1);
  int s2_total_call_count = calculate_section_call_count_sum(s2);

  int delta = s2_total_call_count - s1_total_call_count;

  if (delta != 0) {
    return delta;
  }

  if (s1 < s2) {
    return -1;
  }
  if (s1 > s2) {
    return 1;
  }
  return 0;
}

/* Remove some sections from those marked to be in overlays.  Choose
   those that are called from many places, likely library functions.  */

static unsigned int
auto_ovl_lib_functions (struct bfd_link_info *info, unsigned int lib_size)
{
  bfd *ibfd;
  asection **lib_sections = NULL;
  unsigned int i, lib_count = 0;
  struct _cl_param collect_lib_param;
  struct function_info dummy_caller = { NULL };
  struct spu_link_hash_table *htab;
  unsigned int initial_lib_size = lib_size;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      extern const bfd_target spu_elf32_vec;
      asection *sec;

      if (ibfd->xvec != &spu_elf32_vec)
	continue;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	if (sec->linker_mark
	    && sec->size < lib_size
	    && (sec->flags & SEC_CODE) != 0)
	  lib_count++;
    }

  if (lib_count == 0)
    return lib_size;

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
  if (htab == NULL)
    {
      free (lib_sections);
      return (unsigned int) -1;
    }

  for (i = 0; i < lib_count; i++)
    {
      unsigned int current_section_total_size = 0;
      unsigned int stub_size_estimate = 0;
      asection *sec = lib_sections[2 * i];
      asection *rodata_sec = lib_sections[2 * i + 1];
      struct _spu_elf_section_data *sec_data;
      struct spu_elf_stack_info *sinfo;

      current_section_total_size = sec->size;
      if (rodata_sec)
	current_section_total_size += rodata_sec->size;

      if (current_section_total_size < lib_size)
	{
	  sec_data = spu_elf_section_data (sec);
	  if (sec_data != NULL)
	    sinfo = sec_data->u.i.stack_info;
	  else
	    sinfo = NULL;

	  if (sinfo != NULL)
	    {
	      int k;
	      for (k = 0; k < sinfo->num_fun; ++k)
		{
		  struct call_info *call;
		  for (call = sinfo->fun[k].call_list; call; call = call->next)
		    {
		      if (call->fun == NULL || call->fun->sec == NULL)
			continue;

		      if (call->fun->sec->linker_mark)
			{
			  struct call_info *p;
			  for (p = dummy_caller.call_list; p; p = p->next)
			    if (p->fun == call->fun)
			      break;
			  if (!p)
			    stub_size_estimate += ovl_stub_size (htab->params);
			}
		    }
		}
	    }
	}

      if (current_section_total_size + stub_size_estimate < lib_size)
	{
	  /* This section fits. Mark it as non-overlay.  */
	  sec->linker_mark = 0;
	  if (rodata_sec)
	    rodata_sec->linker_mark = 0;

	  lib_size -= current_section_total_size + stub_size_estimate;

	  /* Call stubs to the section we just added are no longer needed.  */
	  struct call_info **pp = &dummy_caller.call_list;
	  while (*pp != NULL)
	    {
	      struct call_info *current_call = *pp;
	      if (current_call->fun == NULL || current_call->fun->sec == NULL)
	        {
	          pp = &current_call->next;
	          continue;
	        }

	      if (!current_call->fun->sec->linker_mark)
		{
		  lib_size += ovl_stub_size (htab->params);
		  *pp = current_call->next;
		  free (current_call);
		}
	      else
		{
		  pp = &current_call->next;
		}
	    }

	  /* Add new call stubs to dummy_caller.  */
	  sec_data = spu_elf_section_data (sec);
	  if (sec_data != NULL)
	    sinfo = sec_data->u.i.stack_info;
	  else
	    sinfo = NULL;

	  if (sinfo != NULL)
	    {
	      int k;
	      for (k = 0; k < sinfo->num_fun; ++k)
		{
		  struct call_info *call;
		  for (call = sinfo->fun[k].call_list;
		       call;
		       call = call->next)
		    {
		      if (call->fun == NULL || call->fun->sec == NULL)
			continue;

		      if (call->fun->sec->linker_mark)
			{
			  struct call_info *new_callee = bfd_malloc (sizeof (*new_callee));
			  if (new_callee == NULL)
			    {
			      while (dummy_caller.call_list != NULL)
				{
				  struct call_info *tmp_call = dummy_caller.call_list;
				  dummy_caller.call_list = tmp_call->next;
				  free (tmp_call);
				}
			      free (lib_sections);
			      return (unsigned int) -1;
			    }
			  *new_callee = *call;
			  if (!insert_callee (&dummy_caller, new_callee))
			    free (new_callee);
			}
		    }
		}
	    }
	}
    }

  while (dummy_caller.call_list != NULL)
    {
      struct call_info *call = dummy_caller.call_list;
      dummy_caller.call_list = call->next;
      free (call);
    }

  for (i = 0; i < 2 * lib_count; i++)
    if (lib_sections[i] != NULL)
      lib_sections[i]->gc_mark = 1;

  free (lib_sections);
  return lib_size;
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
  bool added_fun = false;
  asection ***ovly_sections = (asection ***) param;

  if (fun->visit7)
    return true;

  fun->visit7 = true;

  for (call = fun->call_list; call != NULL; call = call->next)
    if (!call->is_pasted && !call->broken_cycle)
      {
	if (!collect_overlays (call->fun, info, ovly_sections))
	  return false;
	break;
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
	  struct function_info *current_fun_in_segment = fun;
	  do
	    {
	      struct call_info *found_pasted_call = NULL;
	      for (call = current_fun_in_segment->call_list; call != NULL; call = call->next)
		{
		  if (call->is_pasted)
		    {
		      found_pasted_call = call;
		      break;
		    }
		}

	      if (found_pasted_call == NULL)
		{
		  return false;
		}

	      current_fun_in_segment = found_pasted_call->fun;
	      current_fun_in_segment->sec->gc_mark = 0;
	      if (current_fun_in_segment->rodata)
		{
		  current_fun_in_segment->rodata->gc_mark = 0;
		}
	    }
	  while (current_fun_in_segment->sec->segment_mark);
	}
    }

  for (call = fun->call_list; call != NULL; call = call->next)
    if (!call->broken_cycle)
      {
	if (!collect_overlays (call->fun, info, ovly_sections))
	  return false;
      }

  if (added_fun)
    {
      struct _spu_elf_section_data *sec_data;
      struct spu_elf_stack_info *sinfo;

      sec_data = spu_elf_section_data (fun->sec);
      if (sec_data != NULL)
	{
	  sinfo = sec_data->u.i.stack_info;
	  if (sinfo != NULL)
	    {
	      int i;
	      for (i = 0; i < sinfo->num_fun; ++i)
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
  struct call_info *call;
  struct function_info *max_called_fun;
  size_t child_cumulative_stack_val;
  size_t current_cumulative_stack;
  size_t local_stack_usage;
  const char *fun_name_str;
  bool has_call_to_non_pasted_fun;
  struct _sum_stack_param *sum_stack_param = param;
  struct spu_link_hash_table *htab;

  local_stack_usage = fun->stack;
  current_cumulative_stack = local_stack_usage;

  if (fun->visit3)
    return true;

  has_call_to_non_pasted_fun = false;
  max_called_fun = NULL;
  for (call = fun->call_list; call; call = call->next)
    {
      if (call->broken_cycle)
	continue;
      if (!call->is_pasted)
	has_call_to_non_pasted_fun = true;

      if (!sum_stack (call->fun, info, sum_stack_param))
	return false;

      child_cumulative_stack_val = sum_stack_param->cum_stack;
      
      if (!call->is_tail || call->is_pasted || call->fun->start != NULL)
	child_cumulative_stack_val += local_stack_usage;

      if (current_cumulative_stack < child_cumulative_stack_val)
	{
	  current_cumulative_stack = child_cumulative_stack_val;
	  max_called_fun = call->fun;
	}
    }

  sum_stack_param->cum_stack = current_cumulative_stack;
  fun->stack = current_cumulative_stack;
  fun->visit3 = true;

  if (!fun->non_root
      && sum_stack_param->overall_stack < current_cumulative_stack)
    sum_stack_param->overall_stack = current_cumulative_stack;

  htab = spu_hash_table (info);
  if (htab->params->auto_overlay)
    return true;

  fun_name_str = func_name (fun);
  if (htab->params->stack_analysis)
    {
      if (!fun->non_root)
	info->callbacks->info ("  %s: 0x%v\n", fun_name_str, (bfd_vma) current_cumulative_stack);
      info->callbacks->minfo ("%s: 0x%v 0x%v\n",
			      fun_name_str, (bfd_vma) local_stack_usage, (bfd_vma) current_cumulative_stack);

      if (has_call_to_non_pasted_fun)
	{
	  info->callbacks->minfo (_("  calls:\n"));
	  for (call = fun->call_list; call; call = call->next)
	    if (!call->is_pasted && !call->broken_cycle)
	      {
		const char *f2 = func_name (call->fun);
		const char *ann1 = call->fun == max_called_fun ? "*" : " ";
		const char *ann2 = call->is_tail ? "t" : " ";

		info->callbacks->minfo ("   %s%s %s\n", ann1, ann2, f2);
	      }
	}
    }

  if (sum_stack_param->emit_stack_syms)
    {
      size_t name_buffer_size = 0;
      char *name = NULL;
      struct elf_link_hash_entry *h;

      name_buffer_size = 18 + strlen (fun_name_str);
      name = bfd_malloc (name_buffer_size);

      if (name == NULL)
	return false;

      if (fun->global || ELF_ST_BIND (fun->u.sym->st_info) == STB_GLOBAL)
	{
	  snprintf (name, name_buffer_size, "__stack_%s", fun_name_str);
	}
      else
	{
	  snprintf (name, name_buffer_size, "__stack_%x_%s", fun->sec->id & 0xffffffff, fun_name_str);
	}

      h = elf_link_hash_lookup (&htab->elf, name, true, true, false);
      free (name);
      if (h != NULL
	  && (h->root.type == bfd_link_hash_new
	      || h->root.type == bfd_link_hash_undefined
	      || h->root.type == bfd_link_hash_undefweak))
	{
	  h->root.type = bfd_link_hash_defined;
	  h->root.u.def.section = bfd_abs_section_ptr;
	  h->root.u.def.value = current_cumulative_stack;
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

static struct call_info *
find_pasted_call (asection *sec)
{
  if (sec == NULL)
    return NULL;

  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL)
    return NULL;

  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL)
    return NULL;

  for (int k = 0; k < sinfo->num_fun; ++k)
    {
      struct call_info *call;
      for (call = sinfo->fun[k].call_list; call != NULL; call = call->next)
        {
          if (call->is_pasted)
            return call;
        }
    }

  return NULL;
}

/* qsort predicate to sort bfds by file name.  */

static int
sort_bfds (const void *a, const void *b)
{
  bfd *const *abfd1 = (bfd *const *)a;
  bfd *const *abfd2 = (bfd *const *)b;

  bfd *bfd1 = *abfd1;
  bfd *bfd2 = *abfd2;

  if (bfd1 == NULL) {
    return (bfd2 == NULL) ? 0 : -1;
  }
  if (bfd2 == NULL) {
    return 1;
  }

  const char *filename1 = bfd_get_filename(bfd1);
  const char *filename2 = bfd_get_filename(bfd2);

  if (filename1 == NULL) {
    return (filename2 == NULL) ? 0 : -1;
  }
  if (filename2 == NULL) {
    return 1;
  }

  return filename_cmp(filename1, filename2);
}

static int
print_section_info (FILE *script, asection *sec, struct bfd_link_info *info)
{
  if (sec == NULL)
    return 0;

  const char *archive_file_name = "";
  if (sec->owner != NULL && sec->owner->my_archive != NULL)
    archive_file_name = bfd_get_filename (sec->owner->my_archive);

  if (fprintf (script, "   %s%c%s (%s)\n",
               archive_file_name,
               info->path_separator,
               bfd_get_filename (sec->owner),
               sec->name) <= 0)
    return -1;
  return 0;
}

typedef asection *(*section_selector_fn)(struct function_info *);

static asection *
select_func_sec (struct function_info *fun)
{
  return fun->sec;
}

static asection *
select_func_rodata (struct function_info *fun)
{
  return fun->rodata;
}

static int
print_pasted_calls (FILE *script,
                    asection *base_sec,
                    struct bfd_link_info *info,
                    section_selector_fn selector)
{
  if (!base_sec->segment_mark)
    return 0;

  struct call_info *call = find_pasted_call (base_sec);
  while (call != NULL)
    {
      struct function_info *call_fun = call->fun;
      asection *target_sec = selector(call_fun);
      if (print_section_info (script, target_sec, info) < 0)
        return -1;

      struct call_info *next_call_in_list = NULL;
      for (next_call_in_list = call_fun->call_list;
           next_call_in_list != NULL;
           next_call_in_list = next_call_in_list->next)
        {
          if (next_call_in_list->is_pasted)
            break;
        }
      call = next_call_in_list;
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
  for (j = base; j < count && ovly_map[j] == ovlynum; j++)
    {
      asection *sec_main = ovly_sections[2 * j];
      if (print_section_info (script, sec_main, info) < 0)
        return (unsigned int)-1;

      if (print_pasted_calls (script, sec_main, info, select_func_sec) < 0)
        return (unsigned int)-1;

      asection *sec_aux = ovly_sections[2 * j + 1];
      if (print_section_info (script, sec_aux, info) < 0)
        return (unsigned int)-1;

      if (print_pasted_calls (script, sec_main, info, select_func_rodata) < 0)
        return (unsigned int)-1;
    }

  return j;
}

/* Handle --auto-overlay.  */

static void
spu_elf_auto_overlay (struct bfd_link_info *info)
{
  unsigned int lo = (unsigned int) -1;
  unsigned int hi = 0;
  unsigned int fixed_size = 0;
  unsigned int reserved = 0;
  struct spu_link_hash_table *htab = spu_hash_table(info);
  struct _mos_param mos_param = { .max_overlay_size = 0 };
  struct _uos_param uos_param = { .exclude_input_section = NULL, .exclude_output_section = NULL, .clearing = 0 };

  bfd **bfd_arr = NULL;
  unsigned int bfd_arr_count = 0;
  asection **ovly_sections = NULL;
  unsigned int *ovly_map = NULL;
  FILE *script = NULL;

  unsigned int total_overlay_size = 0;
  unsigned int code_section_count = 0;
  unsigned int actual_overlay_section_count = 0;
  unsigned int final_ovlynum = 0;

  bool error_occurred = false;

  struct elf_segment_map *m;
  unsigned int i;

  for (m = elf_seg_map (info->output_bfd); m != NULL; m = m->next)
    if (m->p_type == PT_LOAD)
      for (i = 0; i < m->count; i++)
	if (m->sections[i]->size != 0)
	  {
	    if (m->sections[i]->vma < lo)
	      lo = m->sections[i]->vma;
	    if (m->sections[i]->vma + m->sections[i]->size - 1 > hi)
	      hi = m->sections[i]->vma + m->sections[i]->size - 1;
	  }
  fixed_size = hi + 1 - lo;

  if (!discover_functions (info)) {
    error_occurred = true;
    goto cleanup;
  }

  if (!build_call_tree (info)) {
    error_occurred = true;
    goto cleanup;
  }

  reserved = htab->params->auto_overlay_reserved;
  if (reserved == 0)
    {
      struct _sum_stack_param sum_stack_param;
      sum_stack_param.emit_stack_syms = 0;
      sum_stack_param.overall_stack = 0;
      if (!for_each_node (sum_stack, info, &sum_stack_param, true)) {
	error_occurred = true;
	goto cleanup;
      }
      reserved = (sum_stack_param.overall_stack + htab->params->extra_stack_space);
    }

  if (fixed_size + reserved <= htab->local_store && htab->params->ovly_flavour != ovly_soft_icache)
    {
      htab->params->auto_overlay = 0;
      return;
    }

  uos_param.exclude_input_section = NULL;
  uos_param.exclude_output_section = bfd_get_section_by_name (info->output_bfd, ".interrupt");

  const char *ovly_mgr_entry = "__ovly_load";
  if (htab->params->ovly_flavour == ovly_soft_icache)
    ovly_mgr_entry = "__icache_br_handler";
  struct elf_link_hash_entry *h = elf_link_hash_lookup (&htab->elf, ovly_mgr_entry,
							false, false, false);
  if (h != NULL && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) && h->def_regular)
    {
      uos_param.exclude_input_section = h->root.u.def.section;
    }
  else
    {
      fixed_size += (*htab->params->spu_elf_load_ovl_mgr) ();
    }

  if (!for_each_node (mark_overlay_section, info, &mos_param, true)) {
    error_occurred = true;
    goto cleanup;
  }

  uos_param.clearing = 0;
  if ((uos_param.exclude_input_section || uos_param.exclude_output_section)
      && !for_each_node (unmark_overlay_section, info, &uos_param, true)) {
    error_occurred = true;
    goto cleanup;
  }

  unsigned int current_bfd_count_for_alloc = 0;
  bfd *ibfd;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    ++current_bfd_count_for_alloc;

  bfd_arr = bfd_malloc (current_bfd_count_for_alloc * sizeof (*bfd_arr));
  if (bfd_arr == NULL) {
    bfd_set_error(bfd_error_no_memory);
    error_occurred = true;
    goto cleanup;
  }

  code_section_count = 0;
  bfd_arr_count = 0;
  total_overlay_size = 0;
  extern const bfd_target spu_elf32_vec;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      asection *sec;
      unsigned int old_code_section_count;

      if (ibfd->xvec != &spu_elf32_vec)
	continue;

      old_code_section_count = code_section_count;
      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	if (sec->linker_mark)
	  {
	    if ((sec->flags & SEC_CODE) != 0)
	      code_section_count += 1;
	    fixed_size -= sec->size;
	    total_overlay_size += sec->size;
	  }
	else if ((sec->flags & (SEC_ALLOC | SEC_LOAD)) == (SEC_ALLOC | SEC_LOAD)
		 && sec->output_section->owner == info->output_bfd
		 && startswith (sec->output_section->name, ".ovl.init"))
	  fixed_size -= sec->size;
      if (code_section_count != old_code_section_count)
	bfd_arr[bfd_arr_count++] = ibfd;
    }

  if (bfd_arr_count > 1)
    {
      bool duplicates_found = false;
      qsort (bfd_arr, bfd_arr_count, sizeof (*bfd_arr), sort_bfds);
      for (i = 1; i < bfd_arr_count; ++i)
	if (filename_cmp (bfd_get_filename (bfd_arr[i - 1]),
			  bfd_get_filename (bfd_arr[i])) == 0)
	  {
	    if (bfd_arr[i - 1]->my_archive == bfd_arr[i]->my_archive)
	      {
		if (bfd_arr[i - 1]->my_archive && bfd_arr[i]->my_archive)
		  info->callbacks->einfo (_("%s duplicated in %s\n"),
					  bfd_get_filename (bfd_arr[i]),
					  bfd_get_filename (bfd_arr[i]->my_archive));
		else
		  info->callbacks->einfo (_("%s duplicated\n"),
					  bfd_get_filename (bfd_arr[i]));
		duplicates_found = true;
	      }
	  }
      if (duplicates_found)
	{
	  info->callbacks->einfo (_("sorry, no support for duplicate "
				    "object files in auto-overlay script\n"));
	  bfd_set_error (bfd_error_bad_value);
	  error_occurred = true;
	  goto cleanup;
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
	  unsigned int ovlynum_guess = (total_overlay_size * 2 * htab->params->num_lines
				     / (htab->local_store - fixed_size));
	  fixed_size += ovlynum_guess * 16 + 16 + 4 + 16;
	}
    }

  if (fixed_size + mos_param.max_overlay_size > htab->local_store)
    {
      info->callbacks->einfo (_("non-overlay size of 0x%v plus maximum overlay "
			      "size of 0x%v exceeds local store\n"),
			    (bfd_vma) fixed_size,
			    (bfd_vma) mos_param.max_overlay_size);
      bfd_set_error (bfd_error_bad_value);
      error_occurred = true;
      goto cleanup;
    }
  else if (fixed_size < htab->params->auto_overlay_fixed)
    {
      unsigned int max_fixed, lib_size;
      max_fixed = htab->local_store - mos_param.max_overlay_size;
      if (max_fixed > htab->params->auto_overlay_fixed)
	max_fixed = htab->params->auto_overlay_fixed;
      lib_size = max_fixed - fixed_size;
      lib_size = auto_ovl_lib_functions (info, lib_size);
      if (lib_size == (unsigned int) -1) {
	error_occurred = true;
	goto cleanup;
      }
      fixed_size = max_fixed - lib_size;
    }

  ovly_sections = bfd_malloc (2 * code_section_count * sizeof (*ovly_sections));
  if (ovly_sections == NULL) {
    bfd_set_error(bfd_error_no_memory);
    error_occurred = true;
    goto cleanup;
  }
  asection **ovly_p = ovly_sections;
  if (!for_each_node (collect_overlays, info, &ovly_p, true)) {
    error_occurred = true;
    goto cleanup;
  }
  actual_overlay_section_count = (size_t) (ovly_p - ovly_sections) / 2;

  ovly_map = bfd_malloc (actual_overlay_section_count * sizeof (*ovly_map));
  if (ovly_map == NULL) {
    bfd_set_error(bfd_error_no_memory);
    error_occurred = true;
    goto cleanup;
  }

  struct function_info dummy_caller;
  memset (&dummy_caller, 0, sizeof (dummy_caller));
  unsigned int overlay_size_limit = (htab->local_store - fixed_size) / htab->params->num_lines;
  if (htab->params->line_size != 0)
    overlay_size_limit = htab->params->line_size;
  
  unsigned int base_idx = 0;
  final_ovlynum = 0;
  while (base_idx < actual_overlay_section_count)
    {
      unsigned int current_packed_size = 0, current_packed_rosize = 0, current_packed_roalign = 0;
      unsigned int current_overlay_end_idx;

      // Clear dummy_caller for the new overlay being packed
      while (dummy_caller.call_list != NULL)
	{
	  struct call_info *call = dummy_caller.call_list;
	  dummy_caller.call_list = call->next;
	  free (call);
	}

      for (current_overlay_end_idx = base_idx; current_overlay_end_idx < actual_overlay_section_count; current_overlay_end_idx++)
	{
	  asection *sec = ovly_sections[2 * current_overlay_end_idx];
	  asection *rosec = ovly_sections[2 * current_overlay_end_idx + 1];

	  unsigned int temp_size = align_power (current_packed_size, sec->alignment_power) + sec->size;
	  unsigned int temp_ro_size = current_packed_rosize;
	  unsigned int temp_ro_align = current_packed_roalign;

	  if (rosec != NULL)
	    {
	      temp_ro_size = align_power (temp_ro_size, rosec->alignment_power) + rosec->size;
	      if (temp_ro_align < rosec->alignment_power)
		temp_ro_align = rosec->alignment_power;
	    }
	  
	  if (align_power (temp_size, temp_ro_align) + temp_ro_size > overlay_size_limit)
	    break;

	  if (sec->segment_mark)
	    {
	      struct call_info *pasty_call_iter = find_pasted_call (sec);
	      while (pasty_call_iter != NULL)
		{
		  struct function_info *call_fun = pasty_call_iter->fun;
		  temp_size = (align_power (temp_size, call_fun->sec->alignment_power)
			       + call_fun->sec->size);
		  if (call_fun->rodata)
		    {
		      temp_ro_size = (align_power (temp_ro_size,
						    call_fun->rodata->alignment_power)
				       + call_fun->rodata->size);
		      if (temp_ro_align < call_fun->rodata->alignment_power)
			temp_ro_align = call_fun->rodata->alignment_power;
		    }
		  struct call_info *next_pasty = NULL;
		  for (struct call_info *call = call_fun->call_list; call; call = call->next)
		    if (call->is_pasted)
		      {
			next_pasty = call;
			break;
		      }
		  pasty_call_iter = next_pasty;
		}
	    }
	  if (align_power (temp_size, temp_ro_align) + temp_ro_size > overlay_size_limit)
	    break;
	  
	  // Add calls from this section to dummy_caller for stub calculation
	  struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
	  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
	  struct call_info *pasty_chain_start = NULL;

	  for (unsigned int k = 0; k < (unsigned)sinfo->num_fun; ++k)
	    for (struct call_info *call = sinfo->fun[k].call_list; call; call = call->next)
	      if (call->is_pasted)
		{
		  pasty_chain_start = call;
		}
	      else if (call->fun->sec->linker_mark)
		{
		  if (!copy_callee (&dummy_caller, call)) {
		    error_occurred = true;
		    goto cleanup;
		  }
		}
	  
	  struct call_info *current_pasty = pasty_chain_start;
	  while (current_pasty != NULL)
	    {
	      struct function_info *call_fun = current_pasty->fun;
	      struct call_info *next_pasty = NULL;
	      for (struct call_info *call = call_fun->call_list; call; call = call->next)
		if (call->is_pasted)
		  {
		    next_pasty = call;
		  }
		else if (!copy_callee (&dummy_caller, call)) {
		  error_occurred = true;
		  goto cleanup;
		}
	      current_pasty = next_pasty;
	    }

	  unsigned int num_stubs = 0;
	  for (struct call_info *call = dummy_caller.call_list; call; call = call->next)
	    {
	      unsigned int stub_delta = 1;
	      if (htab->params->ovly_flavour == ovly_soft_icache)
		stub_delta = call->count;
	      num_stubs += stub_delta;

	      for (unsigned int k = base_idx; k < current_overlay_end_idx + 1; k++)
		if (call->fun->sec == ovly_sections[2 * k])
		  {
		    num_stubs -= stub_delta;
		    break;
		  }
	    }
	  if (htab->params->ovly_flavour == ovly_soft_icache
	      && num_stubs > htab->params->max_branch)
	    break;
	  if (align_power (temp_size, temp_ro_align) + temp_ro_size
	      + num_stubs * ovl_stub_size (htab->params) > overlay_size_limit)
	    break;
	  current_packed_size = temp_size;
	  current_packed_rosize = temp_ro_size;
	  current_packed_roalign = temp_ro_align;
	}

      if (current_overlay_end_idx == base_idx)
	{
	  info->callbacks->einfo (_("%pB:%pA%s exceeds overlay size\n"),
				  ovly_sections[2 * base_idx]->owner,
				  ovly_sections[2 * base_idx],
				  ovly_sections[2 * base_idx + 1] ? " + rodata" : "");
	  bfd_set_error (bfd_error_bad_value);
	  error_occurred = true;
	  goto cleanup;
	}

      ++final_ovlynum;
      while (base_idx < current_overlay_end_idx)
	ovly_map[base_idx++] = final_ovlynum;
    }

  // Final cleanup of dummy_caller after the packing loop
  while (dummy_caller.call_list != NULL)
    {
      struct call_info *call = dummy_caller.call_list;
      dummy_caller.call_list = call->next;
      free (call);
    }

  script = htab->params->spu_elf_open_overlay_script ();
  if (script == NULL) {
      bfd_set_error(bfd_error_system_call);
      error_occurred = true;
      goto cleanup;
  }

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      if (fprintf (script, "SECTIONS\n{\n") <= 0) { error_occurred = true; goto cleanup; }

      if (fprintf (script,
		   " . = ALIGN (%u);\n"
		   " .ovl.init : { *(.ovl.init) }\n"
		   " . = ABSOLUTE (ADDR (.ovl.init));\n",
		   htab->params->line_size) <= 0) { error_occurred = true; goto cleanup; }

      unsigned int current_base = 0;
      unsigned int ovlynum_gen = 1;
      while (current_base < actual_overlay_section_count)
	{
	  unsigned int indx = ovlynum_gen - 1;
	  unsigned int vma, lma;

	  vma = (indx & (htab->params->num_lines - 1)) << htab->line_size_log2;
	  lma = vma + (((indx >> htab->num_lines_log2) + 1) << 18);

	  if (fprintf (script, " .ovly%u ABSOLUTE (ADDR (.ovl.init)) + %u "
			       ": AT (LOADADDR (.ovl.init) + %u) {\n",
		       ovlynum_gen, vma, lma) <= 0) { error_occurred = true; goto cleanup; }

	  unsigned int new_base = print_one_overlay_section (script, current_base, actual_overlay_section_count, ovlynum_gen,
							    ovly_map, ovly_sections, info);
	  if (new_base == (unsigned int) -1) { error_occurred = true; goto cleanup; }
	  current_base = new_base;

	  if (fprintf (script, "  }\n") <= 0) { error_occurred = true; goto cleanup; }

	  ovlynum_gen++;
	}

      if (fprintf (script, " . = ABSOLUTE (ADDR (.ovl.init)) + %u;\n",
		   1 << (htab->num_lines_log2 + htab->line_size_log2)) <= 0) { error_occurred = true; goto cleanup; }

      if (fprintf (script, "}\nINSERT AFTER .toe;\n") <= 0) { error_occurred = true; goto cleanup; }
    }
  else
    {
      if (fprintf (script, "SECTIONS\n{\n") <= 0) { error_occurred = true; goto cleanup; }

      if (fprintf (script,
		   " . = ALIGN (16);\n"
		   " .ovl.init : { *(.ovl.init) }\n"
		   " . = ABSOLUTE (ADDR (.ovl.init));\n") <= 0) { error_occurred = true; goto cleanup; }

      unsigned int region_gen;
      for (region_gen = 1; region_gen <= htab->params->num_lines; region_gen++)
	{
	  unsigned int ovlynum_gen = region_gen;
	  unsigned int current_base = 0;
	  while (current_base < actual_overlay_section_count && ovly_map[current_base] < ovlynum_gen)
	    current_base++;

	  if (current_base == actual_overlay_section_count)
	    break;

	  if (region_gen == 1)
	    {
	      if (fprintf (script,
			   " OVERLAY : AT (ALIGN (LOADADDR (.ovl.init) + SIZEOF (.ovl.init), 16))\n {\n") <= 0) { error_occurred = true; goto cleanup; }
	    }
	  else
	    {
	      if (fprintf (script, " OVERLAY :\n {\n") <= 0) { error_occurred = true; goto cleanup; }
	    }

	  while (current_base < actual_overlay_section_count)
	    {
	      if (fprintf (script, "  .ovly%u {\n", ovlynum_gen) <= 0) { error_occurred = true; goto cleanup; }

	      unsigned int new_base = print_one_overlay_section (script, current_base, actual_overlay_section_count, ovlynum_gen,
							    ovly_map, ovly_sections, info);
	      if (new_base == (unsigned int) -1) { error_occurred = true; goto cleanup; }
	      current_base = new_base;

	      if (fprintf (script, "  }\n") <= 0) { error_occurred = true; goto cleanup; }

	      ovlynum_gen += htab->params->num_lines;
	      while (current_base < actual_overlay_section_count && ovly_map[current_base] < ovlynum_gen)
		current_base++;
	    }

	  if (fprintf (script, " }\n") <= 0) { error_occurred = true; goto cleanup; }
	}

      if (fprintf (script, "}\nINSERT BEFORE .text;\n") <= 0) { error_occurred = true; goto cleanup; }
    }

cleanup:
  if (ovly_map) {
      free(ovly_map);
      ovly_map = NULL;
  }
  if (ovly_sections) {
      free(ovly_sections);
      ovly_sections = NULL;
  }
  if (script) {
      if (fclose(script) != 0 && !error_occurred) { // If fclose fails, set error unless already set
          bfd_set_error(bfd_error_system_call);
          error_occurred = true;
      }
      script = NULL;
  }

  if (error_occurred) {
      info->callbacks->fatal(_("%P: auto overlay error: %E\n"));
  } else {
      if (htab->params->auto_overlay & AUTO_RELINK) {
          (*htab->params->spu_elf_relink)();
      }
      xexit(0);
  }
}

/* Provide an estimate of total stack required.  */

static bool
spu_elf_stack_analysis (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab;
  struct _sum_stack_param sum_stack_param = {0};

  if (!discover_functions (info))
    return false;

  if (!build_call_tree (info))
    return false;

  htab = spu_hash_table (info);
  if (!htab || !htab->params)
    return false;

  if (htab->params->stack_analysis)
    {
      info->callbacks->info (_("Stack size for call graph root nodes.\n"));
      info->callbacks->minfo (_("\nStack size for functions.  "
				"Annotations: '*' max stack, 't' tail call\n"));
    }

  sum_stack_param.emit_stack_syms = htab->params->emit_stack_syms;

  if (!for_each_node (sum_stack, info, &sum_stack_param, true))
    return false;

  if (htab->params->stack_analysis)
    info->callbacks->info (_("Maximum stack required is 0x%v\n"),
			   (bfd_vma) sum_stack_param.overall_stack);
  return true;
}

/* Perform a final link.  */

static bool
spu_elf_final_link (bfd *output_bfd, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  struct spu_link_parameters *params = htab->params;

  if (params->auto_overlay)
    {
      spu_elf_auto_overlay (info);
    }

  bool requires_analysis = params->stack_analysis ||
                           (params->ovly_flavour == ovly_soft_icache &&
                            params->lrlive_analysis);

  if (requires_analysis && !spu_elf_stack_analysis (info))
    {
      info->callbacks->einfo (_("%X%P: stack/lrlive analysis error: %E\n"));
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
  if (relocs != NULL)
    {
      Elf_Internal_Rela *rel;
      const Elf_Internal_Rela *relend = relocs + sec->reloc_count;

      for (rel = relocs; rel < relend; rel++)
	{
	  int r_type = ELF32_R_TYPE (rel->r_info);
	  if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
	    ++count;
	}

      if (elf_section_data (sec)->relocs != relocs)
	free (relocs);
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
static const bfd_vma SPU_FIXUP_ALIGNMENT_BYTES = 16;
static const bfd_vma SPU_FIXUP_ALIGN_MASK = ~(SPU_FIXUP_ALIGNMENT_BYTES - 1);
static const bfd_vma SPU_FIXUP_INITIAL_BIT_VALUE = 8;
static const unsigned int SPU_FIXUP_OFFSET_TO_SHIFT_BITS = 2;

static void
spu_elf_emit_fixup (bfd * output_bfd, struct bfd_link_info *info,
		    bfd_vma offset)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (htab == NULL)
    {
      _bfd_error_handler (_("SPU ELF fixup: internal error, hash table is NULL."));
      return;
    }

  asection *sfixup = htab->sfixup;
  if (sfixup == NULL)
    {
      _bfd_error_handler (_("SPU ELF fixup: internal error, fixup section is NULL."));
      return;
    }

  bfd_vma current_aligned_addr = offset & SPU_FIXUP_ALIGN_MASK;
  bfd_vma bit_to_set = SPU_FIXUP_INITIAL_BIT_VALUE >> ((offset & (SPU_FIXUP_ALIGNMENT_BYTES - 1)) >> SPU_FIXUP_OFFSET_TO_SHIFT_BITS);

  bfd_vma fixup_value;
  int target_index;
  bool increment_reloc_count = false;

  if (sfixup->reloc_count == 0)
    {
      target_index = 0;
      fixup_value = current_aligned_addr | bit_to_set;
      increment_reloc_count = true;
    }
  else
    {
      bfd_vma previous_record_value = FIXUP_GET(output_bfd, htab, sfixup->reloc_count - 1);
      bfd_vma previous_aligned_addr = previous_record_value & SPU_FIXUP_ALIGN_MASK;

      if (current_aligned_addr != previous_aligned_addr)
        {
          if (((bfd_vma)sfixup->reloc_count + 1) * FIXUP_RECORD_SIZE > sfixup->size)
            {
              _bfd_error_handler (_("SPU ELF fixup: fatal error, .fixup section capacity exceeded."));
              return;
            }
          target_index = sfixup->reloc_count;
          fixup_value = current_aligned_addr | bit_to_set;
          increment_reloc_count = true;
        }
      else
        {
          target_index = sfixup->reloc_count - 1;
          fixup_value = previous_record_value | bit_to_set;
        }
    }

  FIXUP_PUT(output_bfd, htab, target_index, fixup_value);

  if (increment_reloc_count)
    {
      sfixup->reloc_count++;
    }
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
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes = (struct elf_link_hash_entry **) (elf_sym_hashes (input_bfd));
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection *ea_section = bfd_get_section_by_name (output_bfd, "._ea");

  bool needs_stubs = (htab->stub_sec != NULL && maybe_needs_stubs (input_section));
  unsigned int input_section_overlay_idx = overlay_index (input_section);

  int overall_result = true;
  bool emit_ppu_relocs = false;

  Elf_Internal_Rela *rel_ptr = relocs;
  Elf_Internal_Rela *rel_end = relocs + input_section->reloc_count;

  for (; rel_ptr < rel_end; rel_ptr++)
    {
      int r_type = ELF32_R_TYPE (rel_ptr->r_info);
      unsigned int r_symndx = ELF32_R_SYM (rel_ptr->r_info);
      reloc_howto_type *howto = elf_howto_table + r_type;

      Elf_Internal_Sym *sym = NULL;
      asection *sec = NULL;
      struct elf_link_hash_entry *h = NULL;
      const char *sym_name = NULL;
      bfd_vma relocation_value = 0;
      bfd_vma addend = rel_ptr->r_addend;
      bool unresolved_reloc = false;
      bool is_ea_symbol = false;

      // 1. Resolve symbol and determine initial relocation value.
      if (r_symndx < symtab_hdr->sh_info)
        {
          sym = local_syms + r_symndx;
          sec = local_sections[r_symndx];
          sym_name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym, sec);
          relocation_value = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel_ptr);
        }
      else
        {
          if (sym_hashes == NULL)
            {
              overall_result = false;
              break;
            }

          h = sym_hashes[r_symndx - symtab_hdr->sh_info];

          if (info->wrap_hash != NULL && (input_section->flags & SEC_DEBUGGING) != 0)
            h = ((struct elf_link_hash_entry *)
                 unwrap_hash_lookup (info, input_bfd, &h->root));

          while (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning)
            h = (struct elf_link_hash_entry *) h->root.u.i.link;

          if (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)
            {
              sec = h->root.u.def.section;
              if (sec == NULL || sec->output_section == NULL)
                unresolved_reloc = true;
              else
                relocation_value = (h->root.u.def.value
                                    + sec->output_section->vma
                                    + sec->output_offset);
            }
          else if (h->root.type == bfd_link_hash_undefweak)
            {
              // Handled by subsequent checks, relocation_value remains 0.
            }
          else if (info->unresolved_syms_in_objects == RM_IGNORE
                   && ELF_ST_VISIBILITY (h->other) == STV_DEFAULT)
            {
              // Handled by subsequent checks, relocation_value remains 0.
            }
          else if (!bfd_link_relocatable (info)
                   && !(r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64))
            {
              bool error_on_undefined = (info->unresolved_syms_in_objects == RM_DIAGNOSE
                                         && !info->warn_unresolved_syms)
                                        || ELF_ST_VISIBILITY (h->other) != STV_DEFAULT;
              info->callbacks->undefined_symbol
                (info, h->root.root.string, input_bfd,
                 input_section, rel_ptr->r_offset, error_on_undefined);
              unresolved_reloc = true;
            }
          sym_name = h->root.root.string;
        }

      // 2. Handle relocations against discarded sections.
      if (sec != NULL && discarded_section (sec))
        {
          RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
                                           rel_ptr, 1, rel_end, R_SPU_NONE,
                                           howto, 0, contents);
          continue;
        }

      // 3. Skip further processing for relocatable links.
      if (bfd_link_relocatable (info))
        continue;

      // 4. Specific SPU relocation adjustment for R_SPU_ADD_PIC.
      if (r_type == R_SPU_ADD_PIC && h != NULL && !(h->def_regular || ELF_COMMON_DEF_P (h)))
        {
          bfd_byte *loc = contents + rel_ptr->r_offset;
          loc[0] = 0x1c;
          loc[1] = 0x00;
          loc[2] &= 0x3f;
        }

      // 5. Determine if symbol is in the ._ea section.
      is_ea_symbol = (ea_section != NULL && sec != NULL && sec->output_section == ea_section);

      // 6. Handle overlay stubs.
      enum _stub_type stub_type = no_stub;
      if (needs_stubs && !is_ea_symbol)
        stub_type = needs_ovl_stub (h, sym, sec, input_section, rel_ptr, contents, info);

      if (stub_type != no_stub)
        {
          unsigned int ovl_idx_for_stub = (stub_type != nonovl_stub) ? input_section_overlay_idx : 0;
          struct got_entry *g, **head;

          if (h != NULL)
            head = &h->got.glist;
          else
            head = elf_local_got_ents (input_bfd) + r_symndx;

          for (g = *head; g != NULL; g = g->next)
            {
              if (htab->params->ovly_flavour == ovly_soft_icache)
                {
                  if (g->ovl == ovl_idx_for_stub
                      && g->br_addr == (rel_ptr->r_offset
                                        + input_section->output_offset
                                        + input_section->output_section->vma))
                    break;
                }
              else
                {
                  if (g->addend == addend && (g->ovl == ovl_idx_for_stub || g->ovl == 0))
                    break;
                }
            }
          if (g == NULL)
            abort (); // Should be guaranteed to find a stub if needs_ovl_stub returned non-no_stub.

          relocation_value = g->stub_addr;
          addend = 0;
        }
      else
        {
          // 7. For soft icache, encode the overlay index into addresses if no stub is used.
          if (htab->params->ovly_flavour == ovly_soft_icache
              && (r_type == R_SPU_ADDR16_HI || r_type == R_SPU_ADDR32 || r_type == R_SPU_REL32)
              && !is_ea_symbol)
            {
              unsigned int ovl_sec_idx = overlay_index (sec);
              if (ovl_sec_idx != 0)
                {
                  unsigned int set_id = ((ovl_sec_idx - 1) >> htab->num_lines_log2) + 1;
                  relocation_value += set_id << 18;
                }
            }
        }

      // 8. Emit fixups for R_SPU_ADDR32 if enabled.
      if (htab->params->emit_fixups
          && (input_section->flags & SEC_ALLOC) != 0
          && r_type == R_SPU_ADDR32)
        {
          bfd_vma offset_for_fixup = rel_ptr->r_offset
                                     + input_section->output_section->vma
                                     + input_section->output_offset;
          spu_elf_emit_fixup (output_bfd, info, offset_for_fixup);
        }

      // 9. Handle specific PPU relocations or mark as unresolved if in ._ea.
      if (unresolved_reloc)
        {
          // The unresolved flag is already set, will be handled after.
        }
      else if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
        {
          if (is_ea_symbol)
            {
              // Adjust relocation for ._ea section, relative to ELF image start.
              rel_ptr->r_addend += (relocation_value
                                    - ea_section->vma
                                    + elf_section_data (ea_section)->this_hdr.sh_offset);
              rel_ptr->r_info = ELF32_R_INFO (0, r_type); // Convert to section-relative.
            }
          emit_ppu_relocs = true;
          continue; // PPU relocations are not applied by _bfd_final_link_relocate here.
        }
      else if (is_ea_symbol)
        {
          // If a non-PPU relocation targets ._ea, it's considered unresolved in SPU context.
          unresolved_reloc = true;
        }

      // 10. Final check for unresolved relocations and report if necessary.
      if (unresolved_reloc)
        {
          if (_bfd_elf_section_offset (output_bfd, info, input_section,
                                       rel_ptr->r_offset) != (bfd_vma) -1)
            {
              _bfd_error_handler
                (_("%pB(%s+%#" PRIx64 "): "
                   "unresolvable %s relocation against symbol `%s'"),
                 input_bfd,
                 bfd_section_name (input_section),
                 (uint64_t) rel_ptr->r_offset,
                 howto->name,
                 sym_name);
              overall_result = false;
            }
        }

      // 11. Apply the relocation to the section contents.
      bfd_reloc_status_type reloc_status = _bfd_final_link_relocate (howto,
                                                                       input_bfd,
                                                                       input_section,
                                                                       contents,
                                                                       rel_ptr->r_offset,
                                                                       relocation_value,
                                                                       addend);

      // 12. Handle _bfd_final_link_relocate errors.
      if (reloc_status != bfd_reloc_ok)
        {
          const char *error_msg = NULL;
          bool is_fatal_error = true;

          switch (reloc_status)
            {
            case bfd_reloc_overflow:
              (*info->callbacks->reloc_overflow)
                (info, (h ? &h->root : NULL), sym_name, howto->name,
                 (bfd_vma) 0, input_bfd, input_section, rel_ptr->r_offset);
              is_fatal_error = false; // Overflow might not be immediately fatal.
              break;

            case bfd_reloc_undefined:
              (*info->callbacks->undefined_symbol)
                (info, sym_name, input_bfd, input_section, rel_ptr->r_offset, true);
              is_fatal_error = false; // Undefined symbol might not be immediately fatal.
              break;

            case bfd_reloc_outofrange:
              error_msg = _("internal error: out of range error");
              break;

            case bfd_reloc_notsupported:
              error_msg = _("internal error: unsupported relocation error");
              break;

            case bfd_reloc_dangerous:
              error_msg = _("internal error: dangerous error");
              break;

            default:
              error_msg = _("internal error: unknown error");
              break;
            }

          if (error_msg != NULL)
            {
              (*info->callbacks->warning) (info, error_msg, sym_name, input_bfd,
                                           input_section, rel_ptr->r_offset);
              if (is_fatal_error)
                  overall_result = false;
            }
          else if (is_fatal_error)
              overall_result = false;
        }
    } // End of main relocation loop

  // Post-loop processing: Handle PPU relocations that need to be emitted.
  if (overall_result && emit_ppu_relocs && !info->emitrelocations)
    {
      Elf_Internal_Rela *write_ptr = relocs;
      Elf_Internal_Rela *read_ptr = relocs;

      for (; read_ptr < rel_end; read_ptr++)
        {
          int r_type = ELF32_R_TYPE (read_ptr->r_info);
          if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
            *write_ptr++ = *read_ptr;
        }
      input_section->reloc_count = write_ptr - relocs;

      Elf_Internal_Shdr *rel_hdr = _bfd_elf_single_rel_hdr (input_section);
      if (rel_hdr != NULL)
        rel_hdr->sh_size = input_section->reloc_count * rel_hdr->sh_entsize;
      
      return 2; // Special return value indicating some relocations were emitted.
    }

  return overall_result;
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
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (htab == NULL || htab->stub_sec == NULL || htab->params == NULL)
    {
      return 1;
    }

  const bool is_relocatable = bfd_link_relocatable(info);
  const bool is_defined_or_weak = (h != NULL &&
                                   (h->root.type == bfd_link_hash_defined ||
                                    h->root.type == bfd_link_hash_defweak));
  const bool is_regular_def = (h != NULL && h->def_regular);
  const bool starts_with_spuear = (h != NULL &&
                                   h->root.root.string != NULL &&
                                   startswith(h->root.root.string, "_SPUEAR_"));

  if (!is_relocatable && is_defined_or_weak && is_regular_def && starts_with_spuear)
    {
      asection *output_sec = htab->stub_sec[0]->output_section;
      bfd *owner_bfd = output_sec->owner;
      unsigned int shndx = _bfd_elf_section_from_bfd_section(owner_bfd, output_sec);

      struct got_entry *g;
      for (g = h->got.glist; g != NULL; g = g->next)
        {
          bool condition_met = false;
          if (htab->params->ovly_flavour == ovly_soft_icache)
            {
              condition_met = (g->br_addr == g->stub_addr);
            }
          else
            {
              condition_met = (g->addend == 0 && g->ovl == 0);
            }

          if (condition_met)
            {
              sym->st_shndx = shndx;
              sym->st_value = g->stub_addr;
              break;
            }
        }
    }

  return 1;
}

static int spu_plugin = 0;

static int spu_plugin = 0;

void
spu_elf_plugin (int val)
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
  int extra_headers = 0;
  asection *sec;
  struct spu_link_hash_table *htab;

  if (info != NULL)
    {
      htab = spu_hash_table (info);
      if (htab != NULL)
        {
          extra_headers = htab->num_overlays;
          if (extra_headers > 0)
            extra_headers++;
        }
    }

  sec = bfd_get_section_by_name (abfd, ".toe");
  if (sec != NULL && (sec->flags & SEC_LOAD) != 0)
    {
      extra_headers++;
    }

  return extra_headers;
}

/* Remove .toe section from other PT_LOAD segments and put it in
   a segment of its own.  Put overlays in separate segments too.  */

static struct elf_segment_map *
alloc_segment_map_with_sections (bfd *abfd, bfd_size_type count, asection **sections)
{
  bfd_size_type alloc_size = sizeof (struct elf_segment_map);
  if (count > 0)
    alloc_size += (count - 1) * sizeof (sections[0]);

  struct elf_segment_map *map = bfd_zalloc (abfd, alloc_size);
  if (map == NULL)
    return NULL;

  map->count = count;
  map->p_type = PT_LOAD; /* All segments handled here are PT_LOAD. */
  if (count > 0 && sections != NULL)
    memcpy (map->sections, sections, count * sizeof (sections[0]));

  return map;
}

static bool
is_overlay_segment_candidate (struct elf_segment_map *map)
{
  /* An overlay segment is a PT_LOAD segment with a single section
     whose overlay index is non-zero.  */
  return map->p_type == PT_LOAD
         && map->count == 1
         && spu_elf_section_data (map->sections[0])->u.o.ovl_index != 0;
}

static bool
spu_elf_modify_segment_map (bfd *abfd, struct bfd_link_info *info)
{
  struct elf_segment_map **current_seg_ptr;
  asection *toe;
  unsigned int i;

  if (info == NULL)
    return true;

  toe = bfd_get_section_by_name (abfd, ".toe");

  /* First pass: Split PT_LOAD segments that contain .toe or overlay sections.  */
  current_seg_ptr = &elf_seg_map (abfd);
  while (*current_seg_ptr != NULL)
    {
      struct elf_segment_map *m_current = *current_seg_ptr;
      bool split_occurred = false;

      if (m_current->p_type == PT_LOAD && m_current->count > 1)
	{
	  for (i = 0; i < m_current->count; i++)
	    {
	      asection *s = m_current->sections[i];
	      if (s == toe || spu_elf_section_data (s)->u.o.ovl_index != 0)
		{
		  struct elf_segment_map *m_original_next = m_current->next;
		  struct elf_segment_map *m_single = NULL;
		  struct elf_segment_map *m_suffix = NULL;
		  struct elf_segment_map *last_new_segment = NULL;

		  /* Create suffix segment if sections[i+1...count-1] exist.  */
		  if (i + 1 < m_current->count)
		    {
		      bfd_size_type suffix_count = m_current->count - (i + 1);
		      m_suffix = alloc_segment_map_with_sections (abfd, suffix_count, m_current->sections + i + 1);
		      if (m_suffix == NULL)
			return false;
		      m_suffix->next = m_original_next;
		      last_new_segment = m_suffix;
		    }

		  /* Create a new segment for the single section 's'.  */
		  m_single = alloc_segment_map_with_sections (abfd, 1, &s);
		  if (m_single == NULL)
		    return false; /* If bfd_zalloc has a free mechanism, m_suffix should be freed here. */
		  m_single->next = (m_suffix != NULL) ? m_suffix : m_original_next;
		  if (last_new_segment == NULL)
		    last_new_segment = m_single;

		  /* Adjust m_current (prefix) or replace it if 's' was the first section.  */
		  if (i > 0)
		    {
		      /* m_current becomes the prefix segment.  */
		      m_current->count = i;
		      m_current->next = m_single;
		      /* current_seg_ptr still points to m_current, which is now the prefix.  */
		    }
		  else
		    {
		      /* i == 0, no prefix. Replace the original segment pointed to by *current_seg_ptr.  */
		      *current_seg_ptr = m_single;
		    }

		  split_occurred = true;
		  /* Advance the iterator for the outer loop to point to the segment *after* the newly inserted chain.  */
		  current_seg_ptr = &last_new_segment->next;
		  break; /* Only split on the first matching section within a segment.  */
		}
	    }
	}

      /* If no split occurred for m_current, advance current_seg_ptr normally.  */
      if (!split_occurred)
	{
	  current_seg_ptr = &m_current->next;
	}
    }

  /* Second pass: Move all overlay segments to the head of PT_LOAD segments.  */
  struct elf_segment_map *m_overlay_list = NULL;
  struct elf_segment_map **p_overlay_tail = &m_overlay_list;
  struct elf_segment_map **first_pt_load_ptr = NULL;

  current_seg_ptr = &elf_seg_map (abfd);
  while (*current_seg_ptr != NULL)
    {
      if ((*current_seg_ptr)->p_type == PT_LOAD)
	{
	  if (first_pt_load_ptr == NULL)
	    first_pt_load_ptr = current_seg_ptr;

	  if (is_overlay_segment_candidate (*current_seg_ptr))
	    {
	      struct elf_segment_map *m_ovl = *current_seg_ptr;
	      m_ovl->no_sort_lma = 1; /* Mark for later processing if needed.  */

	      /* Unlink from main list.  */
	      *current_seg_ptr = m_ovl->next;
	      /* Append to overlay list.  */
	      *p_overlay_tail = m_ovl;
	      p_overlay_tail = &m_ovl->next;
	      m_ovl->next = NULL; /* Ensure overlay list is properly terminated.  */
	      continue; /* Re-evaluate the segment now pointed to by current_seg_ptr.  */
	    }
	}
      /* Advance to the next segment in the main list.  */
      current_seg_ptr = &((*current_seg_ptr)->next);
    }

  /* Re-insert overlay segments at the head of the segment map, possibly after a filehdr segment.  */
  if (m_overlay_list != NULL)
    {
      struct elf_segment_map **insert_point = &elf_seg_map (abfd);
      if (first_pt_load_ptr != NULL)
	{
	  /* If the first PT_LOAD segment includes the ELF file header,
	     insert overlays after it.  */
	  if ((*first_pt_load_ptr)->p_type == PT_LOAD
	      && (*first_pt_load_ptr)->includes_filehdr)
	    {
	      insert_point = &(*first_pt_load_ptr)->next;
	    }
	  else
	    {
	      insert_point = first_pt_load_ptr;
	    }
	}

      /* Link the end of the overlay list to the segment at the insert point.  */
      *p_overlay_tail = *insert_point;
      /* Link the insert point to the beginning of the overlay list.  */
      *insert_point = m_overlay_list;
    }

  return true;
}

/* Tweak the section type of .note.spu_name.  */

static bool
spu_elf_fake_sections (bfd *obfd ATTRIBUTE_UNUSED,
                       Elf_Internal_Shdr *hdr,
                       asection *sec)
{
  if (hdr == NULL || sec == NULL || sec->name == NULL)
    {
      return false;
    }

  if (strcmp (sec->name, SPU_PTNOTE_SPUNAME) == 0)
    {
      hdr->sh_type = SHT_NOTE;
    }
  return true;
}

/* Tweak phdrs before writing them out.  */

static bool
handle_spu_overlays (bfd *abfd, struct spu_link_hash_table *htab,
                     Elf_Internal_Phdr *phdr, unsigned int phdr_count)
{
  struct elf_segment_map *m;
  unsigned int i;

  static const unsigned int SPU_OVLY_TABLE_ENTRY_SIZE = 16;
  static const unsigned int SPU_OVLY_TABLE_FILE_OFFSET_OFFSET = 8;
  static const unsigned int SPU_INIT_OVS_OFFSET = 4;
  static const unsigned int SPU_BFD_PUT_32_SIZE = 4;

  for (i = 0, m = elf_seg_map (abfd); m != NULL && i < phdr_count; ++i, m = m->next)
    {
      if (m->count == 0)
        continue;

      const struct spu_elf_section_data *sd = spu_elf_section_data (m->sections[0]);
      if (sd == NULL)
        {
          return false;
        }

      unsigned int ovl_index = sd->u.o.ovl_index;

      if (ovl_index == 0)
        continue;

      phdr[i].p_flags |= PF_OVERLAY;

      if (htab->ovtab != NULL && htab->params != NULL
          && htab->params->ovly_flavour != ovly_soft_icache)
        {
          unsigned int required_table_size = (ovl_index + 1) * SPU_OVLY_TABLE_ENTRY_SIZE;
          if (htab->ovtab->size < required_table_size)
            {
              return false;
            }

          bfd_byte *p = htab->ovtab->contents;
          unsigned int offset_in_table = ovl_index * SPU_OVLY_TABLE_ENTRY_SIZE + SPU_OVLY_TABLE_FILE_OFFSET_OFFSET;

          bfd_put_32 (htab->ovtab->owner, phdr[i].p_offset, p + offset_in_table);
        }
    }

  if (htab->init != NULL && htab->ovl_sec[0] != NULL)
    {
      if (htab->init->size < SPU_INIT_OVS_OFFSET + SPU_BFD_PUT_32_SIZE)
        {
          return false;
        }

      const struct elf_section_data *esd = elf_section_data (htab->ovl_sec[0]);
      if (esd == NULL)
        {
          return false;
        }

      bfd_vma val = esd->this_hdr.sh_offset;
      bfd_put_32 (htab->init->owner, val, htab->init->contents + SPU_INIT_OVS_OFFSET);
    }

  return true;
}

static bool
check_and_apply_load_segment_rounding (Elf_Internal_Phdr *phdr, unsigned int count)
{
  Elf_Internal_Phdr *last_load_segment = NULL;
  unsigned int i;

  static const unsigned int SPU_ALIGNMENT_FACTOR = 16;
  static const unsigned int SPU_ALIGNMENT_MASK = SPU_ALIGNMENT_FACTOR - 1;

  for (i = count; i-- != 0; )
    {
      if (phdr[i].p_type != PT_LOAD)
        {
          continue;
        }

      unsigned int file_adjust = (unsigned int) -phdr[i].p_filesz & SPU_ALIGNMENT_MASK;
      unsigned int mem_adjust = (unsigned int) -phdr[i].p_memsz & SPU_ALIGNMENT_MASK;

      if (file_adjust != 0 && last_load_segment != NULL)
        {
          if (phdr[i].p_offset + phdr[i].p_filesz + file_adjust > last_load_segment->p_offset)
            {
              return false;
            }
        }

      if (mem_adjust != 0 && last_load_segment != NULL && phdr[i].p_filesz != 0)
        {
          if (phdr[i].p_vaddr + phdr[i].p_memsz + mem_adjust > last_load_segment->p_vaddr
              && phdr[i].p_vaddr + phdr[i].p_memsz <= last_load_segment->p_vaddr)
            {
              return false;
            }
        }

      if (phdr[i].p_filesz != 0)
        {
          last_load_segment = &phdr[i];
        }
    }

  for (i = count; i-- != 0; )
    {
      if (phdr[i].p_type != PT_LOAD)
        {
          continue;
        }

      unsigned int file_adjust = (unsigned int) -phdr[i].p_filesz & SPU_ALIGNMENT_MASK;
      phdr[i].p_filesz += file_adjust;

      unsigned int mem_adjust = (unsigned int) -phdr[i].p_memsz & SPU_ALIGNMENT_MASK;
      phdr[i].p_memsz += mem_adjust;
    }

  return true;
}

static bool
spu_elf_modify_headers (bfd *abfd, struct bfd_link_info *info)
{
  if (abfd == NULL || info == NULL)
    {
      return _bfd_elf_modify_headers (abfd, info);
    }

  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  if (bed == NULL || bed->s == NULL || bed->s->sizeof_phdr == 0)
    {
      return _bfd_elf_modify_headers (abfd, info);
    }

  struct elf_obj_tdata *tdata = elf_tdata (abfd);
  if (tdata == NULL || tdata->phdr == NULL)
    {
      return _bfd_elf_modify_headers (abfd, info);
    }

  Elf_Internal_Phdr *phdr = tdata->phdr;
  unsigned int phdr_count = elf_program_header_size (abfd) / bed->s->sizeof_phdr;

  if (phdr_count == 0)
    {
      return _bfd_elf_modify_headers (abfd, info);
    }

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (htab == NULL)
    {
      return _bfd_elf_modify_headers (abfd, info);
    }

  if (htab->num_overlays != 0)
    {
      if (!handle_spu_overlays (abfd, htab, phdr, phdr_count))
        {
          return _bfd_elf_modify_headers (abfd, info);
        }
    }

  check_and_apply_load_segment_rounding (phdr, phdr_count);

  return _bfd_elf_modify_headers (abfd, info);
}

static bool should_process_section(asection *isec);
static bfd_vma calculate_next_quadword_boundary(bfd_vma current_offset);
static bool process_single_section_relocations(bfd *ibfd, asection *isec,
                                               struct bfd_link_info *info,
                                               int *fixup_count_ptr);

static bool
should_process_section(asection *isec)
{
  return (isec->flags & SEC_ALLOC)
         && (isec->flags & SEC_RELOC)
         && isec->reloc_count > 0;
}

static bfd_vma
calculate_next_quadword_boundary(bfd_vma current_offset)
{
  /* A quadword is 16 bytes. This calculation determines the start of
     the next 16-byte aligned block after the current_offset. */
  return (current_offset & ~(bfd_vma)15) + 16;
}

static bool
process_single_section_relocations(bfd *ibfd, asection *isec,
                                   struct bfd_link_info *info,
                                   int *fixup_count_ptr)
{
  Elf_Internal_Rela *internal_relocs;
  bfd_vma current_quadword_boundary = 0;
  Elf_Internal_Rela *irela_ptr;
  const Elf_Internal_Rela *irela_end;

  internal_relocs = _bfd_elf_link_read_relocs(ibfd, isec, NULL, NULL,
                                              info->keep_memory);
  if (internal_relocs == NULL)
    {
      /* _bfd_elf_link_read_relocs should set an error if it returns NULL. */
      return false;
    }

  irela_ptr = internal_relocs;
  irela_end = irela_ptr + isec->reloc_count;

  for (; irela_ptr < irela_end; ++irela_ptr)
    {
      if (ELF32_R_TYPE(irela_ptr->r_info) == R_SPU_ADDR32
          && irela_ptr->r_offset >= current_quadword_boundary)
        {
          current_quadword_boundary = calculate_next_quadword_boundary(irela_ptr->r_offset);
          (*fixup_count_ptr)++;
        }
    }
  return true;
}

bool
spu_elf_size_sections (bfd *obfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (!htab->params->emit_fixups)
    return true; /* No fixups to emit, nothing more to do. */

  asection *sfixup = htab->sfixup;
  int fixup_count = 0;

  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour)
        continue;

      for (asection *isec = ibfd->sections; isec != NULL; isec = isec->next)
        {
          if (!should_process_section(isec))
            continue;

          if (!process_single_section_relocations(ibfd, isec, info, &fixup_count))
            return false;
        }
    }

  /* A NULL fixup record is always added as a sentinel. */
  const size_t size = (fixup_count + 1) * FIXUP_RECORD_SIZE;

  if (!bfd_set_section_size (sfixup, size))
    return false;

  /* Allocate zero-initialized memory for the fixup section contents.
     Using info->input_bfds as the bfd for allocation is a common BFD pattern,
     tying the memory to the input BFD's memory pool. */
  sfixup->contents = (bfd_byte *) bfd_zalloc (info->input_bfds, size);
  if (sfixup->contents == NULL)
    {
      /* bfd_zalloc typically sets bfd_error_no_memory on failure. */
      return false;
    }

  sfixup->alloced = 1; /* Mark the section contents as allocated. */

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
