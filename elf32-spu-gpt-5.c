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
spu_elf_bfd_to_reloc_type(bfd_reloc_code_real_type code)
{
  static const struct {
    bfd_reloc_code_real_type code;
    enum elf_spu_reloc_type type;
  } map[] = {
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
  unsigned int i;
  for (i = 0; i < (unsigned int)(sizeof(map) / sizeof(map[0])); ++i)
    if (map[i].code == code)
      return map[i].type;
  return (enum elf_spu_reloc_type)-1;
}

static bool
spu_elf_info_to_howto(bfd *abfd, arelent *cache_ptr, Elf_Internal_Rela *dst)
{
  if (cache_ptr == NULL || dst == NULL)
    {
      bfd_set_error(bfd_error_bad_value);
      return false;
    }

  enum elf_spu_reloc_type r_type = (enum elf_spu_reloc_type) ELF32_R_TYPE(dst->r_info);
  if ((int) r_type < 0 || r_type >= R_SPU_max)
    {
      if (abfd != NULL)
        _bfd_error_handler(_("%pB: unsupported relocation type %#x"), abfd, (unsigned) r_type);
      bfd_set_error(bfd_error_bad_value);
      return false;
    }

  cache_ptr->howto = &elf_howto_table[(size_t) r_type];
  return true;
}

static reloc_howto_type *
spu_elf_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                           bfd_reloc_code_real_type code)
{
  int r_type = (int) spu_elf_bfd_to_reloc_type (code);
  size_t table_size = sizeof (elf_howto_table) / sizeof (elf_howto_table[0]);

  if (r_type < 0 || (size_t) r_type >= table_size)
    return NULL;

  return &elf_howto_table[r_type];
}

static reloc_howto_type *
spu_elf_reloc_name_lookup(bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  size_t i;
  const size_t count = sizeof(elf_howto_table) / sizeof(elf_howto_table[0]);

  if (r_name == NULL)
    return NULL;

  for (i = 0; i < count; ++i)
    {
      reloc_howto_type *entry = &elf_howto_table[i];
      const char *name = entry->name;

      if (name != NULL && strcasecmp(name, r_name) == 0)
        return entry;
    }

  return NULL;
}

/* Apply R_SPU_REL9 and R_SPU_REL9I relocs.  */

static bfd_reloc_status_type
spu_elf_rel9 (bfd *abfd, arelent *reloc_entry, asymbol *symbol,
              void *data, asection *input_section,
              bfd *output_bfd, char **error_message)
{
  bfd_size_type addr_octets;
  bfd_vma val;
  bfd_vma insn;
  bfd_byte *loc;
  const reloc_howto_type *howto;

  if (output_bfd != NULL)
    return bfd_elf_generic_reloc (abfd, reloc_entry, symbol, data,
                                  input_section, output_bfd, error_message);

  if (abfd == NULL || reloc_entry == NULL || symbol == NULL
      || data == NULL || input_section == NULL)
    return bfd_reloc_dangerous;

  howto = reloc_entry->howto;
  if (howto == NULL)
    return bfd_reloc_dangerous;

  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;

  addr_octets = reloc_entry->address * OCTETS_PER_BYTE (abfd, input_section);
  loc = (bfd_byte *) data + addr_octets;

  val = 0;
  if (!bfd_is_com_section (symbol->section))
    val = symbol->value;
  if (symbol->section->output_section != NULL)
    val += symbol->section->output_section->vma;

  val += reloc_entry->addend;

  if (input_section->output_section == NULL)
    return bfd_reloc_dangerous;

  val -= input_section->output_section->vma + input_section->output_offset;

  val >>= 2;
  if (val + 256 >= 512)
    return bfd_reloc_overflow;

  insn = bfd_get_32 (abfd, loc);

  val = (val & 0x7f) | ((val & 0x180) << 7) | ((val & 0x180) << 16);
  insn &= ~howto->dst_mask;
  insn |= val & howto->dst_mask;
  bfd_put_32 (abfd, insn, loc);

  return bfd_reloc_ok;
}

static bool
spu_elf_new_section_hook(bfd *abfd, asection *sec)
{
  if (abfd == NULL || sec == NULL)
    return false;

  struct _spu_elf_section_data *sdata = bfd_zalloc(abfd, sizeof(*sdata));
  if (sdata == NULL)
    return false;

  sec->used_by_bfd = sdata;
  return _bfd_elf_new_section_hook(abfd, sec);
}

/* Set up overlay info for executables.  */

static bool
spu_elf_object_p (bfd *abfd)
{
  if (abfd == NULL)
    return true;

  if ((abfd->flags & (EXEC_P | DYNAMIC)) == 0)
    return true;

  Elf_Internal_Ehdr *ehdr = elf_elfheader (abfd);
  if (ehdr == NULL)
    return true;

  unsigned int phnum = ehdr->e_phnum;
  Elf_Internal_Phdr *phdr_base = (elf_tdata (abfd) != NULL) ? elf_tdata (abfd)->phdr : NULL;
  if (phnum == 0 || phdr_base == NULL)
    return true;

  unsigned int num_sections = elf_numsections (abfd);
  Elf_Internal_Shdr **shdrs = elf_elfsections (abfd);
  if (shdrs == NULL || num_sections < 2)
    return true;

  unsigned int num_ovl = 0;
  unsigned int num_buf = 0;
  Elf_Internal_Phdr *last_phdr = NULL;

  for (unsigned int i = 0; i < phnum; i++)
    {
      Elf_Internal_Phdr *cur_phdr = &phdr_base[i];

      if (cur_phdr->p_type != PT_LOAD || (cur_phdr->p_flags & PF_OVERLAY) == 0)
        continue;

      ++num_ovl;

      if (last_phdr == NULL
          || ((last_phdr->p_vaddr ^ cur_phdr->p_vaddr) & 0x3ffff) != 0)
        ++num_buf;

      last_phdr = cur_phdr;

      for (unsigned int j = 1; j < num_sections; j++)
        {
          Elf_Internal_Shdr *shdr = shdrs[j];
          if (shdr == NULL
              || shdr->bfd_section == NULL
              || ELF_SECTION_SIZE (shdr, cur_phdr) == 0
              || !ELF_SECTION_IN_SEGMENT (shdr, cur_phdr))
            continue;

          asection *sec = shdr->bfd_section;
          struct spu_elf_section_data *sdata = spu_elf_section_data (sec);
          if (sdata != NULL)
            {
              sdata->u.o.ovl_index = num_ovl;
              sdata->u.o.ovl_buf = num_buf;
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

  const char *name = sym->name;
  if (name == NULL)
  {
    return;
  }

  if (sym->section == bfd_abs_section_ptr)
  {
    return;
  }

  const char *p = name;
  const char *prefix = "_EAR_";
  while (*prefix != '\0')
  {
    if (*p == '\0' || *p != *prefix)
    {
      return;
    }
    ++p;
    ++prefix;
  }

  sym->flags |= BSF_KEEP;
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
spu_elf_link_hash_table_create(bfd *abfd)
{
  struct spu_link_hash_table *htab = bfd_zmalloc(sizeof *htab);
  if (htab == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init(&htab->elf, abfd,
                                     _bfd_elf_link_hash_newfunc,
                                     sizeof(struct elf_link_hash_entry)))
  {
    free(htab);
    return NULL;
  }

  return &htab->elf.root;
}

void
spu_elf_setup(struct bfd_link_info *info, struct spu_elf_params *params)
{
  struct spu_link_hash_table *htab;
  unsigned int line_ln2 = 0U;
  unsigned int num_lines_ln2 = 0U;
  unsigned int max_branch_ln2 = 0U;
  unsigned int fromelem_ln2;

  if (info == NULL || params == NULL)
    return;

  htab = spu_hash_table(info);
  if (htab == NULL)
    return;

  htab->params = params;

  if (htab->params->line_size != 0)
    line_ln2 = bfd_log2(htab->params->line_size);

  if (htab->params->num_lines != 0)
    num_lines_ln2 = bfd_log2(htab->params->num_lines);

  if (htab->params->max_branch != 0)
    max_branch_ln2 = bfd_log2(htab->params->max_branch);

  htab->line_size_log2 = line_ln2;
  htab->num_lines_log2 = num_lines_ln2;

  fromelem_ln2 = (max_branch_ln2 > 4U) ? (max_branch_ln2 - 4U) : 0U;
  htab->fromelem_size_log2 = fromelem_ln2;
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
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  struct elf_link_hash_entry *h;
  Elf_Internal_Sym *sym;
  Elf_Internal_Sym *locsyms;
  asection *symsec;

  if (hp != NULL)
    *hp = NULL;
  if (symp != NULL)
    *symp = NULL;
  if (symsecp != NULL)
    *symsecp = NULL;

  if (ibfd == NULL || elf_tdata (ibfd) == NULL)
    return false;

  symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;

  if (r_symndx >= symtab_hdr->sh_info)
    {
      unsigned long idx;

      sym_hashes = elf_sym_hashes (ibfd);
      if (sym_hashes == NULL)
        return false;

      idx = r_symndx - symtab_hdr->sh_info;
      h = sym_hashes[idx];
      if (h == NULL)
        return false;

      while (h->root.type == bfd_link_hash_indirect
             || h->root.type == bfd_link_hash_warning)
        h = (struct elf_link_hash_entry *) h->root.u.i.link;

      if (hp != NULL)
        *hp = h;

      if (symsecp != NULL)
        {
          symsec = NULL;
          if (h->root.type == bfd_link_hash_defined
              || h->root.type == bfd_link_hash_defweak)
            symsec = h->root.u.def.section;
          *symsecp = symsec;
        }
    }
  else
    {
      locsyms = (locsymsp != NULL) ? *locsymsp : NULL;

      if (locsyms == NULL)
        {
          locsyms = (Elf_Internal_Sym *) symtab_hdr->contents;
          if (locsyms == NULL)
            {
              locsyms = bfd_elf_get_elf_syms (ibfd, symtab_hdr,
                                              symtab_hdr->sh_info,
                                              0, NULL, NULL, NULL);
              if (locsyms == NULL)
                return false;
            }
          if (locsymsp != NULL)
            *locsymsp = locsyms;
        }

      sym = locsyms + r_symndx;

      if (symp != NULL)
        *symp = sym;

      if (symsecp != NULL)
        *symsecp = bfd_section_from_elf_index (ibfd, sym->st_shndx);
    }

  return true;
}

/* Create the note section if not already present.  This is done early so
   that the linker maps the sections to the right place in the output.  */

static inline size_t align_up_size(size_t value, size_t alignment)
{
  if (alignment == 0)
    return value;
  size_t mask = alignment - 1;
  return (value + mask) & ~mask;
}

bool
spu_elf_create_sections (struct bfd_link_info *info)
{
  const size_t NOTE_ALIGN = 4;
  const size_t NOTE_HDR_SIZE = 12;
  const size_t FIXUP_ALIGN = 2;

  if (info == NULL)
    return false;

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (htab == NULL)
    return false;

  bfd *ibfd;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (bfd_get_section_by_name (ibfd, SPU_PTNOTE_SPUNAME) != NULL)
        break;
    }

  if (ibfd == NULL)
    {
      asection *s;
      size_t name_len;
      size_t size;
      bfd_byte *data;
      flagword flags;
      const char *out_name;

      ibfd = info->input_bfds;
      if (ibfd == NULL || info->output_bfd == NULL)
        return false;

      flags = SEC_LOAD | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
      s = bfd_make_section_anyway_with_flags (ibfd, SPU_PTNOTE_SPUNAME, flags);
      if (s == NULL || !bfd_set_section_alignment (s, NOTE_ALIGN))
        return false;

      elf_section_type (s) = SHT_NOTE;

      out_name = bfd_get_filename (info->output_bfd);
      if (out_name == NULL)
        return false;

      name_len = strlen (out_name) + 1;

      size = NOTE_HDR_SIZE
             + align_up_size (sizeof (SPU_PLUGIN_NAME), NOTE_ALIGN)
             + align_up_size (name_len, NOTE_ALIGN);

      if (!bfd_set_section_size (s, size))
        return false;

      data = bfd_zalloc (ibfd, size);
      if (data == NULL)
        return false;

      bfd_put_32 (ibfd, sizeof (SPU_PLUGIN_NAME), data + 0);
      bfd_put_32 (ibfd, name_len, data + 4);
      bfd_put_32 (ibfd, 1, data + 8);

      memcpy (data + NOTE_HDR_SIZE, SPU_PLUGIN_NAME, sizeof (SPU_PLUGIN_NAME));

      memcpy (data + NOTE_HDR_SIZE
                      + align_up_size (sizeof (SPU_PLUGIN_NAME), NOTE_ALIGN),
              out_name, name_len);

      s->contents = data;
      s->alloced = 1;
    }

  if (htab->params != NULL && htab->params->emit_fixups)
    {
      asection *s;
      flagword flags;

      if (htab->elf.dynobj == NULL)
        htab->elf.dynobj = ibfd;

      ibfd = htab->elf.dynobj;
      if (ibfd == NULL)
        return false;

      flags = (SEC_LOAD | SEC_ALLOC | SEC_READONLY | SEC_HAS_CONTENTS
               | SEC_IN_MEMORY | SEC_LINKER_CREATED);
      s = bfd_make_section_anyway_with_flags (ibfd, ".fixup", flags);
      if (s == NULL || !bfd_set_section_alignment (s, FIXUP_ALIGN))
        return false;
      htab->sfixup = s;
    }

  return true;
}

/* qsort predicate to sort sections by vma.  */

static int
sort_sections(const void *a, const void *b)
{
  if (a == b)
    return 0;
  if (a == NULL)
    return -1;
  if (b == NULL)
    return 1;

  const asection *const s1 = *(const asection *const *)a;
  const asection *const s2 = *(const asection *const *)b;

  if (s1 == s2)
    return 0;
  if (s1 == NULL)
    return -1;
  if (s2 == NULL)
    return 1;

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

int
spu_elf_find_overlays (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab;
  asection **alloc_sec;
  unsigned int i, n, ovl_index, num_buf;
  asection *s;
  bfd_vma ovl_end;
  static const char *const entry_names[2][2] = {
    { "__ovly_load", "__icache_br_handler" },
    { "__ovly_return", "__icache_call_handler" }
  };

  if (info == NULL || info->output_bfd == NULL)
    {
      bfd_set_error (bfd_error_bad_value);
      return 0;
    }

  htab = spu_hash_table (info);
  if (htab == NULL || htab->params == NULL)
    {
      bfd_set_error (bfd_error_bad_value);
      return 0;
    }

  if (info->output_bfd->section_count < 2)
    return 1;

  alloc_sec = bfd_malloc (info->output_bfd->section_count * sizeof (*alloc_sec));
  if (alloc_sec == NULL)
    return 0;

  n = 0;
  for (s = info->output_bfd->sections; s != NULL; s = s->next)
    if ((s->flags & SEC_ALLOC) != 0
        && (s->flags & (SEC_LOAD | SEC_THREAD_LOCAL)) != SEC_THREAD_LOCAL
        && s->size != 0)
      alloc_sec[n++] = s;

  if (n == 0)
    {
      free (alloc_sec);
      return 1;
    }

  qsort (alloc_sec, n, sizeof (*alloc_sec), sort_sections);

  ovl_end = alloc_sec[0]->vma + alloc_sec[0]->size;

  ovl_index = 0;
  num_buf = 0;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      unsigned int prev_buf = 0, set_id = 0;
      bfd_vma vma_start = 0;

      for (i = 1; i < n; i++)
        {
          asection *s1 = alloc_sec[i];
          if (s1->vma < ovl_end)
            {
              asection *s0 = alloc_sec[i - 1];
              vma_start = s0->vma;
              ovl_end = s0->vma
                        + ((bfd_vma) 1
                           << (htab->num_lines_log2 + htab->line_size_log2));
              --i;
              break;
            }
          else
            ovl_end = s1->vma + s1->size;
        }

      for (; i < n; i++)
        {
          s = alloc_sec[i];
          if (s->vma >= ovl_end)
            break;

          if (!startswith (s->name, ".ovl.init"))
            {
              num_buf = ((s->vma - vma_start) >> htab->line_size_log2) + 1;
              set_id = (num_buf == prev_buf) ? set_id + 1 : 0;
              prev_buf = num_buf;

              if ((s->vma - vma_start) & (htab->params->line_size - 1))
                {
                  info->callbacks->einfo (_("%X%P: overlay section %pA "
                                            "does not start on a cache line\n"),
                                          s);
                  bfd_set_error (bfd_error_bad_value);
                  free (alloc_sec);
                  return 0;
                }
              else if (s->size > htab->params->line_size)
                {
                  info->callbacks->einfo (_("%X%P: overlay section %pA "
                                            "is larger than a cache line\n"),
                                          s);
                  bfd_set_error (bfd_error_bad_value);
                  free (alloc_sec);
                  return 0;
                }

              alloc_sec[ovl_index++] = s;
              spu_elf_section_data (s)->u.o.ovl_index
                = (set_id << htab->num_lines_log2) + num_buf;
              spu_elf_section_data (s)->u.o.ovl_buf = num_buf;
            }
        }

      for (; i < n; i++)
        {
          s = alloc_sec[i];
          if (s->vma < ovl_end)
            {
              info->callbacks->einfo (_("%X%P: overlay section %pA "
                                        "is not in cache area\n"),
                                      alloc_sec[i - 1]);
              bfd_set_error (bfd_error_bad_value);
              free (alloc_sec);
              return 0;
            }
          else
            ovl_end = s->vma + s->size;
        }
    }
  else
    {
      for (i = 1; i < n; i++)
        {
          s = alloc_sec[i];
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
                      info->callbacks->einfo (_("%X%P: overlay sections %pA "
                                                "and %pA do not start at the "
                                                "same address\n"),
                                              s0, s);
                      bfd_set_error (bfd_error_bad_value);
                      free (alloc_sec);
                      return 0;
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
  htab->ovl_sec = alloc_sec;

  if (ovl_index == 0)
    return 1;

  for (i = 0; i < 2; i++)
    {
      const char *name;
      struct elf_link_hash_entry *h;
      unsigned int flavour = htab->params->ovly_flavour;

      if (flavour > 1)
        {
          bfd_set_error (bfd_error_bad_value);
          return 0;
        }

      name = entry_names[i][flavour];
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

static bool
is_branch (const unsigned char *insn)
{
  if (insn == NULL)
    return false;

  const unsigned char mask0 = 0xec;
  const unsigned char value0 = 0x20;

  if ((insn[0] & mask0) != value0)
    return false;

  const unsigned char mask1 = 0x80;

  return (insn[1] & mask1) == 0;
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

static bool
is_indirect_branch(const unsigned char *insn)
{
  if (insn == NULL) {
    return false;
  }

  const unsigned char opcode_mask = 0xEFu;
  const unsigned char opcode_value = 0x25u;
  const unsigned char modrm_mask = 0x80u;

  const unsigned char opcode = (unsigned char)(insn[0] & opcode_mask);
  const unsigned char modrm = (unsigned char)(insn[1] & modrm_mask);

  return (opcode == opcode_value) && (modrm == 0u);
}

/* Return true for branch hint instructions.
   hbra  0001000..
   hbrr  0001001..  */

static bool
is_hint(const unsigned char *insn)
{
    if (insn == NULL) {
        return false;
    }
    const unsigned int MASK = 0xFCu;
    const unsigned int VALUE = 0x10u;
    return (((unsigned int)insn[0]) & MASK) == VALUE;
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

  if (input_section->name != NULL && strcmp (input_section->name, ".eh_frame") == 0)
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
  enum _stub_type ret = no_stub;
  enum elf_spu_reloc_type r_type;
  unsigned int sym_type;
  bool branch = false;
  bool hint = false;
  bool call = false;
  bfd_byte insn[4];
  const bfd_byte *pc = NULL;

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

  sym_type = (h != NULL) ? h->type : ELF_ST_TYPE (sym->st_info);

  r_type = ELF32_R_TYPE (irela->r_info);
  if (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16)
    {
      if (contents == NULL)
        {
          if (input_section == NULL || input_section->owner == NULL)
            return stub_error;

          if (irela->r_offset + 4 < irela->r_offset
              || irela->r_offset + 4 > input_section->size)
            return stub_error;

          if (!bfd_get_section_contents (input_section->owner,
                                         input_section,
                                         insn,
                                         irela->r_offset, 4))
            return stub_error;
          pc = insn;
        }
      else
        {
          if (input_section != NULL)
            {
              if (irela->r_offset + 4 < irela->r_offset
                  || irela->r_offset + 4 > input_section->size)
                return stub_error;
            }
          pc = contents + irela->r_offset;
        }

      branch = is_branch (pc);
      hint = is_hint (pc);
      if (branch || hint)
        {
          call = (pc[0] & 0xfd) == 0x31;
          if (call && sym_type != STT_FUNC && contents != NULL)
            {
              const char *sym_name;

              if (h != NULL)
                sym_name = h->root.root.string;
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
      || (sym_type != STT_FUNC && !(branch || hint) && (sym_sec->flags & SEC_CODE) == 0))
    return no_stub;

  if (spu_elf_section_data (sym_sec->output_section)->u.o.ovl_index == 0
      && !htab->params->non_overlay_stubs)
    return ret;

  if (spu_elf_section_data (sym_sec->output_section)->u.o.ovl_index
      != spu_elf_section_data (input_section->output_section)->u.o.ovl_index)
    {
      unsigned int lrlive = 0;

      if (branch && pc != NULL)
        lrlive = (pc[1] & 0x70) >> 4;

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
  struct got_entry *g = NULL, **head;
  bfd_vma addend = 0;

  if (stub_type != nonovl_stub)
    {
      if (isec == NULL || isec->output_section == NULL)
        return false;
      ovl = spu_elf_section_data (isec->output_section)->u.o.ovl_index;
    }

  if (h != NULL)
    {
      head = &h->got.glist;
    }
  else
    {
      if (ibfd == NULL || irela == NULL)
        return false;

      if (elf_local_got_ents (ibfd) == NULL)
        {
          bfd_size_type count = elf_tdata (ibfd)->symtab_hdr.sh_info;
          bfd_size_type elem_size = sizeof (*elf_local_got_ents (ibfd));
          if (elem_size != 0 && count > (bfd_size_type)(~(bfd_size_type) 0) / elem_size)
            return false;

          bfd_size_type amt = count * elem_size;
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
          struct got_entry *prev = NULL;
          struct got_entry *node = *head;

          while (node != NULL)
            {
              struct got_entry *next = node->next;

              if (node->addend == addend)
                {
                  if (prev == NULL)
                    *head = next;
                  else
                    prev->next = next;

                  htab->stub_count[node->ovl] -= 1;
                  free (node);
                }
              else
                {
                  prev = node;
                }

              node = next;
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
      g = bfd_malloc (sizeof *g);
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

#include <limits.h>

static unsigned int
ovl_stub_size(struct spu_elf_params *params)
{
  if (params == NULL)
    return 0u;

  const unsigned int width = (unsigned int)(sizeof(unsigned int) * CHAR_BIT);
  const unsigned int left = (unsigned int)params->ovly_flavour;
  const unsigned int right = (unsigned int)params->compact_stub;

  if (left >= width || right >= width)
    return 0u;

  unsigned int value = 16u;
  value <<= left;
  value >>= right;

  return value;
}

static unsigned int ovl_stub_size_log2(struct spu_elf_params *params)
{
    unsigned int ovly;
    unsigned int compact;

    if (params == NULL) {
        return 0u;
    }

    ovly = (unsigned int)params->ovly_flavour;
    compact = (unsigned int)params->compact_stub;

    return 4u + ovly - compact;
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
  unsigned int ovl = 0, dest_ovl, set_id;
  struct got_entry *g, **head;
  asection *sec;
  bfd_vma addend = 0, from, to, br_dest, patt;
  unsigned int lrlive;
  size_t pos;
  bfd *owner;
  bfd_byte *buf;

  if (htab == NULL || htab->params == NULL || isec == NULL || dest_sec == NULL || isec->output_section == NULL || dest_sec->output_section == NULL)
    return false;

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
      {
        struct got_entry **local = elf_local_got_ents (ibfd);
        if (local == NULL)
          return false;
        head = local + ELF32_R_SYM (irela->r_info);
      }
    }

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
        {
          htab->stub_err = 1;
          return false;
        }

      if (g->ovl == 0 && ovl != 0)
        return true;

      if (g->stub_addr != (bfd_vma) -1)
        return true;
    }

  sec = htab->stub_sec[ovl];
  if (sec == NULL || sec->output_section == NULL || sec->owner == NULL || sec->contents == NULL)
    {
      htab->stub_err = 1;
      return false;
    }
  owner = sec->owner;
  buf = sec->contents;
  pos = sec->size;

  if (htab->ovly_entry[0] == NULL
      || htab->ovly_entry[0]->root.u.def.section == NULL
      || htab->ovly_entry[0]->root.u.def.section->output_section == NULL)
    {
      htab->stub_err = 1;
      return false;
    }

  dest += dest_sec->output_offset + dest_sec->output_section->vma;
  from = pos + sec->output_offset + sec->output_section->vma;
  g->stub_addr = from;
  to = (htab->ovly_entry[0]->root.u.def.value
        + htab->ovly_entry[0]->root.u.def.section->output_offset
        + htab->ovly_entry[0]->root.u.def.section->output_section->vma);

  if (((dest | to | from) & 3U) != 0)
    {
      htab->stub_err = 1;
      return false;
    }
  dest_ovl = spu_elf_section_data (dest_sec->output_section)->u.o.ovl_index;

  if (htab->params->ovly_flavour == ovly_normal
      && !htab->params->compact_stub)
    {
      bfd_put_32 (owner, ILA + ((dest_ovl << 7) & 0x01ffff80) + 78, buf + pos);
      bfd_put_32 (owner, LNOP, buf + pos + 4);
      bfd_put_32 (owner, ILA + ((dest << 7) & 0x01ffff80) + 79, buf + pos + 8);
      if (!BRA_STUBS)
        bfd_put_32 (owner, BR + (((to - (from + 12)) << 5) & 0x007fff80), buf + pos + 12);
      else
        bfd_put_32 (owner, BRA + ((to << 5) & 0x007fff80), buf + pos + 12);
    }
  else if (htab->params->ovly_flavour == ovly_normal
           && htab->params->compact_stub)
    {
      if (!BRA_STUBS)
        bfd_put_32 (owner, BRSL + (((to - from) << 5) & 0x007fff80) + 75, buf + pos);
      else
        bfd_put_32 (owner, BRASL + ((to << 5) & 0x007fff80) + 75, buf + pos);
      bfd_put_32 (owner, (dest & 0x3ffff) | (dest_ovl << 18), buf + pos + 4);
    }
  else if (htab->params->ovly_flavour == ovly_soft_icache
           && htab->params->compact_stub)
    {
      lrlive = 0;
      if (stub_type == nonovl_stub)
        ;
      else if (stub_type == call_ovl_stub)
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

      if (ovl == 0)
        {
          if (htab->ovly_entry[1] == NULL
              || htab->ovly_entry[1]->root.u.def.section == NULL
              || htab->ovly_entry[1]->root.u.def.section->output_section == NULL)
            {
              htab->stub_err = 1;
              return false;
            }
          to = (htab->ovly_entry[1]->root.u.def.value
                + htab->ovly_entry[1]->root.u.def.section->output_offset
                + htab->ovly_entry[1]->root.u.def.section->output_section->vma);
        }

      g->stub_addr += 4;
      br_dest = g->stub_addr;
      if (irela == NULL)
        {
          BFD_ASSERT (stub_type == nonovl_stub);
          g->br_addr = g->stub_addr;
          br_dest = to;
        }

      set_id = ((dest_ovl - 1) >> htab->num_lines_log2) + 1;
      bfd_put_32 (owner, (set_id << 18) | (dest & 0x3ffff), buf + pos);
      bfd_put_32 (owner, BRASL + ((to << 5) & 0x007fff80) + 75, buf + pos + 4);
      bfd_put_32 (owner, (lrlive << 29) | (g->br_addr & 0x3ffff), buf + pos + 8);
      patt = dest ^ br_dest;
      if (irela != NULL && ELF32_R_TYPE (irela->r_info) == R_SPU_REL16)
        patt = (dest - g->br_addr) ^ (br_dest - g->br_addr);
      bfd_put_32 (owner, (patt << 5) & 0x007fff80, buf + pos + 12);

      if (ovl == 0)
        sec->size += 16;
    }
  else
    {
      htab->stub_err = 1;
      return false;
    }

  sec->size += ovl_stub_size (htab->params);

  if (htab->params->emit_stub_syms)
    {
      size_t len;
      char *name;
      int add;
      size_t used, rem;

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

      used = 0;
      rem = len + 1;

      {
        int n = snprintf (name + used, rem, "%08x.ovl_call.", g->ovl);
        if (n < 0 || (size_t) n >= rem) { free (name); return false; }
        used += (size_t) n; rem -= (size_t) n;
      }

      if (h != NULL)
        {
          size_t hlen = strlen (h->root.root.string);
          if (hlen + 1 > rem) { free (name); return false; }
          memcpy (name + used, h->root.root.string, hlen + 1);
          used += hlen; rem -= hlen;
        }
      else
        {
          int n = snprintf (name + used, rem, "%x:%x",
                            dest_sec->id & 0xffffffff,
                            (int) ELF32_R_SYM (irela->r_info) & 0xffffffff);
          if (n < 0 || (size_t) n >= rem) { free (name); return false; }
          used += (size_t) n; rem -= (size_t) n;
        }

      if (add != 0)
        {
          int n = snprintf (name + used, rem, "+%x", add);
          if (n < 0 || (size_t) n >= rem) { free (name); return false; }
          used += (size_t) n; rem -= (size_t) n;
        }

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
    }

  return true;
}

/* Called via elf_link_hash_traverse to allocate stubs for any _SPUEAR_
   symbols.  */

static bool
allocate_spuear_stubs(struct elf_link_hash_entry *h, void *inf)
{
  if (h == NULL || inf == NULL)
    return true;

  struct bfd_link_info *info = inf;
  struct spu_link_hash_table *htab = spu_hash_table(info);
  if (htab == NULL || htab->params == NULL)
    return true;

  if (!(h->root.type == bfd_link_hash_defined
        || h->root.type == bfd_link_hash_defweak))
    return true;

  if (!h->def_regular)
    return true;

  const char *name = h->root.root.string;
  if (name == NULL || !startswith(name, "_SPUEAR_"))
    return true;

  asection *sym_sec = h->root.u.def.section;
  if (sym_sec == NULL)
    return true;

  if (sym_sec->output_section == bfd_abs_section_ptr)
    return true;

  struct spu_elf_section_data *secdata = spu_elf_section_data(sym_sec->output_section);
  if (secdata == NULL)
    return true;

  if (secdata->u.o.ovl_index == 0 && !htab->params->non_overlay_stubs)
    return true;

  return count_stub(htab, NULL, NULL, nonovl_stub, h, NULL);
}

static bool
build_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info = (struct bfd_link_info *) inf;
  struct spu_link_hash_table *htab;
  asection *sym_sec;
  asection *outsec;
  const char *name;
  struct spu_elf_section_data *secdata;

  if (h == NULL || info == NULL)
    return true;

  if (!(h->root.type == bfd_link_hash_defined
        || h->root.type == bfd_link_hash_defweak))
    return true;

  if (!h->def_regular)
    return true;

  name = h->root.root.string;
  if (name == NULL || !startswith (name, "_SPUEAR_"))
    return true;

  sym_sec = h->root.u.def.section;
  if (sym_sec == NULL)
    return true;

  outsec = sym_sec->output_section;
  if (outsec == NULL || outsec == bfd_abs_section_ptr)
    return true;

  secdata = spu_elf_section_data (outsec);
  if (secdata == NULL)
    return true;

  htab = spu_hash_table (info);
  if (secdata->u.o.ovl_index == 0)
    {
      if (htab == NULL || htab->params == NULL || !htab->params->non_overlay_stubs)
        return true;
    }

  return build_stub (info, NULL, NULL, nonovl_stub, h, NULL,
                     h->root.u.def.value, sym_sec);
}

/* Size or build stubs.  */

static bool
process_section_stubs (struct bfd_link_info *info,
                       bool build,
                       struct spu_link_hash_table *htab,
                       bfd *ibfd,
                       Elf_Internal_Shdr *symtab_hdr,
                       asection *isec,
                       Elf_Internal_Sym **local_syms_ptr)
{
  Elf_Internal_Rela *internal_relocs, *irelaend, *irela;

  if ((isec->flags & SEC_RELOC) == 0 || isec->reloc_count == 0)
    return true;

  if (!maybe_needs_stubs (isec))
    return true;

  internal_relocs = _bfd_elf_link_read_relocs (ibfd, isec, NULL, NULL,
                                               info->keep_memory);
  if (internal_relocs == NULL)
    return false;

  irela = internal_relocs;
  irelaend = irela + isec->reloc_count;

  for (; irela < irelaend; irela++)
    {
      enum elf_spu_reloc_type r_type = ELF32_R_TYPE (irela->r_info);
      unsigned int r_indx = ELF32_R_SYM (irela->r_info);
      asection *sym_sec;
      Elf_Internal_Sym *sym;
      struct elf_link_hash_entry *h;
      enum _stub_type stub_type;

      if (r_type >= R_SPU_max)
        {
          bfd_set_error (bfd_error_bad_value);
          if (elf_section_data (isec)->relocs != internal_relocs)
            free (internal_relocs);
          return false;
        }

      if (!get_sym_h (&h, &sym, &sym_sec, local_syms_ptr, r_indx, ibfd))
        {
          if (elf_section_data (isec)->relocs != internal_relocs)
            free (internal_relocs);
          return false;
        }

      stub_type = needs_ovl_stub (h, sym, sym_sec, isec, irela, NULL, info);
      if (stub_type == no_stub)
        continue;
      if (stub_type == stub_error)
        {
          if (elf_section_data (isec)->relocs != internal_relocs)
            free (internal_relocs);
          return false;
        }

      if (htab->stub_count == NULL)
        {
          bfd_size_type amt = (htab->num_overlays + 1) * sizeof (*htab->stub_count);
          htab->stub_count = bfd_zmalloc (amt);
          if (htab->stub_count == NULL)
            {
              if (elf_section_data (isec)->relocs != internal_relocs)
                free (internal_relocs);
              return false;
            }
        }

      if (!build)
        {
          if (!count_stub (htab, ibfd, isec, stub_type, h, irela))
            {
              if (elf_section_data (isec)->relocs != internal_relocs)
                free (internal_relocs);
              return false;
            }
        }
      else
        {
          bfd_vma dest = (h != NULL) ? h->root.u.def.value : sym->st_value;
          dest += irela->r_addend;

          if (!build_stub (info, ibfd, isec, stub_type, h, irela, dest, sym_sec))
            {
              if (elf_section_data (isec)->relocs != internal_relocs)
                free (internal_relocs);
              return false;
            }
        }
    }

  if (elf_section_data (isec)->relocs != internal_relocs)
    free (internal_relocs);

  return true;
}

static bool
process_stubs (struct bfd_link_info *info, bool build)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      extern const bfd_target spu_elf32_vec;
      Elf_Internal_Shdr *symtab_hdr;
      asection *isec;
      Elf_Internal_Sym *local_syms = NULL;

      if (ibfd->xvec != &spu_elf32_vec)
        continue;

      symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
      if (symtab_hdr->sh_info == 0)
        continue;

      for (isec = ibfd->sections; isec != NULL; isec = isec->next)
        {
          if (!process_section_stubs (info, build, htab, ibfd, symtab_hdr, isec, &local_syms))
            {
              if (symtab_hdr->contents != (unsigned char *) local_syms)
                free (local_syms);
              return false;
            }
        }

      if (local_syms != NULL
          && symtab_hdr->contents != (unsigned char *) local_syms)
        {
          if (!info->keep_memory)
            free (local_syms);
          else
            symtab_hdr->contents = (unsigned char *) local_syms;
        }
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
  flagword flags;
  unsigned int i;
  asection *stub;
  unsigned int stub_align_log2;
  bfd_size_type stub_unit_size;
  bfd_boolean is_soft_icache;

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

  is_soft_icache = (htab->params->ovly_flavour == ovly_soft_icache);
  stub_align_log2 = ovl_stub_size_log2 (htab->params);
  stub_unit_size = ovl_stub_size (htab->params);

  if (htab->stub_count != NULL)
    {
      bfd_size_type amt = (htab->num_overlays + 1) * sizeof (*htab->stub_sec);
      htab->stub_sec = bfd_zmalloc (amt);
      if (htab->stub_sec == NULL)
        return 0;

      flags = SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY;

      stub = bfd_make_section_anyway_with_flags (ibfd, ".stub", flags);
      htab->stub_sec[0] = stub;
      if (stub == NULL || !bfd_set_section_alignment (stub, stub_align_log2))
        return 0;

      stub->size = htab->stub_count[0] * stub_unit_size;
      if (is_soft_icache)
        stub->size += htab->stub_count[0] * 16;

      for (i = 0; i < htab->num_overlays; ++i)
        {
          asection *osec = htab->ovl_sec[i];
          unsigned int ovl = spu_elf_section_data (osec)->u.o.ovl_index;

          stub = bfd_make_section_anyway_with_flags (ibfd, ".stub", flags);
          htab->stub_sec[ovl] = stub;
          if (stub == NULL || !bfd_set_section_alignment (stub, stub_align_log2))
            return 0;

          stub->size = htab->stub_count[ovl] * stub_unit_size;
        }
    }

  if (is_soft_icache)
    {
      flags = SEC_ALLOC;
      htab->ovtab = bfd_make_section_anyway_with_flags (ibfd, ".ovtab", flags);
      if (htab->ovtab == NULL || !bfd_set_section_alignment (htab->ovtab, 4))
        return 0;

      htab->ovtab->size = (16 + 16 + (16 << htab->fromelem_size_log2)) << htab->num_lines_log2;

      flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
      htab->init = bfd_make_section_anyway_with_flags (ibfd, ".ovini", flags);
      if (htab->init == NULL || !bfd_set_section_alignment (htab->init, 4))
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
      if (htab->ovtab == NULL || !bfd_set_section_alignment (htab->ovtab, 4))
        return 0;

      htab->ovtab->size = htab->num_overlays * 16 + 16 + htab->num_buf * 4;
    }

  htab->toe = bfd_make_section_anyway_with_flags (ibfd, ".toe", SEC_ALLOC);
  if (htab->toe == NULL || !bfd_set_section_alignment (htab->toe, 4))
    return 0;

  htab->toe->size = 16;

  return 2;
}

/* Called from ld to place overlay manager data sections.  This is done
   after the overlay manager itself is loaded, mainly so that the
   linker's htab->init section is placed after any other .ovl.init
   sections.  */

void
spu_elf_place_overlay_data(struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table(info);
  unsigned int i;

  if (htab == NULL || htab->params == NULL || htab->params->place_spu_section == NULL)
    return;

  {
    void (*place)(asection *, asection *, const char *) = htab->params->place_spu_section;
    int flavour = htab->params->ovly_flavour;

    if (htab->stub_sec != NULL)
      {
        if (htab->stub_sec[0] != NULL)
          place(htab->stub_sec[0], NULL, ".text");

        if (htab->ovl_sec != NULL)
          {
            for (i = 0; i < htab->num_overlays; ++i)
              {
                asection *osec = htab->ovl_sec[i];
                if (osec == NULL)
                  continue;

                if (spu_elf_section_data(osec) == NULL)
                  continue;

                {
                  unsigned int ovl = spu_elf_section_data(osec)->u.o.ovl_index;
                  if (ovl <= htab->num_overlays)
                    {
                      asection *dst = htab->stub_sec[ovl];
                      if (dst != NULL)
                        place(dst, osec, NULL);
                    }
                }
              }
          }
      }

    if (flavour == ovly_soft_icache && htab->init != NULL)
      place(htab->init, NULL, ".ovl.init");

    if (htab->ovtab != NULL)
      {
        const char *ovout = (flavour == ovly_soft_icache) ? ".bss" : ".data";
        place(htab->ovtab, NULL, ovout);
      }

    if (htab->toe != NULL)
      place(htab->toe, NULL, ".toe");
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
  const char *start;
  const char *end;
  size_t max;
  ufile_ptr off;
  size_t remaining;
  size_t count;

  if (os == NULL || buf == NULL)
    return 0;

  start = (const char *) os->start;
  end = (const char *) os->end;

  if (start == NULL || end == NULL || end < start)
    return 0;

  max = (size_t) (end - start);
  off = (ufile_ptr) offset;

  if (off >= max)
    return 0;

  remaining = max - off;

  if (nbytes <= 0)
    count = remaining;
  else
    {
      size_t req = (size_t) nbytes;
      count = req < remaining ? req : remaining;
    }

  if (count == 0)
    return 0;

  memcpy (buf, start + off, count);
  return (file_ptr) count;
}

static int
ovl_mgr_stat(struct bfd *abfd ATTRIBUTE_UNUSED, void *stream, struct stat *sb)
{
  if (sb == NULL)
    return 0;

  memset(sb, 0, sizeof(*sb));

  if (stream != NULL)
    {
      struct _ovl_stream *os = stream;
      const char *start = (const char *) os->start;
      const char *end = (const char *) os->end;

      if (start != NULL && end != NULL && end >= start)
        sb->st_size = end - start;
    }

  return 0;
}

bool
spu_elf_open_builtin_lib (bfd **ovl_bfd, const struct _ovl_stream *stream)
{
  if (ovl_bfd == NULL)
    return false;

  *ovl_bfd = NULL;

  bfd *handle = bfd_openr_iovec("builtin ovl_mgr",
                                "elf32-spu",
                                ovl_mgr_open,
                                (void *) stream,
                                ovl_mgr_pread,
                                NULL,
                                ovl_mgr_stat);
  if (handle == NULL)
    return false;

  *ovl_bfd = handle;
  return true;
}

static unsigned int
overlay_index(asection *sec)
{
  if (sec == NULL)
  {
    return 0;
  }

  if (sec->output_section == NULL || sec->output_section == bfd_abs_section_ptr)
  {
    return 0;
  }

  if (spu_elf_section_data(sec->output_section) == NULL)
  {
    return 0;
  }

  return spu_elf_section_data(sec->output_section)->u.o.ovl_index;
}

/* Define an STT_OBJECT symbol.  */

static struct elf_link_hash_entry *
define_ovtab_symbol (struct spu_link_hash_table *htab, const char *name)
{
  struct elf_link_hash_entry *h = elf_link_hash_lookup (&htab->elf, name, true, false, false);
  if (h == NULL)
    return NULL;

  if (h->root.type != bfd_link_hash_defined || !h->def_regular)
    {
      h->root.type = bfd_link_hash_defined;
      h->root.u.def.section = htab->ovtab;
      h->type = STT_OBJECT;
      h->ref_regular = 1;
      h->def_regular = 1;
      h->ref_regular_nonweak = 1;
      h->non_elf = 0;
      return h;
    }

  {
    asection *section = h->root.u.def.section;
    bfd *owner = section != NULL ? section->owner : NULL;

    if (owner != NULL)
      {
        _bfd_error_handler (_("%pB is not allowed to define %s"),
                            owner, h->root.root.string);
        bfd_set_error (bfd_error_bad_value);
        return NULL;
      }

    _bfd_error_handler (_("you are not allowed to define %s in a script"),
                        h->root.root.string);
    bfd_set_error (bfd_error_bad_value);
    return NULL;
  }
}

/* Fill in all stubs and the overlay tables.  */

static bool set_ovtab_symbol(struct spu_link_hash_table *htab, const char *name, bfd_vma value, asection *section, bfd_size_type size)
{
  struct elf_link_hash_entry *h = define_ovtab_symbol(htab, name);
  if (h == NULL)
    return false;
  h->root.u.def.value = value;
  if (section != NULL)
    h->root.u.def.section = section;
  h->size = size;
  return true;
}

static bool
spu_elf_build_stubs (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  struct elf_link_hash_entry *h;
  unsigned int i;

  if (htab->num_overlays != 0)
    {
      for (i = 0; i < 2; i++)
        {
          h = htab->ovly_entry[i];
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
    }

  if (htab->stub_sec != NULL)
    {
      for (i = 0; i <= htab->num_overlays; i++)
        {
          asection *sec = htab->stub_sec[i];
          if (sec->size != 0)
            {
              sec->contents = bfd_zalloc (sec->owner, sec->size);
              if (sec->contents == NULL)
                return false;
              sec->alloced = 1;
              sec->rawsize = sec->size;
              sec->size = 0;
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
          asection *sec = htab->stub_sec[i];
          if (sec->size != sec->rawsize)
            {
              _bfd_error_handler  (_("stubs don't match calculated size"));
              bfd_set_error (bfd_error_bad_value);
              return false;
            }
          sec->rawsize = 0;
        }
    }

  if (htab->ovtab == NULL || htab->ovtab->size == 0)
    return true;

  htab->ovtab->contents = bfd_zalloc (htab->ovtab->owner, htab->ovtab->size);
  if (htab->ovtab->contents == NULL)
    return false;
  htab->ovtab->alloced = 1;

  if (htab->params->ovly_flavour == ovly_soft_icache)
    {
      bfd_vma off = 0;
      bfd_size_type sz;

      if (!set_ovtab_symbol (htab, "__icache_tag_array", 0, NULL, (bfd_size_type) (16 << htab->num_lines_log2)))
        return false;
      sz = (bfd_size_type) (16 << htab->num_lines_log2);
      off += sz;

      if (!set_ovtab_symbol (htab, "__icache_tag_array_size", (bfd_vma) (16 << htab->num_lines_log2), bfd_abs_section_ptr, 0))
        return false;

      if (!set_ovtab_symbol (htab, "__icache_rewrite_to", off, NULL, (bfd_size_type) (16 << htab->num_lines_log2)))
        return false;
      sz = (bfd_size_type) (16 << htab->num_lines_log2);
      off += sz;

      if (!set_ovtab_symbol (htab, "__icache_rewrite_to_size", (bfd_vma) (16 << htab->num_lines_log2), bfd_abs_section_ptr, 0))
        return false;

      sz = (bfd_size_type) (16 << (htab->fromelem_size_log2 + htab->num_lines_log2));
      if (!set_ovtab_symbol (htab, "__icache_rewrite_from", off, NULL, sz))
        return false;
      off += sz;

      if (!set_ovtab_symbol (htab, "__icache_rewrite_from_size", (bfd_vma) (16 << (htab->fromelem_size_log2 + htab->num_lines_log2)), bfd_abs_section_ptr, 0))
        return false;

      if (!set_ovtab_symbol (htab, "__icache_log2_fromelemsize", (bfd_vma) htab->fromelem_size_log2, bfd_abs_section_ptr, 0))
        return false;

      if (!set_ovtab_symbol (htab, "__icache_base", htab->ovl_sec[0]->vma, bfd_abs_section_ptr, (bfd_size_type) (htab->num_buf << htab->line_size_log2)))
        return false;

      if (!set_ovtab_symbol (htab, "__icache_linesize", (bfd_vma) (1 << htab->line_size_log2), bfd_abs_section_ptr, 0))
        return false;

      if (!set_ovtab_symbol (htab, "__icache_log2_linesize", (bfd_vma) htab->line_size_log2, bfd_abs_section_ptr, 0))
        return false;

      if (!set_ovtab_symbol (htab, "__icache_neg_log2_linesize", (bfd_vma) (-htab->line_size_log2), bfd_abs_section_ptr, 0))
        return false;

      if (!set_ovtab_symbol (htab, "__icache_cachesize", (bfd_vma) (1 << (htab->num_lines_log2 + htab->line_size_log2)), bfd_abs_section_ptr, 0))
        return false;

      if (!set_ovtab_symbol (htab, "__icache_log2_cachesize", (bfd_vma) (htab->num_lines_log2 + htab->line_size_log2), bfd_abs_section_ptr, 0))
        return false;

      if (!set_ovtab_symbol (htab, "__icache_neg_log2_cachesize", (bfd_vma) (-(htab->num_lines_log2 + htab->line_size_log2)), bfd_abs_section_ptr, 0))
        return false;

      if (htab->init != NULL && htab->init->size != 0)
        {
          htab->init->contents = bfd_zalloc (htab->init->owner, htab->init->size);
          if (htab->init->contents == NULL)
            return false;
          htab->init->alloced = 1;

          if (!set_ovtab_symbol (htab, "__icache_fileoff", 0, htab->init, 8))
            return false;
        }
    }
  else
    {
      bfd_byte *p = htab->ovtab->contents;
      bfd *obfd = htab->ovtab->output_section->owner;

      p[7] = 1;

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

      if (!set_ovtab_symbol (htab, "_ovly_table", 16, NULL, (bfd_size_type) (htab->num_overlays * 16)))
        return false;

      if (!set_ovtab_symbol (htab, "_ovly_table_end", (bfd_vma) (htab->num_overlays * 16 + 16), NULL, 0))
        return false;

      if (!set_ovtab_symbol (htab, "_ovly_buf_table", (bfd_vma) (htab->num_overlays * 16 + 16), NULL, (bfd_size_type) (htab->num_buf * 4)))
        return false;

      if (!set_ovtab_symbol (htab, "_ovly_buf_table_end", (bfd_vma) (htab->num_overlays * 16 + 16 + htab->num_buf * 4), NULL, 0))
        return false;
    }

  if (!set_ovtab_symbol (htab, "_EAR_", 0, htab->toe, 16))
    return false;

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

  if (info == NULL)
    return NULL;

  htab = spu_hash_table (info);
  if (htab == NULL || htab->params == NULL)
    return NULL;

  abfd = info->output_bfd;
  if (abfd == NULL)
    return NULL;

  hi = htab->params->local_store_hi;
  lo = htab->params->local_store_lo;

  if (hi >= lo)
    htab->local_store = (hi - lo) + 1;
  else
    htab->local_store = 0;

  for (m = elf_seg_map (abfd); m != NULL; m = m->next)
    {
      if (m->p_type != PT_LOAD)
        continue;

      for (i = 0; i < m->count; i++)
        {
          asection *sec = m->sections[i];
          bfd_size_type size;
          bfd_vma vma;
          bfd_vma remaining;

          if (sec == NULL)
            continue;

          size = sec->size;
          if (size == 0)
            continue;

          vma = sec->vma;

          if (vma < lo || vma > hi)
            return sec;

          remaining = hi - vma; /* Safe since vma <= hi above. */
          if ((bfd_vma)(size - 1) > remaining)
            return sec;
        }
    }

  return NULL;
}

/* OFFSET in SEC (presumably) is the beginning of a function prologue.
   Search for stack adjusting insns, and return the sp delta.
   If a store of lr is found save the instruction offset to *LR_STORE.
   If a stack adjusting instruction is found, save that offset to
   *SP_ADJUST.  */

static inline int handle_sp_update(int rt, int32_t *reg, bfd_vma offset, bfd_vma *sp_adjust, int sp_reg)
{
  if (rt != sp_reg)
    return 0;
  if (reg[rt] > 0)
    return 2;
  if (sp_adjust != NULL)
    *sp_adjust = offset;
  return 1;
}

static int
find_function_stack_adjust (asection *sec,
			    bfd_vma offset,
			    bfd_vma *lr_store,
			    bfd_vma *sp_adjust)
{
  int32_t reg[128];
  const int SP_REG = 1;
  const int LR_REG = 0;

  if (sec == NULL)
    return 0;

  memset (reg, 0, sizeof (reg));
  for (; offset + 4 <= sec->size; offset += 4)
    {
      unsigned char buf[4];
      int rt, ra;
      uint32_t imm;

      if (sec->owner == NULL || !bfd_get_section_contents (sec->owner, sec, buf, offset, 4))
	break;

      rt = buf[3] & 0x7f;
      ra = ((buf[2] & 0x3f) << 1) | (buf[3] >> 7);

      if (buf[0] == 0x24)
	{
	  if (rt == LR_REG && ra == SP_REG && lr_store != NULL)
	    *lr_store = offset;
	  continue;
	}

      imm = ((uint32_t)buf[1] << 9) | ((uint32_t)buf[2] << 1) | ((uint32_t)buf[3] >> 7);

      if (buf[0] == 0x1c)
	{
	  int sp_action;
	  imm >>= 7;
	  imm = (imm ^ 0x200) - 0x200;
	  reg[rt] = reg[ra] + (int32_t)imm;

	  sp_action = handle_sp_update(rt, reg, offset, sp_adjust, SP_REG);
	  if (sp_action == 2)
	    break;
	  if (sp_action == 1)
	    return reg[rt];
	}
      else if (buf[0] == 0x18 && (buf[1] & 0xe0) == 0)
	{
	  int rb = ((buf[1] & 0x1f) << 2) | ((buf[2] & 0xc0) >> 6);
	  int sp_action;

	  reg[rt] = reg[ra] + reg[rb];

	  sp_action = handle_sp_update(rt, reg, offset, sp_adjust, SP_REG);
	  if (sp_action == 2)
	    break;
	  if (sp_action == 1)
	    return reg[rt];
	}
      else if (buf[0] == 0x08 && (buf[1] & 0xe0) == 0)
	{
	  int rb = ((buf[1] & 0x1f) << 2) | ((buf[2] & 0xc0) >> 6);
	  int sp_action;

	  reg[rt] = reg[rb] - reg[ra];

	  sp_action = handle_sp_update(rt, reg, offset, sp_adjust, SP_REG);
	  if (sp_action == 2)
	    break;
	  if (sp_action == 1)
	    return reg[rt];
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
	  reg[rt] = (int32_t)imm;
	  continue;
	}
      else if (buf[0] == 0x60 && (buf[1] & 0x80) != 0)
	{
	  reg[rt] |= (int32_t)(imm & 0xffff);
	  continue;
	}
      else if (buf[0] == 0x04)
	{
	  imm >>= 7;
	  imm = (imm ^ 0x200) - 0x200;
	  reg[rt] = reg[ra] | (int32_t)imm;
	  continue;
	}
      else if (buf[0] == 0x32 && (buf[1] & 0x80) != 0)
	{
	  reg[rt] = (((imm & 0x8000) ? 0xff000000 : 0)
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
	  reg[rt] = reg[ra] & (int32_t)imm;
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

static int
sort_syms(const void *a, const void *b)
{
  const Elf_Internal_Sym *const *s1 = (const Elf_Internal_Sym *const *) a;
  const Elf_Internal_Sym *const *s2 = (const Elf_Internal_Sym *const *) b;

  asection *sec1 = sort_syms_psecs[*s1 - sort_syms_syms];
  asection *sec2 = sort_syms_psecs[*s2 - sort_syms_syms];

  if (sec1 != sec2)
    return (sec1->index < sec2->index) ? -1 : 1;

  {
    bfd_signed_vma v1 = (*s1)->st_value;
    bfd_signed_vma v2 = (*s2)->st_value;
    if (v1 != v2)
      return (v1 < v2) ? -1 : 1;
  }

  {
    bfd_signed_vma sz1 = (*s1)->st_size;
    bfd_signed_vma sz2 = (*s2)->st_size;
    if (sz1 != sz2)
      return (sz1 > sz2) ? -1 : 1;
  }

  return (*s1 < *s2) ? -1 : 1;
}

/* Allocate a struct spu_elf_stack_info with MAX_FUN struct function_info
   entries for section SEC.  */

static struct spu_elf_stack_info *
alloc_stack_info (asection *sec, int max_fun)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  bfd_size_type base, extra_elems, amt;

  if (sec_data == NULL)
    return NULL;

  if (max_fun < 1)
    {
      sec_data->u.i.stack_info = NULL;
      return NULL;
    }

  base = (bfd_size_type) sizeof (struct spu_elf_stack_info);
  extra_elems = (bfd_size_type) (max_fun - 1);

  if (extra_elems > 0)
    {
      bfd_size_type max_extra = (((bfd_size_type) -1) - base) / (bfd_size_type) sizeof (struct function_info);
      if (extra_elems > max_extra)
        {
          sec_data->u.i.stack_info = NULL;
          return NULL;
        }
      amt = base + extra_elems * (bfd_size_type) sizeof (struct function_info);
    }
  else
    amt = base;

  sec_data->u.i.stack_info = bfd_zmalloc (amt);
  if (sec_data->u.i.stack_info != NULL)
    sec_data->u.i.stack_info->max_fun = max_fun;
  return sec_data->u.i.stack_info;
}

/* Add a new struct function_info describing a (part of a) function
   starting at SYM_H.  Keep the array sorted by address.  */

static struct function_info *
maybe_insert_function (asection *sec, void *sym_h, bool global, bool is_func)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
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

  int i = sinfo->num_fun - 1;
  while (i >= 0 && sinfo->fun[i].lo > off)
    i--;

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
      const int growth_chunk = 20;
      const bfd_size_type bfd_max = (bfd_size_type) -1;
      const bfd_size_type header_size = sizeof (struct spu_elf_stack_info);
      const bfd_size_type fun_size = sizeof (struct function_info);

      bfd_size_type old_count = (sinfo->max_fun > 0) ? (sinfo->max_fun - 1) : 0;
      if (old_count != 0 && old_count > (bfd_max - header_size) / fun_size)
        return NULL;

      bfd_size_type old = header_size + old_count * fun_size;

      bfd_size_type grow = (bfd_size_type) growth_chunk + (sinfo->max_fun >> 1);
      if (sinfo->max_fun > bfd_max - grow)
        return NULL;

      sinfo->max_fun += grow;

      bfd_size_type new_count = (sinfo->max_fun > 0) ? (sinfo->max_fun - 1) : 0;
      if (new_count != 0 && new_count > (bfd_max - header_size) / fun_size)
        return NULL;

      bfd_size_type amt = header_size + new_count * fun_size;
      if (amt < old)
        return NULL;

      sinfo = bfd_realloc (sinfo, amt);
      if (sinfo == NULL)
        return NULL;

      memset ((char *) sinfo + old, 0, amt - old);
      sec_data->u.i.stack_info = sinfo;
    }

  int insert_index = i + 1;

  if (insert_index < sinfo->num_fun)
    {
      size_t count = (size_t) (sinfo->num_fun - insert_index);
      memmove (&sinfo->fun[insert_index + 1],
               &sinfo->fun[insert_index],
               count * sizeof (sinfo->fun[0]));
    }

  struct function_info *fi = &sinfo->fun[insert_index];
  fi->is_func = is_func;
  fi->global = global;
  fi->sec = sec;
  if (global)
    fi->u.h = sym_h;
  else
    fi->u.sym = sym_h;
  fi->lo = off;
  fi->hi = off + size;
  fi->lr_store = -1;
  fi->sp_adjust = -1;
  fi->stack = -find_function_stack_adjust (sec, off, &fi->lr_store, &fi->sp_adjust);

  sinfo->num_fun += 1;
  return fi;
}

/* Return the name of FUN.  */

static const char *
func_name (struct function_info *fun)
{
  static const char *fallback = "(null)";
  asection *sec;
  bfd *ibfd;
  Elf_Internal_Shdr *symtab_hdr;

  if (fun == NULL)
    return fallback;

  while (fun->start)
    fun = fun->start;

  if (fun->global)
    {
      if (fun->u.h && fun->u.h->root.root.string)
	return fun->u.h->root.root.string;
      return fallback;
    }

  sec = fun->sec;
  if (sec == NULL || sec->name == NULL)
    return fallback;

  if (fun->u.sym == NULL)
    return fallback;

  if (fun->u.sym->st_name == 0)
    {
      unsigned long value = ((unsigned long) fun->u.sym->st_value) & 0xffffffffUL;
      int needed = snprintf (NULL, 0, "%s+%lx", sec->name, value);
      if (needed < 0)
	return fallback;

      char *name = bfd_malloc ((size_t) needed + 1);
      if (name == NULL)
	return fallback;

      if (snprintf (name, (size_t) needed + 1, "%s+%lx", sec->name, value) < 0)
	return fallback;

      return name;
    }

  ibfd = sec->owner;
  if (ibfd == NULL)
    return fallback;

  symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
  return bfd_elf_sym_name (ibfd, symtab_hdr, fun->u.sym, sec);
}

/* Read the instruction at OFF in SEC.  Return true iff the instruction
   is a nop, lnop, or stop 0 (all zero insn).  */

static bool
is_nop (asection *sec, bfd_vma off)
{
  enum { INSN_SIZE = 4 };
  unsigned char insn[INSN_SIZE];

  if (sec == NULL || sec->owner == NULL)
    return false;

  if (off > sec->size)
    return false;

  if (sec->size - off < INSN_SIZE)
    return false;

  if (!bfd_get_section_contents (sec->owner, sec, insn, off, INSN_SIZE))
    return false;

  {
    const bool is_arch_nop = ((insn[0] & 0xbf) == 0) && ((insn[1] & 0xe0) == 0x20);
    const bool is_zero_nop = (insn[0] == 0 && insn[1] == 0 && insn[2] == 0 && insn[3] == 0);
    return is_arch_nop || is_zero_nop;
  }
}

/* Extend the range of FUN to cover nop padding up to LIMIT.
   Return TRUE iff some instruction other than a NOP was found.  */

static bool
insns_at_end(struct function_info *fun, bfd_vma limit)
{
    if (fun == NULL) {
        return false;
    }

    const bfd_vma insn_size = 4;
    bfd_vma off = (fun->hi + (insn_size - 1)) & ~(bfd_vma)(insn_size - 1);

    while (off < limit && is_nop(fun->sec, off)) {
        off += insn_size;
    }

    const bool found = (off < limit);
    fun->hi = found ? off : limit;
    return found;
}

/* Check and fix overlapping function ranges.  Return TRUE iff there
   are gaps in the current info we have about functions in SEC.  */

static bool
check_function_ranges (asection *sec, struct bfd_link_info *info)
{
  if (sec == NULL || info == NULL)
    return false;

  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL)
    return false;

  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL)
    return false;

  bool gaps = false;
  int num_fun = sinfo->num_fun;

  for (int i = 1; i < num_fun; i++)
    {
      if (sinfo->fun[i - 1].hi > sinfo->fun[i].lo)
        {
          const char *f1 = func_name (&sinfo->fun[i - 1]);
          const char *f2 = func_name (&sinfo->fun[i]);
          if (info->callbacks && info->callbacks->einfo)
            info->callbacks->einfo (_("warning: %s overlaps %s\n"), f1, f2);
          sinfo->fun[i - 1].hi = sinfo->fun[i].lo;
        }
      else if (insns_at_end (&sinfo->fun[i - 1], sinfo->fun[i].lo))
        {
          gaps = true;
        }
    }

  if (num_fun <= 0)
    return true;

  if (sinfo->fun[0].lo != 0)
    gaps = true;

  int last = num_fun - 1;
  if (sinfo->fun[last].hi > sec->size)
    {
      const char *f1 = func_name (&sinfo->fun[last]);
      if (info->callbacks && info->callbacks->einfo)
        info->callbacks->einfo (_("warning: %s exceeds section size\n"), f1);
      sinfo->fun[last].hi = sec->size;
    }
  else if (insns_at_end (&sinfo->fun[last], sec->size))
    gaps = true;

  return gaps;
}

/* Search current function info for a function that contains address
   OFFSET in section SEC.  */

static struct function_info *
find_function (asection *sec, bfd_vma offset, struct bfd_link_info *info)
{
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  struct function_info *funs;
  int lo, hi;

  if (info == NULL || info->callbacks == NULL || info->callbacks->einfo == NULL)
    {
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }

  if (sec == NULL)
    goto not_found;

  sec_data = spu_elf_section_data (sec);
  if (sec_data == NULL)
    goto not_found;

  sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL || sinfo->num_fun <= 0)
    goto not_found;

  funs = sinfo->fun;
  if (funs == NULL)
    goto not_found;

  lo = 0;
  hi = sinfo->num_fun;
  while (lo < hi)
    {
      int mid = lo + ((hi - lo) / 2);
      if (offset < funs[mid].lo)
        hi = mid;
      else if (offset >= funs[mid].hi)
        lo = mid + 1;
      else
        return &funs[mid];
    }

not_found:
  info->callbacks->einfo (_("%pA:0x%v not found in function table\n"),
                          sec, offset);
  bfd_set_error (bfd_error_bad_value);
  return NULL;
}

/* Add CALLEE to CALLER call list if not already present.  Return TRUE
   if CALLEE was new.  If this function return FALSE, CALLEE should
   be freed.  */

static bool
insert_callee(struct function_info *caller, struct call_info *callee)
{
  if (caller == NULL || callee == NULL)
    return false;

  struct call_info **pp = &caller->call_list;
  struct call_info *p = *pp;

  while (p != NULL)
    {
      if (p->fun == callee->fun)
        {
          p->is_tail = (p->is_tail && callee->is_tail);
          if (!p->is_tail && p->fun != NULL)
            {
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
      p = *pp;
    }

  callee->next = caller->call_list;
  caller->call_list = callee;
  return true;
}

/* Copy CALL and insert the copy into CALLER.  */

static bool
copy_callee(struct function_info *caller, const struct call_info *call)
{
  if (caller == NULL || call == NULL)
    return true;

  struct call_info *callee = bfd_malloc(sizeof *callee);
  if (callee == NULL)
    return false;

  *callee = *call;

  if (!insert_callee(caller, callee))
    free(callee);

  return true;
}

/* We're only interested in code sections.  Testing SEC_IN_MEMORY excludes
   overlay stub sections.  */

static bool
interesting_section(const asection *sec)
{
  if (sec == NULL)
    return false;

  if (sec->output_section == bfd_abs_section_ptr)
    return false;

  if (sec->size == 0)
    return false;

  if ((sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_IN_MEMORY))
      != (SEC_ALLOC | SEC_LOAD | SEC_CODE))
    return false;

  return true;
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
      enum elf_spu_reloc_type r_type = ELF32_R_TYPE (irela->r_info);
      bool is_branch_reloc = (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16);
      bool nonbranch = !is_branch_reloc;
      bool is_call = false;
      unsigned int r_indx = ELF32_R_SYM (irela->r_info);
      asection *sym_sec;
      Elf_Internal_Sym *sym;
      struct elf_link_hash_entry *h;

      if (!get_sym_h (&h, &sym, &sym_sec, psyms, r_indx, sec->owner))
        return false;

      if (sym_sec == NULL || sym_sec->output_section == bfd_abs_section_ptr)
        continue;

      if (is_branch_reloc)
        {
          unsigned char insn[4];

          if (!bfd_get_section_contents (sec->owner, sec, insn,
                                         irela->r_offset, 4))
            return false;

          if (is_branch (insn))
            {
              is_call = (insn[0] & 0xfd) == 0x31;

              priority = insn[1] & 0x0f;
              priority <<= 8;
              priority |= insn[2];
              priority <<= 8;
              priority |= insn[3];
              priority >>= 7;

              if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE))
                  != (SEC_ALLOC | SEC_LOAD | SEC_CODE))
                {
                  if (!warned && info && info->callbacks && info->callbacks->einfo)
                    info->callbacks->einfo
                      (_("%pB(%pA+0x%v): call to non-code section"
                         " %pB(%pA), analysis incomplete\n"),
                       sec->owner, sec, irela->r_offset,
                       sym_sec->owner, sym_sec);
                  warned = true;
                  continue;
                }
            }
          else
            {
              nonbranch = true;
              if (is_hint (insn))
                continue;
            }
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

          if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE))
              != (SEC_ALLOC | SEC_LOAD | SEC_CODE))
            continue;
        }

      {
        bfd_vma val = (h ? h->root.u.def.value : sym->st_value) + irela->r_addend;

        if (!call_tree)
          {
            struct function_info *fun;
            bool fake_allocated = false;
            Elf_Internal_Sym *orig_sym = sym;

            if (irela->r_addend != 0)
              {
                Elf_Internal_Sym *fake = bfd_zmalloc (sizeof (*fake));
                if (fake == NULL)
                  return false;
                fake->st_value = val;
                fake->st_shndx = _bfd_elf_section_from_bfd_section (sym_sec->owner, sym_sec);
                sym = fake;
                fake_allocated = true;
              }

            fun = sym ? maybe_insert_function (sym_sec, sym, false, is_call)
                      : maybe_insert_function (sym_sec, h, true, is_call);

            if (fun == NULL)
              {
                if (fake_allocated)
                  free (sym);
                return false;
              }

            if (fake_allocated && fun->u.sym != sym)
              free (sym);

            sym = orig_sym;
            continue;
          }

        {
          struct function_info *caller = find_function (sec, irela->r_offset, info);
          struct call_info *callee;

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
            }
          else if (!is_call && !callee->fun->is_func && callee->fun->stack == 0)
            {
              if (sec->owner != sym_sec->owner)
                {
                  callee->fun->start = NULL;
                  callee->fun->is_func = true;
                }
              else if (callee->fun->start == NULL)
                {
                  struct function_info *caller_start = caller;
                  while (caller_start->start)
                    caller_start = caller_start->start;

                  if (caller_start != callee->fun)
                    callee->fun->start = caller_start;
                }
              else
                {
                  struct function_info *callee_start = callee->fun;
                  struct function_info *caller_start = caller;

                  while (callee_start->start)
                    callee_start = callee_start->start;
                  while (caller_start->start)
                    caller_start = caller_start->start;

                  if (caller_start != callee_start)
                    {
                      callee->fun->start = NULL;
                      callee->fun->is_func = true;
                    }
                }
            }
        }
      }
    }

  return true;
}

/* Handle something like .init or .fini, which has a piece of a function.
   These sections are pasted together to form a single function.  */

static bool
pasted_function (asection *sec)
{
  struct bfd_link_order *l;
  struct _spu_elf_section_data *sec_data = NULL;
  struct spu_elf_stack_info *sinfo = NULL;
  Elf_Internal_Sym *fake;
  struct function_info *fun, *fun_start;
  asection *indsec;

  if (sec == NULL || sec->owner == NULL || sec->output_section == NULL)
    return false;

  fake = bfd_zmalloc (sizeof (*fake));
  if (fake == NULL)
    return false;

  fake->st_value = 0;
  fake->st_size = sec->size;
  fake->st_shndx = _bfd_elf_section_from_bfd_section (sec->owner, sec);

  fun = maybe_insert_function (sec, fake, false, false);
  if (fun == NULL)
    {
      free (fake);
      return false;
    }

  fun_start = NULL;
  for (l = sec->output_section->map_head.link_order; l != NULL; l = l->next)
    {
      if (l->type != bfd_indirect_link_order)
        continue;

      indsec = l->u.indirect.section;

      if (indsec == sec)
        {
          if (fun_start != NULL)
            {
              struct call_info *callee = bfd_malloc (sizeof *callee);
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
          break;
        }

      sec_data = spu_elf_section_data (indsec);
      if (sec_data != NULL)
        {
          sinfo = sec_data->u.i.stack_info;
          if (sinfo != NULL && sinfo->num_fun != 0)
            fun_start = &sinfo->fun[sinfo->num_fun - 1];
        }
    }

  return true;
}

/* Map address ranges in code sections to functions.  */

static bool
discover_functions (struct bfd_link_info *info)
{
  bfd *ibfd;
  int bfd_idx = 0;
  size_t num_bfds = 0;
  Elf_Internal_Sym ***psym_arr = NULL;
  asection ***sec_arr = NULL;
  bool gaps = false;
  bool result = false;
  extern const bfd_target spu_elf32_vec;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    bfd_idx++;
  num_bfds = (size_t) bfd_idx;

  if (num_bfds == 0)
    return true;

  psym_arr = bfd_zmalloc (num_bfds * sizeof (*psym_arr));
  if (psym_arr == NULL)
    goto cleanup;

  sec_arr = bfd_zmalloc (num_bfds * sizeof (*sec_arr));
  if (sec_arr == NULL)
    goto cleanup;

  for (ibfd = info->input_bfds, bfd_idx = 0;
       ibfd != NULL;
       ibfd = ibfd->link.next, bfd_idx++)
    {
      Elf_Internal_Shdr *symtab_hdr;
      asection *sec;
      size_t symcount;
      Elf_Internal_Sym *syms, *sy, **psyms, **psy;
      asection **psecs, **p;

      if (ibfd->xvec != &spu_elf32_vec)
        continue;

      symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;

      if (symtab_hdr->sh_entsize == 0)
        goto cleanup;

      symcount = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
      if (symcount == 0)
        {
          if (!gaps)
            for (sec = ibfd->sections; sec != NULL && !gaps; sec = sec->next)
              if (interesting_section (sec))
                {
                  gaps = true;
                  break;
                }
          continue;
        }

      free (symtab_hdr->contents);
      symtab_hdr->contents = NULL;
      syms = bfd_elf_get_elf_syms (ibfd, symtab_hdr, symcount, 0,
                                   NULL, NULL, NULL);
      symtab_hdr->contents = (void *) syms;
      if (syms == NULL)
        goto cleanup;

      {
        size_t limit_psyms = ((size_t) -1) / sizeof (*psyms);
        size_t limit_psecs = ((size_t) -1) / sizeof (*psecs);
        if (symcount >= limit_psyms)
          goto cleanup;
        if (symcount > limit_psecs)
          goto cleanup;
      }

      psyms = bfd_malloc ((symcount + 1) * sizeof (*psyms));
      if (psyms == NULL)
        goto cleanup;
      psym_arr[bfd_idx] = psyms;

      psecs = bfd_malloc (symcount * sizeof (*psecs));
      if (psecs == NULL)
        goto cleanup;
      sec_arr[bfd_idx] = psecs;

      for (psy = psyms, p = psecs, sy = syms; sy < syms + symcount; ++p, ++sy)
        if (ELF_ST_TYPE (sy->st_info) == STT_NOTYPE
            || ELF_ST_TYPE (sy->st_info) == STT_FUNC)
          {
            asection *s;
            *p = s = bfd_section_from_elf_index (ibfd, sy->st_shndx);
            if (s != NULL && interesting_section (s))
              *psy++ = sy;
          }
      symcount = (size_t) (psy - psyms);
      *psy = NULL;

      sort_syms_syms = syms;
      sort_syms_psecs = psecs;
      qsort (psyms, symcount, sizeof (*psyms), sort_syms);

      for (psy = psyms; psy < psyms + symcount; )
        {
          asection *s = psecs[*psy - syms];
          Elf_Internal_Sym **psy2;

          for (psy2 = psy; ++psy2 < psyms + symcount; )
            if (psecs[*psy2 - syms] != s)
              break;

          if (!alloc_stack_info (s, (int) (psy2 - psy)))
            goto cleanup;
          psy = psy2;
        }

      for (psy = psyms; psy < psyms + symcount; ++psy)
        {
          sy = *psy;
          if (ELF_ST_TYPE (sy->st_info) == STT_FUNC)
            {
              asection *s = psecs[sy - syms];
              if (!maybe_insert_function (s, sy, false, true))
                goto cleanup;
            }
        }

      for (sec = ibfd->sections; sec != NULL && !gaps; sec = sec->next)
        if (interesting_section (sec))
          gaps |= check_function_ranges (sec, info);
    }

  if (gaps)
    {
      for (ibfd = info->input_bfds, bfd_idx = 0;
           ibfd != NULL;
           ibfd = ibfd->link.next, bfd_idx++)
        {
          asection *sec;

          if (psym_arr[bfd_idx] == NULL)
            continue;

          for (sec = ibfd->sections; sec != NULL; sec = sec->next)
            if (!mark_functions_via_relocs (sec, info, false))
              goto cleanup;
        }

      for (ibfd = info->input_bfds, bfd_idx = 0;
           ibfd != NULL;
           ibfd = ibfd->link.next, bfd_idx++)
        {
          Elf_Internal_Shdr *symtab_hdr;
          asection *sec;
          Elf_Internal_Sym *syms, *sy, **psyms, **psy;
          asection **psecs;

          if ((psyms = psym_arr[bfd_idx]) == NULL)
            continue;

          psecs = sec_arr[bfd_idx];

          symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
          syms = (Elf_Internal_Sym *) symtab_hdr->contents;

          gaps = false;
          for (sec = ibfd->sections; sec != NULL && !gaps; sec = sec->next)
            if (interesting_section (sec))
              gaps |= check_function_ranges (sec, info);
          if (!gaps)
            continue;

          for (psy = psyms; (sy = *psy) != NULL; ++psy)
            {
              asection *s = psecs[sy - syms];

              if (ELF_ST_TYPE (sy->st_info) != STT_FUNC
                  && ELF_ST_BIND (sy->st_info) == STB_GLOBAL)
                {
                  if (!maybe_insert_function (s, sy, false, false))
                    goto cleanup;
                }
            }
        }

      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
        {
          asection *sec;

          if (ibfd->xvec != &spu_elf32_vec)
            continue;

          for (sec = ibfd->sections; sec != NULL; sec = sec->next)
            if (interesting_section (sec))
              {
                struct _spu_elf_section_data *sec_data;
                struct spu_elf_stack_info *sinfo;

                sec_data = spu_elf_section_data (sec);
                sinfo = sec_data->u.i.stack_info;
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
                else if (!pasted_function (sec))
                  goto cleanup;
              }
        }
    }

  result = true;

cleanup:
  if (psym_arr != NULL && sec_arr != NULL)
    {
      int i;
      for (i = 0; i < (int) num_bfds; i++)
        {
          if (psym_arr[i] != NULL)
            free (psym_arr[i]);
          if (sec_arr[i] != NULL)
            free (sec_arr[i]);
        }
    }
  free (psym_arr);
  free (sec_arr);

  return result;
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
    asection *sec;

    if (ibfd->xvec != &spu_elf32_vec)
    {
      continue;
    }

    for (sec = ibfd->sections; sec != NULL; sec = sec->next)
    {
      struct _spu_elf_section_data *sec_data;
      struct spu_elf_stack_info *sinfo;
      int i;

      sec_data = spu_elf_section_data (sec);
      if (sec_data == NULL)
      {
        continue;
      }

      sinfo = sec_data->u.i.stack_info;
      if (sinfo == NULL)
      {
        continue;
      }

      for (i = 0; i < sinfo->num_fun; ++i)
      {
        bool should_process = (!root_only || !sinfo->fun[i].non_root);
        if (!should_process)
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
  if (fun == NULL)
    return true;

  struct function_info *start = fun->start;
  if (start == NULL)
    return true;

  while (start->start != NULL)
    start = start->start;

  struct call_info *call = fun->call_list;
  while (call != NULL)
    {
      struct call_info *call_next = call->next;
      if (!insert_callee (start, call))
        free (call);
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

  if (fun == NULL)
    return true;

  if (fun->visit1)
    return true;

  fun->visit1 = true;

  for (call = fun->call_list; call != NULL; call = call->next)
    {
      struct function_info *callee = call->fun;

      if (callee == NULL)
        continue;

      callee->non_root = true;

      if (!callee->visit1)
        mark_non_root (callee, 0, 0);
    }
  return true;
}

/* Remove cycles from the call graph.  Set depth of nodes.  */

static bool
remove_cycles(struct function_info *fun, struct bfd_link_info *info, void *param)
{
  unsigned int *param_depth;
  unsigned int depth;
  unsigned int max_depth;
  struct call_info *call;

  if (fun == NULL || info == NULL || param == NULL)
    return false;

  param_depth = (unsigned int *) param;
  depth = *param_depth;
  max_depth = depth;

  fun->depth = depth;
  fun->visit2 = true;
  fun->marking = true;

  for (call = fun->call_list; call != NULL; call = call->next)
    {
      call->max_depth = depth + (!call->is_pasted);

      if (call->fun == NULL)
        return false;

      if (!call->fun->visit2)
        {
          if (!remove_cycles(call->fun, info, &call->max_depth))
            return false;

          if (max_depth < call->max_depth)
            max_depth = call->max_depth;
        }
      else if (call->fun->marking)
        {
          struct spu_link_hash_table *htab = spu_hash_table(info);

          if (htab != NULL
              && htab->params != NULL
              && !htab->params->auto_overlay
              && htab->params->stack_analysis)
            {
              const char *f1 = func_name(fun);
              const char *f2 = func_name(call->fun);

              if (info->callbacks != NULL && info->callbacks->info != NULL)
                info->callbacks->info(_("stack analysis will ignore the call "
                                        "from %s to %s\n"),
                                      f1, f2);
            }

          call->broken_cycle = true;
        }
    }

  fun->marking = false;
  *param_depth = max_depth;
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
  unsigned int *count;

  if (fun == NULL || info == NULL)
    return false;

  if (fun->visit2)
    return true;

  fun->non_root = false;

  count = (unsigned int *) param;
  if (count != NULL)
    *count = 0;

  return remove_cycles (fun, info, param);
}

/* Populate call_list for each function.  */

static bool
build_call_tree(struct bfd_link_info *info)
{
  bfd *ibfd;
  unsigned int depth = 0;
  extern const bfd_target spu_elf32_vec;

  if (info == NULL)
    return false;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      asection *sec;

      if (ibfd->xvec != &spu_elf32_vec)
        continue;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
        {
          if (!mark_functions_via_relocs(sec, info, true))
            return false;
        }
    }

  if (!spu_hash_table(info)->params->auto_overlay)
    {
      if (!for_each_node(transfer_calls, info, 0, false))
        return false;
    }

  if (!for_each_node(mark_non_root, info, 0, false))
    return false;

  if (!for_each_node(remove_cycles, info, &depth, true))
    return false;

  return for_each_node(mark_detached_root, info, &depth, false);
}

/* qsort predicate to sort calls by priority, max_depth then count.  */

static int
sort_calls(const void *a, const void *b)
{
  const struct call_info *const *c1 = (const struct call_info *const *)a;
  const struct call_info *const *c2 = (const struct call_info *const *)b;
  const struct call_info *ci1 = *c1;
  const struct call_info *ci2 = *c2;

  if (ci1->priority != ci2->priority)
    return (ci1->priority < ci2->priority) ? 1 : -1;

  if (ci1->max_depth != ci2->max_depth)
    return (ci1->max_depth < ci2->max_depth) ? 1 : -1;

  if (ci1->count != ci2->count)
    return (ci1->count < ci2->count) ? 1 : -1;

  if (c1 < c2)
    return -1;
  if (c1 > c2)
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

static asection *find_section_in_group_or_owner(asection *text_sec, const char *name)
{
  asection *rodata = NULL;
  asection *group_sec = elf_section_data(text_sec)->next_in_group;

  if (group_sec == NULL)
    {
      rodata = bfd_get_section_by_name(text_sec->owner, name);
    }
  else
    {
      while (group_sec != NULL && group_sec != text_sec)
        {
          if (strcmp(group_sec->name, name) == 0)
            {
              rodata = group_sec;
              break;
            }
          group_sec = elf_section_data(group_sec)->next_in_group;
        }
    }
  return rodata;
}

static bool should_mark_text_section(struct function_info *fun, struct spu_link_hash_table *htab)
{
  if (fun->sec->linker_mark)
    return false;

  if (htab->params->ovly_flavour != ovly_soft_icache
      || htab->params->non_ia_text
      || startswith(fun->sec->name, ".text.ia.")
      || strcmp(fun->sec->name, ".init") == 0
      || strcmp(fun->sec->name, ".fini") == 0)
    return true;

  return false;
}

static bool compute_rodata_attachment(struct function_info *fun,
                                      struct spu_link_hash_table *htab,
                                      unsigned int *out_size)
{
  unsigned int size = fun->sec->size;

  if ((htab->params->auto_overlay & OVERLAY_RODATA) != 0)
    {
      const char *secname = fun->sec->name;
      char *name = NULL;

      if (strcmp(secname, ".text") == 0)
        {
          name = bfd_malloc(sizeof(".rodata"));
          if (name == NULL)
            return false;
          memcpy(name, ".rodata", sizeof(".rodata"));
        }
      else if (startswith(secname, ".text."))
        {
          size_t len = strlen(secname);
          char *p = bfd_malloc(len + 3);
          if (p == NULL)
            return false;
          memcpy(p, ".rodata", sizeof(".rodata"));
          memcpy(p + 7, secname + 5, len - 4);
          name = p;
        }
      else if (startswith(secname, ".gnu.linkonce.t."))
        {
          size_t len = strlen(secname) + 1;
          char *p = bfd_malloc(len);
          if (p == NULL)
            return false;
          memcpy(p, secname, len);
          p[14] = 'r';
          name = p;
        }

      if (name != NULL)
        {
          asection *rodata = find_section_in_group_or_owner(fun->sec, name);
          fun->rodata = rodata;

          if (fun->rodata)
            {
              unsigned int newsize = size + fun->rodata->size;
              if (htab->params->line_size != 0 && newsize > htab->params->line_size)
                {
                  fun->rodata = NULL;
                }
              else
                {
                  size = newsize;
                  fun->rodata->linker_mark = 1;
                  fun->rodata->gc_mark = 1;
                  fun->rodata->flags &= ~SEC_CODE;
                }
            }
          free(name);
        }
    }

  *out_size = size;
  return true;
}

static bool sort_call_list(struct function_info *fun)
{
  unsigned int count = 0;
  struct call_info *call;

  for (call = fun->call_list; call != NULL; call = call->next)
    count++;

  if (count <= 1)
    return true;

  {
    struct call_info **calls = bfd_malloc(count * sizeof(*calls));
    if (calls == NULL)
      return false;

    unsigned int i = 0;
    for (call = fun->call_list; call != NULL; call = call->next)
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
  }

  return true;
}

static bool
mark_overlay_section (struct function_info *fun,
		      struct bfd_link_info *info,
		      void *param)
{
  struct _mos_param *mos_param = param;
  struct spu_link_hash_table *htab;

  if (fun == NULL || info == NULL || mos_param == NULL || fun->sec == NULL)
    return false;

  htab = spu_hash_table(info);

  if (fun->visit4)
    return true;

  fun->visit4 = true;

  if (should_mark_text_section(fun, htab))
    {
      unsigned int size;

      fun->sec->linker_mark = 1;
      fun->sec->gc_mark = 1;
      fun->sec->segment_mark = 0;
      fun->sec->flags |= SEC_CODE;

      if (!compute_rodata_attachment(fun, htab, &size))
        return false;

      if (mos_param->max_overlay_size < size)
        mos_param->max_overlay_size = size;
    }

  if (!sort_call_list(fun))
    return false;

  for (struct call_info *call = fun->call_list; call != NULL; call = call->next)
    {
      if (call->is_pasted)
        {
          BFD_ASSERT (!fun->sec->segment_mark);
          fun->sec->segment_mark = 1;
        }
      if (!call->broken_cycle
          && !mark_overlay_section(call->fun, info, param))
        return false;
    }

  if (fun->sec->output_section != NULL)
    {
      if (fun->lo + fun->sec->output_offset + fun->sec->output_section->vma
          == info->output_bfd->start_address
          || startswith(fun->sec->output_section->name, ".ovl.init"))
        {
          fun->sec->linker_mark = 0;
          if (fun->rodata != NULL)
            fun->rodata->linker_mark = 0;
        }
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
unmark_overlay_section(struct function_info *fun,
                       struct bfd_link_info *info,
                       void *param)
{
  struct call_info *call;
  struct _uos_param *uos_param = param;
  unsigned int excluded = 0;

  (void)info;

  if (fun == NULL || uos_param == NULL)
    return false;

  if (fun->visit5)
    return true;

  fun->visit5 = true;

  if (fun->sec == uos_param->exclude_input_section
      || (fun->sec != NULL
          && fun->sec->output_section == uos_param->exclude_output_section))
    excluded = 1;

  if (RECURSE_UNMARK)
    uos_param->clearing += excluded;

  if (RECURSE_UNMARK ? uos_param->clearing : excluded)
    {
      if (fun->sec != NULL)
        fun->sec->linker_mark = 0;
      if (fun->rodata != NULL)
        fun->rodata->linker_mark = 0;
    }

  for (call = fun->call_list; call != NULL; call = call->next)
    {
      if (!call->broken_cycle)
        {
          if (call->fun == NULL)
            return false;
          if (!unmark_overlay_section(call->fun, info, param))
            return false;
        }
    }

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
  struct _cl_param *lib_param = (struct _cl_param *) param;
  struct call_info *call;
  unsigned int size;

  (void) info;

  if (fun == NULL || lib_param == NULL || fun->sec == NULL || lib_param->lib_sections == NULL)
    return true;

  if (fun->visit6)
    return true;

  fun->visit6 = true;

  if (!fun->sec->linker_mark || !fun->sec->gc_mark || fun->sec->segment_mark)
    return true;

  size = fun->sec->size;
  if (fun->rodata)
    size += fun->rodata->size;

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
      if (!call->broken_cycle && call->fun != NULL)
        collect_lib_sections(call->fun, info, param);
    }

  return true;
}

/* qsort predicate to sort sections by call count.  */

static int total_call_count(asection *sec)
{
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  int total = 0;
  int i;

  if (sec == NULL)
    return 0;

  sec_data = spu_elf_section_data(sec);
  if (sec_data == NULL)
    return 0;

  sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL || sinfo->num_fun <= 0 || sinfo->fun == NULL)
    return 0;

  for (i = 0; i < sinfo->num_fun; ++i)
    total += sinfo->fun[i].call_count;

  return total;
}

static int
sort_lib (const void *a, const void *b)
{
  asection *const *s1 = (asection *const *) a;
  asection *const *s2 = (asection *const *) b;
  int delta;

  if (s1 == NULL || s2 == NULL)
    return 0;

  delta = total_call_count(*s2) - total_call_count(*s1);

  if (delta != 0)
    return delta;

  if (s1 < s2)
    return -1;
  if (s1 > s2)
    return 1;
  return 0;
}

/* Remove some sections from those marked to be in overlays.  Choose
   those that are called from many places, likely library functions.  */

static unsigned int
auto_ovl_lib_functions (struct bfd_link_info *info, unsigned int lib_size)
{
  bfd *ibfd;
  asection **lib_sections = NULL;
  unsigned int i, lib_count;
  struct _cl_param collect_lib_param;
  struct function_info dummy_caller;
  struct spu_link_hash_table *htab;

  memset (&dummy_caller, 0, sizeof (dummy_caller));
  lib_count = 0;
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
          lib_count += 1;
    }

  {
    unsigned int alloc_pairs = lib_count ? lib_count : 1;
    size_t bytes = (size_t) alloc_pairs * 2 * sizeof (*lib_sections);
    lib_sections = bfd_malloc (bytes);
  }
  if (lib_sections == NULL)
    return (unsigned int) -1;

  collect_lib_param.lib_size = lib_size;
  collect_lib_param.lib_sections = lib_sections;
  if (!for_each_node (collect_lib_sections, info, &collect_lib_param, true))
    {
      free (lib_sections);
      return (unsigned int) -1;
    }
  lib_count = (unsigned int) ((collect_lib_param.lib_sections - lib_sections) / 2);

  if (lib_count > 1)
    qsort (lib_sections, lib_count, 2 * sizeof (*lib_sections), sort_lib);

  htab = spu_hash_table (info);
  for (i = 0; i < lib_count; i++)
    {
      unsigned int tmp;
      unsigned int stub_size = 0;
      asection *sec = lib_sections[2 * i];
      asection *rodata = lib_sections[2 * i + 1];

      tmp = sec->size;
      if (rodata)
        tmp += rodata->size;

      if (tmp < lib_size)
        {
          struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
          struct spu_elf_stack_info *sinfo = sec_data ? sec_data->u.i.stack_info : NULL;

          if (sinfo)
            {
              int k;
              for (k = 0; k < sinfo->num_fun; ++k)
                {
                  struct call_info *call;
                  for (call = sinfo->fun[k].call_list; call; call = call->next)
                    if (call->fun->sec->linker_mark)
                      {
                        struct call_info *p;
                        for (p = dummy_caller.call_list; p; p = p->next)
                          if (p->fun == call->fun)
                            break;
                        if (!p)
                          stub_size += ovl_stub_size (htab->params);
                      }
                }
            }
        }

      if (tmp + stub_size >= lib_size)
        continue;

      {
        struct call_info **pp;
        struct call_info *p;

        sec->linker_mark = 0;
        if (rodata)
          rodata->linker_mark = 0;
        lib_size -= tmp + stub_size;

        pp = &dummy_caller.call_list;
        while ((p = *pp) != NULL)
          if (!p->fun->sec->linker_mark)
            {
              lib_size += ovl_stub_size (htab->params);
              *pp = p->next;
              free (p);
            }
          else
            pp = &p->next;
      }

      {
        struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
        struct spu_elf_stack_info *sinfo = sec_data ? sec_data->u.i.stack_info : NULL;

        if (sinfo)
          {
            int k;
            for (k = 0; k < sinfo->num_fun; ++k)
              {
                struct call_info *call;
                for (call = sinfo->fun[k].call_list; call; call = call->next)
                  if (call->fun->sec->linker_mark)
                    {
                      struct call_info *callee = bfd_malloc (sizeof (*callee));
                      if (callee == NULL)
                        {
                          while (dummy_caller.call_list != NULL)
                            {
                              struct call_info *c = dummy_caller.call_list;
                              dummy_caller.call_list = c->next;
                              free (c);
                            }
                          free (lib_sections);
                          return (unsigned int) -1;
                        }
                      *callee = *call;
                      if (!insert_callee (&dummy_caller, callee))
                        free (callee);
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
    if (lib_sections[i])
      lib_sections[i]->gc_mark = 1;
  free (lib_sections);
  return lib_size;
}

/* Build an array of overlay sections.  The deepest node's section is
   added first, then its parent node's section, then everything called
   from the parent section.  The idea being to group sections to
   minimise calls between different overlays.  */

static bool
collect_overlays(struct function_info *fun,
                 struct bfd_link_info *info,
                 void *param)
{
  struct call_info *call;
  bool added_fun = false;
  asection ***ovly_sections = param;

  (void)info;

  if (fun->visit7)
    return true;

  fun->visit7 = true;

  for (call = fun->call_list; call != NULL; call = call->next)
    if (!call->is_pasted && !call->broken_cycle)
      {
        if (!collect_overlays(call->fun, info, ovly_sections))
          return false;
        break;
      }

  if (fun->sec->linker_mark && fun->sec->gc_mark)
    {
      asection **arr = *ovly_sections;

      fun->sec->gc_mark = 0;
      *arr++ = fun->sec;

      if (fun->rodata && fun->rodata->linker_mark && fun->rodata->gc_mark)
        {
          fun->rodata->gc_mark = 0;
          *arr++ = fun->rodata;
        }
      else
        {
          *arr++ = NULL;
        }

      *ovly_sections = arr;
      added_fun = true;

      if (fun->sec->segment_mark)
        {
          struct function_info *call_fun = fun;
          do
            {
              bool found_pasted = false;
              for (call = call_fun->call_list; call != NULL; call = call->next)
                if (call->is_pasted)
                  {
                    call_fun = call->fun;
                    call_fun->sec->gc_mark = 0;
                    if (call_fun->rodata)
                      call_fun->rodata->gc_mark = 0;
                    found_pasted = true;
                    break;
                  }
              if (!found_pasted)
                abort();
            }
          while (call_fun->sec->segment_mark);
        }
    }

  for (call = fun->call_list; call != NULL; call = call->next)
    if (!call->broken_cycle
        && !collect_overlays(call->fun, info, ovly_sections))
      return false;

  if (added_fun)
    {
      struct _spu_elf_section_data *sec_data = spu_elf_section_data(fun->sec);
      if (sec_data != NULL)
        {
          struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
          if (sinfo != NULL)
            {
              int i;
              for (i = 0; i < sinfo->num_fun; ++i)
                if (!collect_overlays(&sinfo->fun[i], info, ovly_sections))
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
sum_stack (struct function_info *fun,
           struct bfd_link_info *info,
           void *param)
{
  struct call_info *call;
  struct function_info *max;
  size_t cum_stack, child_cum, local_stack;
  const char *f1;
  bool has_call;
  struct _sum_stack_param *sum_stack_param;
  struct spu_link_hash_table *htab;
  char *name;
  size_t name_len;
  struct elf_link_hash_entry *h;
  enum bfd_link_hash_type t;

  if (fun == NULL || info == NULL || param == NULL)
    return false;

  sum_stack_param = param;

  cum_stack = fun->stack;
  sum_stack_param->cum_stack = cum_stack;
  if (fun->visit3)
    return true;

  has_call = false;
  max = NULL;

  for (call = fun->call_list; call; call = call->next)
    {
      if (call->broken_cycle)
        continue;

      if (!call->is_pasted)
        has_call = true;

      if (!sum_stack (call->fun, info, sum_stack_param))
        return false;

      child_cum = sum_stack_param->cum_stack;

      if (!call->is_tail || call->is_pasted || call->fun->start != NULL)
        child_cum += fun->stack;

      if (cum_stack < child_cum)
        {
          cum_stack = child_cum;
          max = call->fun;
        }
    }

  sum_stack_param->cum_stack = cum_stack;
  local_stack = fun->stack;
  fun->stack = cum_stack;
  fun->visit3 = true;

  if (!fun->non_root && sum_stack_param->overall_stack < cum_stack)
    sum_stack_param->overall_stack = cum_stack;

  htab = spu_hash_table (info);
  if (htab && htab->params && htab->params->auto_overlay)
    return true;

  f1 = func_name (fun);

  if (htab && htab->params && htab->params->stack_analysis)
    {
      if (!fun->non_root && info->callbacks && info->callbacks->info)
        info->callbacks->info ("  %s: 0x%v\n", f1, (bfd_vma) cum_stack);

      if (info->callbacks && info->callbacks->minfo)
        {
          info->callbacks->minfo ("%s: 0x%v 0x%v\n",
                                  f1, (bfd_vma) local_stack, (bfd_vma) cum_stack);

          if (has_call)
            {
              info->callbacks->minfo (_("  calls:\n"));
              for (call = fun->call_list; call; call = call->next)
                if (!call->is_pasted && !call->broken_cycle)
                  {
                    const char *f2 = func_name (call->fun);
                    const char *ann1 = call->fun == max ? "*" : " ";
                    const char *ann2 = call->is_tail ? "t" : " ";
                    info->callbacks->minfo ("   %s%s %s\n", ann1, ann2, f2);
                  }
            }
        }
    }

  if (sum_stack_param->emit_stack_syms && htab)
    {
      name_len = 18 + strlen (f1);
      name = bfd_malloc (name_len);
      if (name == NULL)
        return false;

      if (fun->global || ELF_ST_BIND (fun->u.sym->st_info) == STB_GLOBAL)
        (void) snprintf (name, name_len, "__stack_%s", f1);
      else
        (void) snprintf (name, name_len, "__stack_%x_%s",
                         fun->sec->id & 0xffffffff, f1);

      h = elf_link_hash_lookup (&htab->elf, name, true, true, false);
      free (name);

      if (h != NULL)
        {
          t = h->root.type;
          if (t == bfd_link_hash_new
              || t == bfd_link_hash_undefined
              || t == bfd_link_hash_undefweak)
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
        }
    }

  return true;
}

/* SEC is part of a pasted function.  Return the call_info for the
   next section of this function.  */

static struct call_info *
find_pasted_call(asection *sec)
{
  if (sec == NULL)
    abort();

  struct _spu_elf_section_data *sec_data = spu_elf_section_data(sec);
  if (sec_data == NULL)
    abort();

  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  if (sinfo == NULL)
    abort();

  int num_fun = sinfo->num_fun;
  if (num_fun < 0)
    abort();

  if (num_fun > 0 && sinfo->fun == NULL)
    abort();

  for (int k = 0; k < num_fun; ++k)
  {
    struct call_info *call = sinfo->fun[k].call_list;
    for (; call != NULL; call = call->next)
    {
      if (call->is_pasted)
        return call;
    }
  }

  abort();
  return NULL;
}

/* qsort predicate to sort bfds by file name.  */

static int
sort_bfds (const void *a, const void *b)
{
  if (a == b)
    return 0;
  if (a == NULL)
    return -1;
  if (b == NULL)
    return 1;

  bfd *const b1 = *(bfd *const *) a;
  bfd *const b2 = *(bfd *const *) b;

  if (b1 == b2)
    return 0;
  if (b1 == NULL)
    return -1;
  if (b2 == NULL)
    return 1;

  const char *const f1 = bfd_get_filename (b1);
  const char *const f2 = bfd_get_filename (b2);

  if (f1 == f2)
    return 0;
  if (f1 == NULL)
    return -1;
  if (f2 == NULL)
    return 1;

  return filename_cmp (f1, f2);
}

static int print_section_line(FILE *script, asection *sec, struct bfd_link_info *info)
{
  const char *archive = "";
  const char *object;
  const char *name;

  if (script == NULL || info == NULL || sec == NULL || sec->owner == NULL)
    return -1;

  if (sec->owner->my_archive != NULL)
    archive = bfd_get_filename(sec->owner->my_archive);

  object = bfd_get_filename(sec->owner);
  name = (sec->name != NULL) ? sec->name : "";

  if (fprintf(script, "   %s%c%s (%s)\n",
              archive,
              info->path_separator,
              object,
              name) <= 0)
    return -1;

  return 0;
}

static int print_pasted_sections(FILE *script, asection *base_sec, struct bfd_link_info *info, int print_rodata)
{
  struct call_info *call = find_pasted_call(base_sec);

  while (call != NULL)
    {
      struct function_info *call_fun = call->fun;
      asection *sec_to_print = print_rodata ? call_fun->rodata : call_fun->sec;

      if (sec_to_print != NULL)
        {
          if (print_section_line(script, sec_to_print, info) < 0)
            return -1;
        }

      for (call = call_fun->call_list; call; call = call->next)
        if (call->is_pasted)
          break;
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
  unsigned int end;

  for (end = base; end < count && ovly_map[end] == ovlynum; ++end)
    ;

  for (j = base; j < end; ++j)
    {
      asection *sec0 = ovly_sections[2 * j];

      if (print_section_line(script, sec0, info) < 0)
        return (unsigned int) -1;

      if (sec0->segment_mark)
        {
          if (print_pasted_sections(script, sec0, info, 0) < 0)
            return (unsigned int) -1;
        }
    }

  for (j = base; j < end; ++j)
    {
      asection *sec1 = ovly_sections[2 * j + 1];
      asection *sec0 = ovly_sections[2 * j];

      if (sec1 != NULL)
        {
          if (print_section_line(script, sec1, info) < 0)
            return (unsigned int) -1;
        }

      if (sec0->segment_mark)
        {
          if (print_pasted_sections(script, sec0, info, 1) < 0)
            return (unsigned int) -1;
        }
    }

  return end;
}

/* Handle --auto-overlay.  */

static void free_call_list(struct function_info *f)
{
  struct call_info *call;
  if (!f)
    return;
  while ((call = f->call_list) != NULL)
    {
      f->call_list = call->next;
      free (call);
    }
}

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
  asection **ovly_sections = NULL, **ovly_p;
  unsigned int *ovly_map = NULL;
  FILE *script = NULL;
  unsigned int total_overlay_size, overlay_size;
  const char *ovly_mgr_entry;
  struct elf_link_hash_entry *h;
  struct _mos_param mos_param;
  struct _uos_param uos_param;
  struct function_info dummy_caller;

  lo = (unsigned int) -1;
  hi = 0;
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

  if (!discover_functions (info))
    goto err_exit;

  if (!build_call_tree (info))
    goto err_exit;

  htab = spu_hash_table (info);
  if (htab == NULL)
    goto err_exit;

  reserved = htab->params->auto_overlay_reserved;
  if (reserved == 0)
    {
      struct _sum_stack_param sum_stack_param;

      sum_stack_param.emit_stack_syms = 0;
      sum_stack_param.overall_stack = 0;
      if (!for_each_node (sum_stack, info, &sum_stack_param, true))
        goto err_exit;
      reserved = (sum_stack_param.overall_stack
                  + htab->params->extra_stack_space);
    }

  if (fixed_size + reserved <= htab->local_store
      && htab->params->ovly_flavour != ovly_soft_icache)
    {
      htab->params->auto_overlay = 0;
      return;
    }

  uos_param.exclude_input_section = 0;
  uos_param.exclude_output_section
    = bfd_get_section_by_name (info->output_bfd, ".interrupt");

  ovly_mgr_entry = "__ovly_load";
  if (htab->params->ovly_flavour == ovly_soft_icache)
    ovly_mgr_entry = "__icache_br_handler";
  h = elf_link_hash_lookup (&htab->elf, ovly_mgr_entry,
                            false, false, false);
  if (h != NULL
      && (h->root.type == bfd_link_hash_defined
          || h->root.type == bfd_link_hash_defweak)
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
  if ((uos_param.exclude_input_section
       || uos_param.exclude_output_section)
      && !for_each_node (unmark_overlay_section, info, &uos_param, true))
    goto err_exit;

  bfd_count = 0;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    ++bfd_count;

  if (bfd_count)
    {
      bfd_arr = bfd_malloc (bfd_count * sizeof (*bfd_arr));
      if (bfd_arr == NULL)
        goto err_exit;
    }

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
          fixed_size -= sec->size;
      if (count != old_count)
        bfd_arr[bfd_count++] = ibfd;
    }

  if (bfd_count > 1)
    {
      bool ok = true;

      qsort (bfd_arr, bfd_count, sizeof (*bfd_arr), sort_bfds);
      for (i = 1; i < bfd_count; ++i)
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
                ok = false;
              }
          }
      if (!ok)
        {
          info->callbacks->einfo (_("sorry, no support for duplicate "
                                    "object files in auto-overlay script\n"));
          bfd_set_error (bfd_error_bad_value);
          goto err_exit;
        }
    }

  if (bfd_arr)
    {
      free (bfd_arr);
      bfd_arr = NULL;
    }

  fixed_size += reserved;
  fixed_size += htab->non_ovly_stub * ovl_stub_size (htab->params);
  if (fixed_size + mos_param.max_overlay_size <= htab->local_store)
    {
      if (htab->params->ovly_flavour == ovly_soft_icache)
        {
          fixed_size += htab->non_ovly_stub * 16;
          fixed_size += 16 << htab->num_lines_log2;
          fixed_size += 16 << htab->num_lines_log2;
          fixed_size += 16 << (htab->fromelem_size_log2
                               + htab->num_lines_log2);
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
    info->callbacks->einfo (_("non-overlay size of 0x%v plus maximum overlay "
                              "size of 0x%v exceeds local store\n"),
                            (bfd_vma) fixed_size,
                            (bfd_vma) mos_param.max_overlay_size);
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

  memset (&dummy_caller, 0, sizeof (dummy_caller));
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
                  tmp = (align_power (tmp, call_fun->sec->alignment_power)
                         + call_fun->sec->size);
                  if (call_fun->rodata)
                    {
                      rotmp = (align_power (rotmp,
                                            call_fun->rodata->alignment_power)
                               + call_fun->rodata->size);
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
            for (call = sinfo->fun[k].call_list; call; call = call->next)
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
          while (pasty != NULL)
            {
              struct function_info *call_fun = pasty->fun;
              pasty = NULL;
              for (call = call_fun->call_list; call; call = call->next)
                if (call->is_pasted)
                  {
                    BFD_ASSERT (pasty == NULL);
                    pasty = call;
                  }
                else if (!copy_callee (&dummy_caller, call))
                  goto err_exit;
            }

          num_stubs = 0;
          for (call = dummy_caller.call_list; call; call = call->next)
            {
              unsigned int stub_delta = 1;

              if (htab->params->ovly_flavour == ovly_soft_icache)
                stub_delta = call->count;
              num_stubs += stub_delta;

              for (k = base; k < i + 1; k++)
                if (call->fun->sec == ovly_sections[2 * k])
                  {
                    num_stubs -= stub_delta;
                    break;
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

      free_call_list (&dummy_caller);

      ++ovlynum;
      while (base < i)
        ovly_map[base++] = ovlynum;
    }

  script = htab->params->spu_elf_open_overlay_script ();

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
  ovly_map = NULL;
  free (ovly_sections);
  ovly_sections = NULL;

  if (fclose (script) != 0)
    goto file_err;
  script = NULL;

  if (htab->params->auto_overlay & AUTO_RELINK)
    (*htab->params->spu_elf_relink) ();

  xexit (0);

 file_err:
  bfd_set_error (bfd_error_system_call);
 err_exit:
  if (script != NULL)
    fclose (script);
  if (ovly_map != NULL)
    free (ovly_map);
  if (ovly_sections != NULL)
    free (ovly_sections);
  if (bfd_arr != NULL)
    free (bfd_arr);
  free_call_list (&dummy_caller);
  info->callbacks->fatal (_("%P: auto overlay error: %E\n"));
}

/* Provide an estimate of total stack required.  */

static bool
spu_elf_stack_analysis(struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab;
  struct _sum_stack_param sum_stack_param;

  if (info == NULL)
    return false;

  if (!discover_functions(info))
    return false;

  if (!build_call_tree(info))
    return false;

  htab = spu_hash_table(info);
  if (htab && htab->params && htab->params->stack_analysis
      && info->callbacks && info->callbacks->info && info->callbacks->minfo)
    {
      info->callbacks->info (_("Stack size for call graph root nodes.\n"));
      info->callbacks->minfo (_("\nStack size for functions.  "
                                "Annotations: '*' max stack, 't' tail call\n"));
    }

  sum_stack_param.emit_stack_syms = (htab && htab->params) ? htab->params->emit_stack_syms : false;
  sum_stack_param.overall_stack = 0;

  if (!for_each_node(sum_stack, info, &sum_stack_param, true))
    return false;

  if (htab && htab->params && htab->params->stack_analysis
      && info->callbacks && info->callbacks->info)
    info->callbacks->info (_("Maximum stack required is 0x%v\n"),
                           (bfd_vma) sum_stack_param.overall_stack);

  return true;
}

/* Perform a final link.  */

static bool
spu_elf_final_link (bfd *output_bfd, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (htab->params->auto_overlay)
  {
    spu_elf_auto_overlay (info);
  }

  {
    bool need_analysis = htab->params->stack_analysis
                         || (htab->params->ovly_flavour == ovly_soft_icache
                             && htab->params->lrlive_analysis);

    if (need_analysis && !spu_elf_stack_analysis (info))
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
spu_elf_count_relocs(struct bfd_link_info *info, asection *sec)
{
  Elf_Internal_Rela *relocs;
  unsigned int count = 0;

  if (info == NULL || sec == NULL || sec->owner == NULL)
    return 0;

  relocs = _bfd_elf_link_read_relocs(sec->owner, sec, NULL, NULL, info->keep_memory);
  if (relocs == NULL)
    return 0;

  {
    Elf_Internal_Rela *rel = relocs;
    Elf_Internal_Rela *relend = relocs + sec->reloc_count;

    for (; rel < relend; ++rel)
      {
        int r_type = ELF32_R_TYPE(rel->r_info);
        if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
          ++count;
      }
  }

  {
    void *cached = NULL;
    if (elf_section_data(sec))
      cached = elf_section_data(sec)->relocs;
    if (cached != relocs)
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
static void
spu_elf_emit_fixup(bfd *output_bfd, struct bfd_link_info *info, bfd_vma offset)
{
  struct spu_link_hash_table *htab = spu_hash_table(info);
  asection *sfixup = htab->sfixup;
  const bfd_vma align_mask = ~(bfd_vma) 15;
  const bfd_vma qaddr = offset & align_mask;
  const bfd_vma bit = ((bfd_vma) 8) >> (unsigned) ((offset & 15) >> 2);

  if (sfixup->reloc_count == 0)
    {
      FIXUP_PUT(output_bfd, htab, 0, qaddr | bit);
      sfixup->reloc_count = 1;
      return;
    }

  {
    bfd_vma base = FIXUP_GET(output_bfd, htab, sfixup->reloc_count - 1);
    if (qaddr != (base & align_mask))
      {
        bfd_size_type capacity = sfixup->size / FIXUP_RECORD_SIZE;
        if ((bfd_size_type) (sfixup->reloc_count + 1) > capacity)
          _bfd_error_handler(_("fatal error while creating .fixup"));
        FIXUP_PUT(output_bfd, htab, sfixup->reloc_count, qaddr | bit);
        sfixup->reloc_count++;
      }
    else
      {
        FIXUP_PUT(output_bfd, htab, sfixup->reloc_count - 1, base | bit);
      }
  }
}

/* Apply RELOCS to CONTENTS of INPUT_SECTION from INPUT_BFD.  */

static int
spu_elf_relocate_section(bfd *output_bfd,
                         struct bfd_link_info *info,
                         bfd *input_bfd,
                         asection *input_section,
                         bfd_byte *contents,
                         Elf_Internal_Rela *relocs,
                         Elf_Internal_Sym *local_syms,
                         asection **local_sections)
{
  if (output_bfd == NULL || info == NULL || input_bfd == NULL
      || input_section == NULL || contents == NULL
      || relocs == NULL || local_syms == NULL || local_sections == NULL)
    return false;

  Elf_Internal_Shdr *symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes = (struct elf_link_hash_entry **) (elf_sym_hashes(input_bfd));
  struct spu_link_hash_table *htab = spu_hash_table(info);
  const bool have_htab = (htab != NULL);
  const bool stubs = (have_htab && htab->stub_sec != NULL && maybe_needs_stubs(input_section));
  const unsigned int iovl = overlay_index(input_section);
  asection *ea = bfd_get_section_by_name(output_bfd, "._ea");

  Elf_Internal_Rela *rel = relocs;
  Elf_Internal_Rela *relend = relocs + input_section->reloc_count;

  int ret = true;
  bool emit_these_relocs = false;

  for (; rel < relend; ++rel)
    {
      const unsigned int r_symndx = ELF32_R_SYM(rel->r_info);
      const int r_type = ELF32_R_TYPE(rel->r_info);
      reloc_howto_type *howto = elf_howto_table + r_type;

      Elf_Internal_Sym *sym = NULL;
      asection *sec = NULL;
      struct elf_link_hash_entry *h = NULL;
      const char *sym_name = NULL;

      bfd_vma relocation = 0;
      bfd_vma addend = rel->r_addend;

      bool unresolved_reloc = false;

      if (r_symndx < symtab_hdr->sh_info)
        {
          sym = local_syms + r_symndx;
          sec = local_sections[r_symndx];
          sym_name = bfd_elf_sym_name(input_bfd, symtab_hdr, sym, sec);
          relocation = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);
        }
      else
        {
          if (sym_hashes == NULL)
            return false;

          h = sym_hashes[r_symndx - symtab_hdr->sh_info];

          if (info->wrap_hash != NULL && (input_section->flags & SEC_DEBUGGING) != 0)
            h = (struct elf_link_hash_entry *) unwrap_hash_lookup(info, input_bfd, &h->root);

          while (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning)
            h = (struct elf_link_hash_entry *) h->root.u.i.link;

          if (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)
            {
              sec = h->root.u.def.section;
              if (sec == NULL || sec->output_section == NULL)
                unresolved_reloc = true;
              else
                relocation = (h->root.u.def.value
                              + sec->output_section->vma
                              + sec->output_offset);
            }
          else if (h->root.type == bfd_link_hash_undefweak)
            {
            }
          else if (info->unresolved_syms_in_objects == RM_IGNORE
                   && ELF_ST_VISIBILITY(h->other) == STV_DEFAULT)
            {
            }
          else if (!bfd_link_relocatable(info) && !(r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64))
            {
              const bool err = ((info->unresolved_syms_in_objects == RM_DIAGNOSE && !info->warn_unresolved_syms)
                                || ELF_ST_VISIBILITY(h->other) != STV_DEFAULT);
              info->callbacks->undefined_symbol(info, h->root.root.string, input_bfd,
                                                input_section, rel->r_offset, err);
            }

          sym_name = h->root.root.string;
        }

      if (sec != NULL && discarded_section(sec))
        RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section,
                                        rel, 1, relend, R_SPU_NONE, howto, 0, contents);

      if (bfd_link_relocatable(info))
        continue;

      if (r_type == R_SPU_ADD_PIC && h != NULL && !(h->def_regular || ELF_COMMON_DEF_P(h)))
        {
          bfd_byte *loc = contents + rel->r_offset;
          loc[0] = 0x1c;
          loc[1] = 0x00;
          loc[2] &= 0x3f;
        }

      const bool is_ea_sym = (ea != NULL && sec != NULL && sec->output_section == ea);

      if (stubs && !is_ea_sym)
        {
          enum _stub_type stub_type = needs_ovl_stub(h, sym, sec, input_section, rel, contents, info);
          if (stub_type != no_stub)
            {
              unsigned int ovl = 0;
              struct got_entry *g, **head;

              if (stub_type != nonovl_stub)
                ovl = iovl;

              head = (h != NULL) ? &h->got.glist : elf_local_got_ents(input_bfd) + r_symndx;

              for (g = *head; g != NULL; g = g->next)
                {
                  if (have_htab && htab->params && htab->params->ovly_flavour == ovly_soft_icache)
                    {
                      bfd_vma br = (rel->r_offset + input_section->output_offset
                                    + input_section->output_section->vma);
                      if (g->ovl == ovl && g->br_addr == br)
                        break;
                    }
                  else
                    {
                      if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
                        break;
                    }
                }

              if (g == NULL)
                abort();

              relocation = g->stub_addr;
              addend = 0;
            }
        }
      else
        {
          if (have_htab && htab->params && htab->params->ovly_flavour == ovly_soft_icache
              && (r_type == R_SPU_ADDR16_HI || r_type == R_SPU_ADDR32 || r_type == R_SPU_REL32)
              && !is_ea_sym)
            {
              unsigned int ovl = overlay_index(sec);
              if (ovl != 0)
                {
                  unsigned int set_id = ((ovl - 1) >> htab->num_lines_log2) + 1;
                  relocation += (bfd_vma) set_id << 18;
                }
            }
        }

      if (have_htab && htab->params && htab->params->emit_fixups && !bfd_link_relocatable(info)
          && (input_section->flags & SEC_ALLOC) != 0 && r_type == R_SPU_ADDR32)
        {
          bfd_vma offset = rel->r_offset + input_section->output_section->vma + input_section->output_offset;
          spu_elf_emit_fixup(output_bfd, info, offset);
        }

      if (!unresolved_reloc)
        {
          if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
            {
              if (is_ea_sym)
                {
                  rel->r_addend += (relocation - ea->vma + elf_section_data(ea)->this_hdr.sh_offset);
                  rel->r_info = ELF32_R_INFO(0, r_type);
                }
              emit_these_relocs = true;
              continue;
            }
          else if (is_ea_sym)
            {
              unresolved_reloc = true;
            }
        }

      if (unresolved_reloc
          && _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset) != (bfd_vma)-1)
        {
          _bfd_error_handler(_("%pB(%s+%#" PRIx64 "): "
                               "unresolvable %s relocation against symbol `%s'"),
                             input_bfd,
                             bfd_section_name(input_section),
                             (uint64_t) rel->r_offset,
                             howto->name,
                             sym_name);
          ret = false;
        }

      bfd_reloc_status_type r = _bfd_final_link_relocate(howto,
                                                         input_bfd,
                                                         input_section,
                                                         contents,
                                                         rel->r_offset, relocation, addend);

      if (r != bfd_reloc_ok)
        {
          switch (r)
            {
            case bfd_reloc_overflow:
              info->callbacks->reloc_overflow(info, (h ? &h->root : NULL), sym_name, howto->name,
                                              (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
              break;

            case bfd_reloc_undefined:
              info->callbacks->undefined_symbol(info, sym_name, input_bfd, input_section,
                                                rel->r_offset, true);
              break;

            case bfd_reloc_outofrange:
              ret = false;
              info->callbacks->warning(info, _("internal error: out of range error"), sym_name,
                                       input_bfd, input_section, rel->r_offset);
              break;

            case bfd_reloc_notsupported:
              ret = false;
              info->callbacks->warning(info, _("internal error: unsupported relocation error"), sym_name,
                                       input_bfd, input_section, rel->r_offset);
              break;

            case bfd_reloc_dangerous:
              ret = false;
              info->callbacks->warning(info, _("internal error: dangerous error"), sym_name,
                                       input_bfd, input_section, rel->r_offset);
              break;

            default:
              ret = false;
              info->callbacks->warning(info, _("internal error: unknown error"), sym_name,
                                       input_bfd, input_section, rel->r_offset);
              break;
            }
        }
    }

  if (ret && emit_these_relocs && !info->emitrelocations)
    {
      Elf_Internal_Rela *wrel = relocs;
      Elf_Internal_Rela *r = relocs;
      Elf_Internal_Rela *rend = relocs + input_section->reloc_count;

      for (; r < rend; ++r)
        {
          int t = ELF32_R_TYPE(r->r_info);
          if (t == R_SPU_PPU32 || t == R_SPU_PPU64)
            *wrel++ = *r;
        }

      input_section->reloc_count = (bfd_size_type) (wrel - relocs);

      Elf_Internal_Shdr *rel_hdr = _bfd_elf_single_rel_hdr(input_section);
      rel_hdr->sh_size = input_section->reloc_count * rel_hdr->sh_entsize;
      ret = 2;
    }

  return ret;
}

static bool
spu_elf_finish_dynamic_sections (bfd *output_bfd, struct bfd_link_info *info)
{
  (void) output_bfd;
  (void) info;
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
  if (info == NULL || sym == NULL)
    return 1;

  struct spu_link_hash_table *htab = spu_hash_table (info);
  if (htab == NULL)
    return 1;

  if (bfd_link_relocatable (info))
    return 1;

  if (htab->stub_sec == NULL || h == NULL)
    return 1;

  if (!(h->def_regular
        && (h->root.type == bfd_link_hash_defined
            || h->root.type == bfd_link_hash_defweak)))
    return 1;

  if (h->root.root.string == NULL || !startswith (h->root.root.string, "_SPUEAR_"))
    return 1;

  {
    int is_soft_icache = (htab->params != NULL
                          && htab->params->ovly_flavour == ovly_soft_icache);
    struct got_entry *g;

    for (g = h->got.glist; g != NULL; g = g->next)
      {
        int match = is_soft_icache
                    ? (g->br_addr == g->stub_addr)
                    : (g->addend == 0 && g->ovl == 0);

        if (!match)
          continue;

        if (htab->stub_sec[0] == NULL
            || htab->stub_sec[0]->output_section == NULL
            || htab->stub_sec[0]->output_section->owner == NULL)
          break;

        sym->st_shndx = (_bfd_elf_section_from_bfd_section
                         (htab->stub_sec[0]->output_section->owner,
                          htab->stub_sec[0]->output_section));
        sym->st_value = g->stub_addr;
        break;
      }
  }

  return 1;
}

static int spu_plugin = 0;

void spu_elf_plugin(int value)
{
    spu_plugin = value;
}

/* Set ELF header e_type for plugins.  */

static bool
spu_elf_init_file_header(bfd *abfd, struct bfd_link_info *info)
{
  if (abfd == NULL || info == NULL)
    return false;

  if (!_bfd_elf_init_file_header(abfd, info))
    return false;

  if (!spu_plugin)
    return true;

  Elf_Internal_Ehdr *ehdr = elf_elfheader(abfd);
  if (ehdr == NULL)
    return false;

  ehdr->e_type = ET_DYN;
  return true;
}

/* We may add an extra PT_LOAD segment for .toe.  We also need extra
   segments for overlays.  */

static int
spu_elf_additional_program_headers (bfd *abfd, struct bfd_link_info *info)
{
  int extra = 0;
  asection *sec = NULL;
  struct spu_link_hash_table *htab = NULL;

  if (info != NULL)
    {
      htab = spu_hash_table (info);
      if (htab != NULL)
        extra = htab->num_overlays;
    }

  if (extra != 0)
    ++extra;

  if (abfd != NULL)
    {
      sec = bfd_get_section_by_name (abfd, ".toe");
      if (sec != NULL && (sec->flags & SEC_LOAD) != 0)
        ++extra;
    }

  return extra;
}

/* Remove .toe section from other PT_LOAD segments and put it in
   a segment of its own.  Put overlays in separate segments too.  */

static bool section_is_overlay(asection *s, asection *toe)
{
  if (s == toe)
    return true;
  return spu_elf_section_data(s)->u.o.ovl_index != 0;
}

static bool isolate_section_in_load_segment(bfd *abfd, struct elf_segment_map *m, unsigned int i)
{
  struct elf_segment_map *m2;
  bfd_size_type amt;

  if (i + 1 < m->count)
    {
      amt = sizeof(struct elf_segment_map);
      amt += (bfd_size_type)(m->count - (i + 2)) * sizeof(m->sections[0]);
      m2 = bfd_zalloc(abfd, amt);
      if (m2 == NULL)
        return false;
      m2->count = m->count - (i + 1);
      memcpy(m2->sections, m->sections + i + 1, m2->count * sizeof(m->sections[0]));
      m2->p_type = PT_LOAD;
      m2->next = m->next;
      m->next = m2;
    }

  m->count = 1;

  if (i != 0)
    {
      m->count = i;
      amt = sizeof(struct elf_segment_map);
      m2 = bfd_zalloc(abfd, amt);
      if (m2 == NULL)
        return false;
      m2->p_type = PT_LOAD;
      m2->count = 1;
      m2->sections[0] = m->sections[i];
      m2->next = m->next;
      m->next = m2;
    }

  return true;
}

static bool is_overlay_segment(struct elf_segment_map *seg)
{
  return seg->count == 1
         && spu_elf_section_data(seg->sections[0])->u.o.ovl_index != 0;
}

static void sort_overlay_segments_first(bfd *abfd)
{
  struct elf_segment_map **p = &elf_seg_map(abfd);
  struct elf_segment_map *m_overlay = NULL;
  struct elf_segment_map **p_overlay = &m_overlay;
  struct elf_segment_map **first_load = NULL;

  while (*p != NULL)
    {
      if ((*p)->p_type == PT_LOAD)
        {
          if (!first_load)
            first_load = p;
          if (is_overlay_segment(*p))
            {
              struct elf_segment_map *m = *p;
              m->no_sort_lma = 1;
              *p = m->next;
              *p_overlay = m;
              p_overlay = &m->next;
              continue;
            }
        }
      p = &(*p)->next;
    }

  if (m_overlay != NULL)
    {
      p = first_load;
      if (*p != NULL && (*p)->p_type == PT_LOAD && (*p)->includes_filehdr)
        p = &(*p)->next;
      *p_overlay = *p;
      *p = m_overlay;
    }
}

static bool
spu_elf_modify_segment_map (bfd *abfd, struct bfd_link_info *info)
{
  struct elf_segment_map *m;
  asection *toe;
  unsigned int i;

  if (info == NULL)
    return true;

  toe = bfd_get_section_by_name (abfd, ".toe");

  for (m = elf_seg_map (abfd); m != NULL; m = m->next)
    {
      if (m->p_type != PT_LOAD || m->count <= 1)
        continue;

      for (i = 0; i < m->count; i++)
        {
          asection *sec = m->sections[i];
          if (section_is_overlay (sec, toe))
            {
              if (!isolate_section_in_load_segment (abfd, m, i))
                return false;
              break;
            }
        }
    }

  sort_overlay_segments_first (abfd);

  return true;
}

/* Tweak the section type of .note.spu_name.  */

static bool
spu_elf_fake_sections (bfd *obfd ATTRIBUTE_UNUSED,
                       Elf_Internal_Shdr *hdr,
                       asection *sec)
{
  if (hdr != NULL && sec != NULL && sec->name != NULL)
  {
    if (strcmp (sec->name, SPU_PTNOTE_SPUNAME) == 0)
    {
      hdr->sh_type = SHT_NOTE;
    }
  }
  return true;
}

/* Tweak phdrs before writing them out.  */

static bool
spu_elf_modify_headers (bfd *abfd, struct bfd_link_info *info)
{
  if (info != NULL)
    {
      const struct elf_backend_data *bed = get_elf_backend_data (abfd);
      struct elf_obj_tdata *tdata = elf_tdata (abfd);
      struct spu_link_hash_table *htab = spu_hash_table (info);

      if (bed != NULL && bed->s != NULL && tdata != NULL && tdata->phdr != NULL && htab != NULL)
        {
          Elf_Internal_Phdr *phdr = tdata->phdr;
          unsigned int count = elf_program_header_size (abfd) / bed->s->sizeof_phdr;

          if (htab->num_overlays != 0)
            {
              struct elf_segment_map *m = elf_seg_map (abfd);
              unsigned int i = 0;

              for (; m != NULL; m = m->next, ++i)
                {
                  if (m->count != 0)
                    {
                      unsigned int o = 0;
                      if (m->sections != NULL && m->sections[0] != NULL)
                        o = spu_elf_section_data (m->sections[0])->u.o.ovl_index;

                      if (o != 0 && i < count)
                        {
                          phdr[i].p_flags |= PF_OVERLAY;

                          if (htab->ovtab != NULL
                              && htab->ovtab->size != 0
                              && htab->params != NULL
                              && htab->params->ovly_flavour != ovly_soft_icache)
                            {
                              bfd_byte *p = htab->ovtab->contents;
                              unsigned int off = o * 16 + 8;
                              bfd_put_32 (htab->ovtab->owner, phdr[i].p_offset, p + off);
                            }
                        }
                    }
                }

              if (htab->init != NULL && htab->init->size != 0 && htab->ovl_sec != NULL && htab->ovl_sec[0] != NULL)
                {
                  bfd_vma val = elf_section_data (htab->ovl_sec[0])->this_hdr.sh_offset;
                  bfd_put_32 (htab->init->owner, val, htab->init->contents + 4);
                }
            }

          {
            Elf_Internal_Phdr *last = NULL;
            bool can_adjust = true;

            for (int j = (int) count - 1; j >= 0; --j)
              {
                if (phdr[j].p_type != PT_LOAD)
                  continue;

                unsigned adjust = (unsigned) (-phdr[j].p_filesz) & 15;
                if (adjust != 0
                    && last != NULL
                    && (phdr[j].p_offset + phdr[j].p_filesz > last->p_offset - adjust))
                  {
                    can_adjust = false;
                    break;
                  }

                adjust = (unsigned) (-phdr[j].p_memsz) & 15;
                if (adjust != 0
                    && last != NULL
                    && phdr[j].p_filesz != 0
                    && phdr[j].p_vaddr + phdr[j].p_memsz > last->p_vaddr - adjust
                    && phdr[j].p_vaddr + phdr[j].p_memsz <= last->p_vaddr)
                  {
                    can_adjust = false;
                    break;
                  }

                if (phdr[j].p_filesz != 0)
                  last = &phdr[j];
              }

            if (can_adjust)
              {
                for (int j = (int) count - 1; j >= 0; --j)
                  {
                    if (phdr[j].p_type == PT_LOAD)
                      {
                        unsigned adjust = (unsigned) (-phdr[j].p_filesz) & 15;
                        phdr[j].p_filesz += adjust;

                        adjust = (unsigned) (-phdr[j].p_memsz) & 15;
                        phdr[j].p_memsz += adjust;
                      }
                  }
              }
          }
        }
    }

  return _bfd_elf_modify_headers (abfd, info);
}

bool
spu_elf_size_sections (bfd *obfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab;
  asection *sfixup;
  size_t fixup_count = 0;
  bfd *ibfd;
  size_t size;

  if (info == NULL)
    return false;

  htab = spu_hash_table (info);
  if (htab == NULL || htab->params == NULL)
    return false;

  if (!htab->params->emit_fixups)
    return true;

  sfixup = htab->sfixup;
  if (sfixup == NULL)
    return false;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      asection *isec;
      Elf_Internal_Rela *internal_relocs;

      if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour)
        continue;

      for (isec = ibfd->sections; isec != NULL; isec = isec->next)
        {
          Elf_Internal_Rela *irela, *irelaend;
          bfd_vma base_end;

          if ((isec->flags & SEC_ALLOC) == 0
              || (isec->flags & SEC_RELOC) == 0
              || isec->reloc_count == 0)
            continue;

          internal_relocs =
            _bfd_elf_link_read_relocs (ibfd, isec, NULL, NULL,
                                       info->keep_memory);
          if (internal_relocs == NULL)
            return false;

          irela = internal_relocs;
          irelaend = irela + isec->reloc_count;
          base_end = 0;

          for (; irela < irelaend; irela++)
            {
              if (ELF32_R_TYPE (irela->r_info) == R_SPU_ADDR32
                  && irela->r_offset >= base_end)
                {
                  base_end = (irela->r_offset & ~(bfd_vma) 15) + 16;
                  fixup_count++;
                }
            }

          if (!info->keep_memory)
            free (internal_relocs);
        }
    }

  {
    size_t nrecs = fixup_count + 1;

    if (nrecs < fixup_count)
      return false;

    if (nrecs > ((size_t) -1) / FIXUP_RECORD_SIZE)
      return false;

    size = nrecs * FIXUP_RECORD_SIZE;
  }

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
