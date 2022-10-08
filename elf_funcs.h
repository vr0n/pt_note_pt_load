#define EI_NIDENT 16 // Byte length of the ELF magic

typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned short Elf64_Half;      // 2 bytes
typedef signed short Elf64_SHalf;       // 2 bytes
typedef unsigned long long Elf64_Off;   // 8 bytes
typedef unsigned int Elf64_Word;        // 4 bytes
typedef signed int Elf64_SWord;         // 4 bytes
typedef unsigned long long Elf64_Xword; // 8 bytes
typedef signed long long Elf64_SXword;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes

typedef struct {
  unsigned char e_ident[EI_NIDENT]; // 16 bytes: To capture the ELF magic
  Elf64_Half e_type;      // 2 bytes: Object file type
  Elf64_Half e_machine;   // 2 bytes: Machine type
  Elf64_Word e_version;   // 4 bytes: Object file version
  Elf64_Addr e_entry;     // 8 bytes: Entry point address
  Elf64_Off e_phoff;      // 8 bytes: Program header offset
  Elf64_Off e_shoff;      // 8 bytes: Section header offset
  Elf64_Word e_flags;     // 4 bytes: Processor specific flags
  Elf64_Half e_ehsize;    // 2 bytes: Elf header size
  Elf64_Half e_phentsize; // 2 bytes: Size of program header entry
  Elf64_Half e_phnum;     // 2 bytes: Number of program header entries
  Elf64_Half e_shentsize; // 2 bytes: Size of section header entry
  Elf64_Half e_shnum;     // 2 bytes: Number of section header entries
  Elf64_Half e_shstrndx;  // 2 bytes: Section name string table index
} Elf64_Ehdr; // 64 bytes

typedef struct {
  Elf64_Word p_type;    // 4 bytes: Segment type
  Elf64_Word p_flags;   // 4 bytes: Segment flags
  Elf64_Off p_offset;   // 8 bytes: Offset of this segment from start of file
  Elf64_Addr p_vaddr;   // 8 bytes: Address in memory
  Elf64_Addr p_paddr;   // 8 bytes: For physical addressing systems
  Elf64_Xword p_filesz; // 8 bytes: File image size of this segment
  Elf64_Xword p_memsz;  // 8 bytes: Memory image size of this segment
  Elf64_Xword p_align;  // 8 bytes: Alginment constraint of this segment
} Elf64_Phdr; // 56 bytes

typedef struct {
} Elf64_Shdr;

typedef struct {
} Elf64_Sec;

typedef struct {
} Elf64_Seg;

typedef struct Elf_File {
  FILE  *binary; // Pointer to FILE that is our open ELF binary
  Elf64_Ehdr elf_header; // 64 bytes: Header
  Elf64_Phdr prog_headers[13]; // 56 bytes each: Array of program headers
} Elf_File;

char* map_phdr_types(unsigned int type) {
  char* phdr_type;

  switch(type) {
    case 1: phdr_type = "LOAD\t";
            break;
    case 2: phdr_type = "DYNAMIC\t";
            break;
    case 3: phdr_type = "INTERP\t";
            break;
    case 4: phdr_type = "NOTE\t";
            break;
    case 5: phdr_type = "NOTE\t";
            break;
    case 6: phdr_type = "PHDR\t";
            break;
    case 1685382480: phdr_type = "GNU_EH_FRAME";
            break;
    case 1685382481: phdr_type = "GNU_STACK";
            break;
    case 1685382482: phdr_type = "GNU_RELRO";
            break;
    case 1685382483: phdr_type = "GNU_PROPERTY";
            break;
    default: phdr_type = "UKNOWN\t";
  }

  return phdr_type;
}

char* map_perms(unsigned int perms) {
  char* phdr_perms;

  switch(perms) {
    case 1: phdr_perms = "--X";
            break;
    case 2: phdr_perms = "-W-";
            break;
    case 3: phdr_perms = "-WX";
            break;
    case 4: phdr_perms = "R--";
            break;
    case 5: phdr_perms = "R-X";
            break;
    case 6: phdr_perms = "RW-";
            break;
    case 7: phdr_perms = "RWX";
            break;
    default: phdr_perms = "UNKOWN";
  }

  return phdr_perms;
}

void print_elf_header(Elf64_Ehdr *ehdr) {
  printf("Magic:\t");
  for (int i = 0; i < EI_NIDENT; i++) {
    printf("%.2x ", ehdr->e_ident[i]);
  }

  printf("\nType:\t %u\t\t\t\t", ehdr->e_type);
  printf("Machine:\t%u\n", ehdr->e_machine);
  printf("Version: %u\t\t\t\t", (unsigned short)(ehdr->e_version));
  printf("Entry Address:\t0x%.08llx\n", ehdr->e_entry);
  printf("Program Header Offset:\t0x%0.8llx\t", ehdr->e_phoff);
  printf("Section Header Offset:\t0x%0.8llx\n", ehdr->e_shoff);
  printf("Flags:\t %u\t\t\t\t", (unsigned short)(ehdr->e_flags));
  printf("Elf Header Size:\t%u\n", (unsigned short)(ehdr->e_ehsize));
  printf("Program Header Size:\t%u\t\t", (unsigned short)(ehdr->e_phentsize));
  printf("Program Headers:\t%u\n", (unsigned short)(ehdr->e_phnum));
  printf("Section Header Size:\t%u\t\t", (unsigned short)(ehdr->e_shentsize));
  printf("Section Headers:\t%u\n", (unsigned short)(ehdr->e_shnum));
  printf("String Table Index:\t%u\n\n", (unsigned short)(ehdr->e_shstrndx));
}

/*
  Parse the Elf Header
*/
// TODO: do the text formatting in a sane way
unsigned long long parse_elf_header(FILE *fp, Elf64_Ehdr *ehdr) {
  fread(ehdr->e_ident,      EI_NIDENT,                 1, fp);
  fread(&ehdr->e_type,      sizeof(ehdr->e_type),      1, fp);
  fread(&ehdr->e_machine,   sizeof(ehdr->e_machine),   1, fp);
  fread(&ehdr->e_version,   sizeof(ehdr->e_version),   1, fp);
  fread(&ehdr->e_entry,     sizeof(ehdr->e_entry),     1, fp);
  fread(&ehdr->e_phoff,     sizeof(ehdr->e_phoff),     1, fp);
  fread(&ehdr->e_shoff,     sizeof(ehdr->e_shoff),     1, fp);
  fread(&ehdr->e_flags,     sizeof(ehdr->e_flags),     1, fp);
  fread(&ehdr->e_ehsize,    sizeof(ehdr->e_ehsize),    1, fp);
  fread(&ehdr->e_phentsize, sizeof(ehdr->e_phentsize), 1, fp);
  fread(&ehdr->e_phnum,     sizeof(ehdr->e_phnum),     1, fp);
  fread(&ehdr->e_shentsize, sizeof(ehdr->e_shentsize), 1, fp);
  fread(&ehdr->e_shnum,     sizeof(ehdr->e_shnum),     1, fp);
  fread(&ehdr->e_shstrndx,  sizeof(ehdr->e_shstrndx),  1, fp);

  return ehdr->e_entry;
}

void print_program_header(Elf64_Phdr *phdr) {
  printf("Type:\t%s\t",         map_phdr_types(phdr->p_type));
  printf("Perms:\t%s\t\t",      map_perms(phdr->p_flags));
  printf("Offset:\t0x%0.8x\t",  phdr->p_offset);
  printf("Vaddr:\t0x%0.8x\n",   phdr->p_vaddr);
  printf("Paddr:\t0x%0.8x\t",   phdr->p_paddr);
  printf("Filesz:\t0x%0.8x\t",  phdr->p_filesz);
  printf("Memsz:\t0x%0.8x\t",   phdr->p_memsz);
  printf("Align:\t0x%0.8x\n\n", phdr->p_align);
}

void parse_program_header(FILE *fp, Elf64_Phdr *phdr) {
  fread(&phdr->p_type,   sizeof(phdr->p_type),   1, fp);
  fread(&phdr->p_flags,  sizeof(phdr->p_flags),  1, fp);
  fread(&phdr->p_offset, sizeof(phdr->p_offset), 1, fp);
  fread(&phdr->p_vaddr,  sizeof(phdr->p_vaddr),  1, fp);
  fread(&phdr->p_paddr,  sizeof(phdr->p_paddr),  1, fp);
  fread(&phdr->p_filesz, sizeof(phdr->p_filesz), 1, fp);
  fread(&phdr->p_memsz,  sizeof(phdr->p_memsz),  1, fp);
  fread(&phdr->p_align,  sizeof(phdr->p_align),  1, fp);
}
