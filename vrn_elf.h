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
