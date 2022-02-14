/*
  Parse the Elf Header
*/
void parse_elf_header(FILE *fp, Elf64_Ehdr *ehdr) {
  printf("AAAAAAA\n");
  fread(ehdr->e_ident, 16, 1, fp);
  printf("\nMagic: ");
  for (int i = 0; i < EI_NIDENT; i++) {
    printf("%.2x ", ehdr->e_ident[i]);
  }

  fread(&ehdr->e_type, sizeof(ehdr->e_type), 1, fp);
  printf("\nType: %u\n", ehdr->e_type);

  fread(&ehdr->e_machine, sizeof(ehdr->e_machine), 1, fp);
  printf("Machine: %u\n", ehdr->e_machine);

  fread(&ehdr->e_version, sizeof(ehdr->e_version), 1, fp);
  printf("Version: %u\n", (unsigned short)(ehdr->e_version));

  fread(&ehdr->e_entry, sizeof(ehdr->e_entry), 1, fp);
  printf("Entry Address: 0x%.08llx\n", ehdr->e_entry);

  fread(&ehdr->e_phoff, sizeof(ehdr->e_phoff), 1, fp);
  printf("Program Header Offset: 0x%0.8llx\n", ehdr->e_phoff);

  fread(&ehdr->e_shoff, sizeof(ehdr->e_shoff), 1, fp);
  printf("Section Header Offset: 0x%0.8llx\n", ehdr->e_shoff);

  fread(&ehdr->e_flags, sizeof(ehdr->e_flags), 1, fp);
  printf("Flags: %u\n", (unsigned short)(ehdr->e_flags));

  fread(&ehdr->e_ehsize, sizeof(ehdr->e_ehsize), 1, fp);
  printf("Elf Header Size: %u\n", (unsigned short)(ehdr->e_ehsize));

  fread(&ehdr->e_phentsize, sizeof(ehdr->e_phentsize), 1, fp);
  printf("Program Header Size: %u\n", (unsigned short)(ehdr->e_phentsize));

  fread(&ehdr->e_phnum, sizeof(ehdr->e_phnum), 1, fp);
  printf("Program Headers: %u\n", (unsigned short)(ehdr->e_phnum));

  fread(&ehdr->e_shentsize, sizeof(ehdr->e_shentsize), 1, fp);
  printf("Section Header Size: %u\n", (unsigned short)(ehdr->e_shentsize));

  fread(&ehdr->e_shnum, sizeof(ehdr->e_shnum), 1, fp);
  printf("Section Headers: %u\n", (unsigned short)(ehdr->e_shnum));

  fread(&ehdr->e_shstrndx, sizeof(ehdr->e_shstrndx), 1, fp);
  printf("String Table Index: %u\n\n", (unsigned short)(ehdr->e_shstrndx));
}

void parse_program_header(FILE *fp, Elf64_Phdr *phdr) {
}
