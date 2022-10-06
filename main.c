#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "./vrn_elf.h"
#include "./elf_funcs.h"

#define EHDR_SIZE 64

void usage(char *program) {
  fprintf(stderr, "Usage: %s <elf file>\n", program);
}

//TODO: Change all functions that use FP to use FP as first arg
void note_to_load(FILE *fp) {
  unsigned int perms = 7; 
  unsigned int type = 4;
  unsigned long long vaddr = 0xc0c0c0c0;

  fseek(fp, -56, SEEK_CUR);
  fwrite(&type, sizeof(type), 1, fp);
  fwrite(&perms, sizeof(perms), 1, fp);
  fseek(fp, 8, SEEK_CUR);
  fwrite(&vaddr, sizeof(vaddr), 1, fp);
  fseek(fp, 32, SEEK_CUR);

  return;
}

// TODO: Create an "ELF" struct that stores the results of these functions
void parse_elf(FILE *fp) {
  struct Elf_File *elf_file;
  Elf64_Ehdr *ehdr;
  int note_count = 0;

  ehdr = malloc(sizeof(*ehdr));

  parse_elf_header(fp, ehdr);

  unsigned short phdr_count = ehdr->e_phnum;
  Elf64_Phdr *phdr = malloc(phdr_count * sizeof(*phdr));

  printf("\n[+] Program Headers\n");
  for (int i = 0; i < phdr_count; i++) {
    parse_program_header(fp, &phdr[i]);

    if (phdr[i].p_type == 4 && note_count == 0) {
      note_count++;
      note_to_load(fp);
    }
  }

  //printf("\n\nEntry point is: %X\n\n", ehdr->e_entry);

  free(ehdr);
  free(phdr);

  return;
}

int check_modes(struct stat stats) {
  // TODO: Figure out why write only works when the file is globally writeable
  if (stats.st_mode & R_OK && stats.st_mode & W_OK && stats.st_mode & X_OK) {
    return 1;
  }

  return 0;
}

void exit_on_error(char *err, FILE *fp) {
  fprintf(stderr, "%s\n", err);
  fprintf(stderr, "Closing ELF file...\n");
  fclose(fp);
  exit(1); 
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    usage(argv[0]);
    exit(1);
  }
  char *elf_file = argv[1];
  struct stat stats;
  FILE *fp;
  
  if (stat(elf_file, &stats) == 0) {
    printf("[+] Opened file. Parsing ELF...");

    if (!check_modes(stats)) {
      fprintf(stderr, "File must be readable, writeable, and executable. Exiting...\n");
      exit(1);
    }

    fp = fopen(elf_file, "r+b");
    if (fp == NULL) {
      char *fp_err = "Could not open file: %s\n", elf_file;
      exit_on_error(fp_err, fp);
    }

    parse_elf(fp);
  }

  fclose(fp);
  printf("[+] Closing %s and exiting...\n", elf_file);
  return 0;
}
