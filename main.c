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

// TODO: Create an "ELF" struct that stores the results of these functions
void parse_elf(FILE *fp) {
  struct Elf_File *elf_file;
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr[11];

  ehdr = malloc(sizeof(*ehdr));
  phdr[11] = malloc(sizeof(*phdr) * 11);

  parse_elf_header(fp, ehdr);

  //int phdrs = ehdr->e_phnum;
  //num_phdrs(phdrs);

  parse_program_header(fp, *phdr);

  free(ehdr);
  free(*phdr);

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
    printf("Opened file. Parsing ELF...\n");

    if (check_modes(stats)) {
      printf("Permissions are good!\n");
    }
    else {
      fprintf(stderr, "File must be readable, writeable, and executable. Exiting...\n");
      exit(1);
    }

    fp = fopen(elf_file, "r+b");
    if (fp == NULL) {
      char *fp_err = "Could not open file: %s\n", elf_file;
      exit_on_error(fp_err, fp);
    }
    printf("Opened file\n");

    parse_elf(fp);
  }

  fclose(fp);
  printf("Closing %s and exiting...\n", elf_file);
  return 0;
}
