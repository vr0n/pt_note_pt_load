// Helper functions for the project

/*
  Simple colorful logging functions
*/
void log_msg(char *log) {
  fprintf(stdout, "\033[0;34m[+] %s\n\033[0m", log);
}

void log_err(char *log) {
  fprintf(stderr, "\033[0;31m[+] %s\n\033[0m", log);
  exit(1); 
}

void exit_on_error(FILE *fp, char *err) {
  fprintf(stderr, "\033[0;31m[-] %s\n", err);
  fprintf(stderr, "\033[0;31m[-] Closing ELF file...\n\033[0m");
  fclose(fp);
  exit(1); 
}

/*
  Usage function
*/
void usage(char *program) {
  fprintf(stderr, "Usage: %s [OPTION]... [BINARY]\n\n", program);
  fprintf(stderr, "A tool that can infect or enumerate an ELF binary (sometimes).\n");
  fprintf(stderr, "    -i, --infect        Infect the binary using the PT_NOTE->PT_LOAD method\n");
  fprintf(stderr, "    -p, --parse         Default. Gather and display information about the target binary\n");
  exit(1);
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
