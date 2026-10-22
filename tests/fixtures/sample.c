int puts(const char *); int printf(const char *, ...);
int strcmp(const char *, const char *);

const char *secret_key = "AsmSearchSecretKey";
static const char banner[] = "Welcome to the sample binary";
unsigned int magic_number = 0xDEADBEEF;

int compute_checksum(const char *s) {
    int sum = 0;
    while (*s) sum = sum * 31 + *s++;
    return sum;
}

int validate_license(const char *key) {
    if (strcmp(key, secret_key) == 0) return 1;
    return compute_checksum(key) == 42;
}

void print_banner(void) {
    puts(banner);
}

int main(int argc, char **argv) {
    print_banner();
    if (argc > 1 && validate_license(argv[1])) {
        printf("License OK: %u\n", magic_number);
        return 0;
    }
    printf("Invalid license\n");
    return 1;
}
