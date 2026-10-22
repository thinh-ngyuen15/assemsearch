#include <stdlib.h>
int puts(const char *);

__attribute__((noinline)) int dispatch(int op, int value) {
    switch (op) {  /* dense cases: compiled to a jump table */
    case 0: return value + 11;
    case 1: return value * 7;
    case 2: return value - 3;
    case 3: puts("three"); return value ^ 5;
    case 4: return value << 2;
    case 5: puts("five"); return value / 9;
    default: return -1;
    }
}

__attribute__((noinline)) int checked(int value) {
    if (value < 0)
        abort();  /* never returns */
    return value * 2;
}

int main(int argc, char **argv) {
    (void)argv;
    return dispatch(argc, 3) + checked(argc);
}
