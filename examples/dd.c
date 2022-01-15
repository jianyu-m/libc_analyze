
#include <stdio.h>
#include <sys/mman.h>
void *mem;

int do_two(int a) {
    int sum = 0;
    for (int i = 0; i < a; i++)
    {
        sum += (i * (i + 1));
    }
    return sum;
}

int do_three(int a) {
    int sum = 0;
    for (int i = 0; i < a; i++)
    {
        sum += (i * (i + 1));
    }
    mem = mmap(NULL, 4096, PROT_READ,
                       MAP_PRIVATE, 0, 0);
    return sum;
}

int do_one(int a, int b) {
    int i = do_two(a);
    if (a > 10)
        return i + do_three(b);
    return i;
}

int main() {
    printf("%d\n", do_one(10, 200));
}