#include <stdlib.h>

// function for randomization
int rand_comparison(const void *a, const void *b)
{
    (void)a;
    (void)b;

    return rand() % 2 ? +1 : -1;
    ;
}
// added seed for randomizaiton (no secure random function)
void shuffle(void *base, size_t nmemb, size_t size)
{
    qsort(base, nmemb, size, rand_comparison);
}
// final randomfunction 
static char *random_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    int i, n;
    n = 0;

    for (i = 0; n < size; n++)
    {
        shuffle(charset, (int)(sizeof charset), sizeof(char));
        printf("%d\n", rand() % (int)(sizeof charset - 1));
        int key = rand() % (int)(sizeof charset - 1);
        str[n] = charset[key];
    }

    str[size] = '\0';

    return str;
}