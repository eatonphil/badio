#include <stdio.h>
#include <string.h>

int main() {
    const char *filename = "test.txt";
    const char *text = "some great stuff";

    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Error opening file\n");
        return 1;
    }

    if (fwrite(text, 1, strlen(text), file) != strlen(text)) {
        perror("Error writing to file\n");
        fclose(file);
        return 1;
    }

    fclose(file);

    unsigned long long i = -5;
    printf("%llu\n", i);
    return 0;
}
