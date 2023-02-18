#include <stdio.h>
#include <limits.h>
int main(){
    printf("sizeof(short int)    =%zu\n", sizeof(short int));
    printf("sizeof(int)          =%zu\n", sizeof(int));
    printf("sizeof(long int)     =%zu\n", sizeof(long int));
    printf("sizeof(long long int)=%zu\n", sizeof(long long int));
    printf("INT_MAX              =%i\n", INT_MAX);
    printf("sizeof(size_t)       =%zu\n", sizeof(size_t));
    return 0;

}
