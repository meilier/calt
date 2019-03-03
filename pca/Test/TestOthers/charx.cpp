#include "cert.hpp"
#include <stdlib.h>

int main()
{
    char buf[1024] = "fdsf";
    if(string(buf)=="fdsf"){
        printf("yes\n");
    }else{
        printf("nop\n");
    }

    printf("hello world\n");

    return 0;
}