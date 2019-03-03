#include "cert.hpp"
#include "client.hpp"
#include <unistd.h>
#include <stdlib.h>

#define WORKDIR "/Users/xingweizheng/github/pca"
int main()
{
    setup();
    sleep(6);
    enqueueST();
    while (1)
    {
        sleep(1);
    }
}