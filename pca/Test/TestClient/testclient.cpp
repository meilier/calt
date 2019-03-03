#include "cert.hpp"
#include <stdlib.h>

#define WORKDIR "/Users/xingweizheng/github/pca"
int main()
{
    FILE *fp;
    char buf[1024];
    //call setup.sh
    string signCmd = "sh " + string(WORKDIR) + "/Scripts/client.sh";
    //Todo: error handling
    printf("hello world client\n");
    if ((fp = popen(signCmd.c_str(), "w")) == NULL)
    {
        printf("failed to popen");
    }else{
        printf("It's OK!\n");
    }
    fp == NULL ? printf("yes"):printf("no");
    while (fgets(buf, 200, fp) != NULL)
    {
        printf("%s\n", buf);
    }
    pclose(fp);
    return 0;
}