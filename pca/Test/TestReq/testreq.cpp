#include "cert.hpp"
#include <stdlib.h>

#define WORKDIR "/Users/xingweizheng/github/pca"
int main()
{
    FILE *fp;
    char buf[1024];
    string cc;
    int count = 0;
    string fule = "fulea xingweizheng";
    //call setup.sh
    string signCmd = " openssl req -in /Users/xingweizheng/testrsa/requests/account/accountCert1.csr -noout -text |grep Subject:| awk  '{print $4}'|awk -F= '{print $2}'";
    //Todo: error handling
    printf("hello world\n");
    if ((fp = popen(signCmd.c_str(), "r")) == NULL)
    {
        printf("failed to popen");
    }else{
        printf("It's OK!\n");
    }
    fp == NULL ? printf("yes\n"):printf("no\n");
    while (fgets(buf, 200, fp) != NULL)
    {
        printf("buf is %s\n", buf);
    }
    pclose(fp);

    for(int i = 0;i < 1024;i++){
        if(buf[i] == ',')
            break;
        printf("%c num is %d\n",buf[i],buf[i]);
        cc+= buf[i];
        count++;
    }
    string mytest(buf);
    //mytest.copy(buf,)
    mytest += "kaka\n";
    cc = cc.append("whya\n");
    printf("hello world233\n");
    printf("weizhengmene #",cc.c_str());
    printf(mytest.c_str());
    //printf("hello world fulea\n");
    return 0;
}