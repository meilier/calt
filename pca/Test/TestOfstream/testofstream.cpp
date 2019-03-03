#include <fstream>
#include <iostream>
using namespace std;
int main()
{
    std::ofstream file1;
    std::ofstream file2;
    file1.open("/Users/xingweizheng/why1.txt",std::ios::out | std::ios::trunc);
    file2.open("/Users/xingweizheng/why2.txt",std::ios::out);
    file1.close();
    file2.close();

}