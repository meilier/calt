#ifndef BLOM_H
#define BLOM_H


#include <string>

#include "breep/network/tcp.hpp"

#define LAMDA 15

namespace blom {
//the generation of blom info, the calculation of blom key, and setup newblom 

    class Blom_Master{
    //选出p g产生矩阵G
    //分配编号及该编号对应的节点
    public:
        Blom_Master() {};
        ~Blom_Master() {};
        bool new_blom(char *out_msg);
        bool get_A_num(int* numtr, long long Atr[], int size, char *out_msg);   //获得编号及对应的行
        void get_g_p(int *ptr, int *gtr);       //获得p和g的值
    private:
        bool MillerRobinTest(int n, int iteration, bool& result, char *out_msg);    //判断n是否为素数，iteration迭代次数
        int primitiveroot(int q, char *out_msg);  //计算素数q的生成元
        void creatematrix_D();  //计算私密矩阵D
        bool pick_p_and_g(char *out_msg); //p=prime, g=generator

        int p; //素数
        int g; //素数p的生成元g
        long long D[LAMDA+1][LAMDA+1];    //矩阵D
        int num;    //下一个要分配的节点编号
    };


    class Blom_Node{
    public:
        Blom_Node() {};
        ~Blom_Node() {};
        void set_p_and_g(int p1, int g1);
        bool set_A_num(int n1, long long Atr[], int size, char *out_msg);
        long long calculate_sum(int j, char *out_msg);  //j为对方节点的编号
    private:
        int p; //素数
        int g; //素数p的生成元g
        int n = -1;            //节点的编号
        long long A[LAMDA+1];     //节点的行向量
        long long sum;
    };

    class Blom_general {
    public:
        Blom_general() {};
        ~Blom_general() {};
        static std::string GetKey(std::string src);
        static bool setup_blom(breep::tcp::peer_manager& peer_manager, char *out_msg);
    };


}

#endif  //BLOM_H