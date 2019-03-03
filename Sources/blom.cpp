#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <openssl/md5.h>
#include <map>

#include "blom.h"
#include "common.h"


#define STACK_SIZE 10000
#define LARGE 999999
#define MAX_ITERATION 20
#define PRINT_BLOM false


namespace blom {

    typedef struct{
        int top;
        char c[STACK_SIZE];
    } stack;
    stack s;



    bool decimal_to_binary(int n, char str[], char *out_msg)
    {
        // n is the given decimal integer.
        // Purpose is to find the binary conversion
        // of n.
        // Initialise the stack.
        // 十进制转二进制
        int r;
        s.top = 0;
        while(n != 0)
        {
            r = n % 2;
            s.top++;
            if(s.top >= STACK_SIZE)
            {
                sprintf(out_msg, "!!!stack overflown!!!\n");
                return false;
            }
            s.c[s.top] = r + 48;
            if(PRINT_BLOM);
                //printf("\n s.c[%d]= %c\n", s.top, s.c[s.top]);
            n = n / 2;
        }
        while(s.top)
        {
            *str++ = s.c[s.top--];
        }
        *str='\0';
        return true;
    }

    void reverse_string(char x[])
    {
        int n = strlen(x)-1;
        int i = 0;
        char temp[STACK_SIZE];
        for(i = 0; i<=n; i++)
            temp[i] = x[n-i];
        for(i=0; i<=n; i++)
            x[i] = temp[i];
    }

    int ModPower(int x, int e, int n, char *out_msg)
    {
        // To calculate y:=x^e(mod n).
        // y;

        char err_msg[256] = { 0 };
        long long y;
        int t;
        int i;
        int BitLength_e;
        char b[STACK_SIZE];
        //printf("e(decimal) = %d\n",e);
        if(!decimal_to_binary(e, b, err_msg)) {
            sprintf(out_msg, "decimal to binary failed, %s", err_msg);
            return -1;
        }
        //if(PRINT_BLOM)
            //printf("b = %s\n", b);
        BitLength_e = strlen(b);
        y = x;
        reverse_string(b);
        for(i = BitLength_e - 2; i >= 0 ; i--)
        {
            //if(PRINT_BLOM)
                //printf("\nb[%d]=%c", i, b[i]);
            if(b[i] == '0')
                t = 1;
            else 
                t = x;
            y = (y * y) % n;
            if ( y < 0 ) {
                y = -y;
                y = (y - 1) * (y % n) % n;
                //printf("y is negative\n");
            }
            y = (y*t) % n;
            if ( y < 0 ) {
                y = -y;
                y = (y - 1) * (y % n) % n;
                //printf("y is negative\n");
            }
        }
        if ( y < 0 ) {
            y = -y;
            y = (y - 1) * (y % n) % n;
            // printf("y is negative\n");
        }
        return (int)y;
    }

    std::string IntArrToString(long long Atr[], int size) {
        int i;
        std::string Astring;
        for(i = 0; i < size; i++) {
            Astring += std::to_string(Atr[i]);
            Astring += " ";
        }
        Astring.erase(Astring.end() - 1);
        //cout <<Astring<<endl;
        return Astring;
    }




    //Blom_Master
    bool Blom_Master::new_blom(char *out_msg)
    {
        bool bret = false;
        char err_msg[256] = { 0 };
        do {
            p = 0;
            g = 0;
            num = 0;
            if(!pick_p_and_g(err_msg)) {
                sprintf(out_msg, "pick p and g failed, %s", err_msg);
                break;
            }
            if(PRINT_BLOM)
                printf("pick_p_and_g successful\n");

            creatematrix_D();
            if(PRINT_BLOM)
                printf("creatematrix_D successful\n");
            bret = true;
        }while(false);
        return bret;
    }

    void Blom_Master::get_g_p(int *ptr, int *gtr)
    {
        *ptr = p;
        *gtr = g;
    }

    bool Blom_Master::pick_p_and_g(char *out_msg)
    {
        if(PRINT_BLOM)
            printf("The function pick_p_and_g begin\n");
        int ptemp, gtemp;
        srand((unsigned int) time(NULL));
        int count = random()%LARGE;

        char err_msg[256] = { 0 };
        bool MBTresult = false;
        while(1)
        {
            srand(count++);
            ptemp = random()%LARGE;
            if(PRINT_BLOM)
                printf("the value of p:%d\n", ptemp);
            if ((ptemp & 0x01) == 0)
                ptemp++;
            if (!MillerRobinTest(ptemp, MAX_ITERATION, MBTresult, err_msg)) {
                sprintf(out_msg, "Miller Robin Test failed, %s", err_msg);
                return false;
            }
            if(MBTresult)
                break;
        }
        if(PRINT_BLOM)
            printf("the value of p:%d, is the prime.\n", ptemp);
        if((gtemp=primitiveroot(ptemp, err_msg)) == -1) {
            sprintf(out_msg, "primitive root failed, %s", err_msg);
            return false;            
        }
        if(PRINT_BLOM)
            printf("the value of g:%d.\n", gtemp);
        p = ptemp;
        g = gtemp;
        return true;
    }

    bool Blom_Master::MillerRobinTest(int n, int iteration, bool& result, char* out_msg)
    {
        // n is the given integer and iteration is the given desired
        // number of iterations in this primality test algorithm.
        // Return true if all the iterations test passed to give
        // the higher confidence that n is a prime, otherwise
        // return false if n is composite.
        int m, t;
        int i,j;
        int a;
        long long u;
        int flag;
        if(n % 2 == 0) {
            result = false; // n is composite.
            return true;
        }
        m = (n-1)/2;
        t = 1;
        while( m % 2 == 0) // repeat until m is even
        {
            m = m / 2;
            t = t + 1;
        }

        char err_msg[256] = { 0 };
        for (j=0; j < iteration; j++) 
        { 
            // Repeat the test for MAX_ITERATION times
            flag = 0;
            srand((unsigned int) time(NULL));
            a = random() % n + 1; // select a in {1,2,......,n}
            if((u=ModPower(a, m, n, err_msg)) == -1) {
                sprintf(out_msg, "ModPower(%d, %d, %d) failed, %s", a, m, n, err_msg);
                return false;
            }
            if (u == 1 || u == n - 1)
                flag = 1;
            for(i=0;i<t;i++)
            {
                if(u == n - 1)
                    flag = 1;
                u = (u * u) % n;
            }
            if ( flag == 0 ) {
                result = false; // n is composite
                return true;
            }
        }
        result = true;  // n is prime.
        return true; 
    } 

    int Blom_Master::primitiveroot(int q, char* out_msg)
    {
        int *hash = new int[q+10];
        int g,n,flag,i,temp=1;

        char err_msg[256] = { 0 };
        for(g=2; g<q; g++)
        {
            //memset(hash, 0, sizeof(hash));
            memset(hash, 0, q+10);
            for(n=1; n<q; n++)
            {
                if((temp=ModPower(g, n, q, err_msg)) == -1) {
                    sprintf(out_msg, "ModPower(%d, %d, %d) failed, %s", g, n, q, err_msg);
                    delete [] hash;
                    return -1;
                }
                if(temp <= 0) {
                    sprintf(out_msg, "ModPower result %d is <= 0, %d^%d (mod %d). why??. ERROR!!!", temp, g, n, q);
                    delete [] hash;
                    return -1;
                }

                hash[temp]=1;
            }
            flag=1;
            for(i=1; i<q; i++)
            {
                if(hash[i]!=1)
                    flag=0;
            }
            if(flag==1) {
                delete [] hash;
                return g;
            }    
        }
        sprintf(out_msg, "cannot find the primitiveroot of prime:%d.ERROR!!!", q);
        delete [] hash;
        return -1;
    }

    bool Blom_Master::get_A_num(int* numtr, long long Atr[], int size, char* out_msg){
        int j, k, temp;
        long long sum;
        char err_msg[256] = { 0 };

        if (size != LAMDA +1) {
            sprintf(out_msg, "The size of A array is not LAMDA +1. ERROR!!!");
            return false;
        }

        for (j=0;j<LAMDA+1;j++){
            sum=0;
            for (k=0;k<LAMDA+1;k++){
                if (k==0)
                    temp = 1;
                else
                    if((temp=ModPower(g, k*(num+1), p, err_msg)) == -1) {
                        sprintf(out_msg, "ModPower(%d, %d, %d) failed, %s", g, k*(num+1), p, err_msg);
                        return false;
                    }
                
                sum = (sum + D[j][k]*temp) % p;
            }
            Atr[j]=sum;
        }
        *numtr = num;
        num++;
        return true;
    }

    void Blom_Master::creatematrix_D(){
        int i,j;
        srand((unsigned int) time(NULL));
        int count = random()%LARGE;
        memset(D, 0 ,sizeof(D));
        for (i=0;i<LAMDA+1;i++){
            for (j=i;j<LAMDA+1;j++){
                srand(count++);
                //srand((unsigned long long) time(NULL));
                D[i][j]=random()%LARGE;
                D[j][i]=D[i][j];
            }
        }
    }


    //Blom_Node
    long long Blom_Node::calculate_sum(int j, char *out_msg){
        int k, temp;
        long long s;
        s = 0;
        char err_msg[256] = { 0 };
        for (k=0;k<LAMDA+1;k++){
            if (k==0)
                temp=1;
            else
                if((temp=ModPower(g, k*(j+1), p, err_msg)) == -1) {
                    sprintf(out_msg, "ModPower(%d, %d, %d) failed, %s", g, k*(j+1), p, err_msg);
                    return -1;
                }
            
            s = (s+A[k]*temp) % p;
            if (PRINT_BLOM)
                printf("k: %d   temp: %d   s: %lld   \n", k, temp, s);
        }
        return s;
    }

    void Blom_Node::set_p_and_g(int p1, int g1) {
        p = p1;
        g = g1;
    }

    bool Blom_Node::set_A_num(int n1, long long Atr[], int size, char* out_msg) {
        bool bret = false;
        do {
            n = n1;
            if (size != sizeof(A)/sizeof(A[0]) ) {
                sprintf(out_msg, "The size of A array is not LAMDA +1. ERROR!!!");
                break;
            }
            int j;
            for (j=0;j<LAMDA+1;j++) {
                A[j] = Atr[j];
                //printf(" %d ", Atr[j]);
            }
            bret = true;
        }while(false);
        return bret;
    }


    //Blom_general
    std::string Blom_general::GetKey(std::string src) {
        MD5_CTX ctx;
        src = "O-3F3%L8." + src + "&f$q3fwe$#5";    //加入前缀和后缀
        //MD5:calculate hash
        std::string md5_string;
        unsigned char md[16] = { 0 };
        char tmp[4] = { 0 };

        MD5_Init( &ctx );
        MD5_Update( &ctx, src.c_str(), src.size() );
        MD5_Final( md, &ctx );

        for( int i = 0; i < 16; ++i )
        {   
            memset( tmp, 0x00, sizeof( tmp ) );
            sprintf( tmp, "%02X", md[i] );
            md5_string += tmp;
        }   
        return md5_string;
        
        //key must be string, ended with 0, length must be 32 + 1.
		//char key[] = { 'H', 'C', 'P', 'w', 'z', '!', 'H', '1', 'Y', '3', 'j', 'a', 'J', '*', '|', 'q', 'w', '8', 'K', '<', 'e', 'o', '7', '>', 'Q', 'i', 'h', ')', 'r', 'P', 'q', '1', 0 };
		//return key;
    }

    bool Blom_general::setup_blom(breep::tcp::peer_manager& peer_manager, char *out_msg) {
        //生成新的blom信息;将新的blom信息发送出去;master节点计算name_key_map

        char err_msg[256] = { 0 }; 
        printf("Master begin setup new blom.\n");
        
        std::string buf;
        //创建blom_master进行密钥的分配
        Blom_Master blom_master;
        if(!blom_master.new_blom(err_msg)) {
            sprintf(out_msg, "master new blom failed, %s", err_msg);
            return false;
        }
        int ptr, gtr, numtr;
        long long Atr[LAMDA+1];
        blom_master.get_g_p(&ptr, &gtr);
        if(!blom_master.get_A_num(&numtr, Atr, sizeof(Atr)/sizeof(Atr[0]), err_msg)) {
            sprintf(out_msg, "master get matrix A and num for itself failed, %s", err_msg);
            return false;                
        }
        if(PRINT_BLOM)
            printf("p: %d, g: %d\n", ptr, gtr);

        std::string name_arr[20];
        memset(name_arr, 0, sizeof(name_arr));

        //master num = 0
        stage.Calc_And(0x1011);
        blom_node.set_p_and_g(ptr, gtr);
        if(!blom_node.set_A_num(numtr, Atr, sizeof(Atr)/sizeof(Atr[0]), err_msg)) {
            sprintf(out_msg, "master set matrix A and num failed, %s", err_msg);
            return false;      
        }
        stage.Calc_Or(0x0100);
        name_arr[numtr] = MASTER_NAME;
        std::map<std::string, std::string>::iterator name_iter;

        //node
        for(name_iter = name_id_map.begin(); name_iter != name_id_map.end(); name_iter++) {
            if(!blom_master.get_A_num(&numtr, Atr, sizeof(Atr)/sizeof(Atr[0]), err_msg)) {
                sprintf(out_msg, "master get matrix A and num for other node failed, %s", err_msg);
                return false;                
            }
    
            name_arr[numtr] = name_iter->first;
            buf.clear();
            buf = "Blom info:" + std::to_string(ptr) + " " + std::to_string(gtr) + " "
                    + std::to_string(numtr) + "\n" + IntArrToString(Atr, sizeof(Atr)/sizeof(Atr[0]));
            communication::Communication::sendTo(peer_manager, name_iter->first, name_iter->second, buf, RSA_TYPE);
        }
        //发送一个数组 数组包含了每个索引对应的nodeName，用来替代节点间发送序号的过程。
        buf.clear();
        buf = "nodeNum.length:" + std::to_string(numtr+1) + "\n";
        for(int i = 0; i < numtr+1; i++) {
            buf = buf + name_arr[i] + " ";
        }
        buf.pop_back();     //删除队尾空格
        communication::Communication::sendToall(peer_manager, buf, RSA_TYPE);

        stage.Calc_And(0x0111);
        name_key_map.clear();

        long long sum;
        // master skip the num = 0(master itself)
        for(int i = 1; i < numtr+1; i++) {
            if((sum=blom_node.calculate_sum(i, err_msg)) == -1) {
                sprintf(out_msg, "master calc sum failed, %s", err_msg);
                return false;                    
            }
            name_key_map.insert(std::pair<std::string, std::string>(name_arr[i], blom::Blom_general::GetKey(std::to_string(sum))));
        }
        stage.Calc_Or(0x1000);
        return true;
    }

}