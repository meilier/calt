#ifdef __linux__
#include <signal.h>
#endif
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <thread>
#include <iostream>
#include <fstream>
#include <sstream>
#include "common.hpp"
#include "cmessage.hpp"
#include "cqueue.hpp"
#include "client.hpp"

#define MYPORT 7000
#define BUFFER_SIZE 1024


int sock_cli;
int file_port;
fd_set rfds;
struct timeval tv;
int retval, maxfd;
ClientCert *cCert;

//recv message queue
ConcurrentQueue<string> rq;

//send message queue
ConcurrentQueue<string> sq;

//handle message queue
ConcurrentQueue<string> hq;

static volatile int keepRunning = 1;

void sig_handler(int sig)
{
    if (sig == SIGINT)
    {
        keepRunning = 0;
    }
}

void enqueueSA()
{
    sq.Push(SA);
}
void enqueueST()
{
    sq.Push(ST);
}
void enqueueGC()
{
    sq.Push(GC);
}
void enqueueRC()
{
    sq.Push(RC);
}

void receiveProcess()
{
    printf("start receive Process thread\n");
    while (1)
    {
        sleep(1);
        /*把可读文件描述符的集合清空*/
        FD_ZERO(&rfds);
        maxfd = 0;
        /*把当前连接的文件描述符加入到集合中*/
        FD_SET(sock_cli, &rfds);
        /*找出文件描述符集合中最大的文件描述符*/
        if (maxfd < sock_cli)
            maxfd = sock_cli;
        /*设置超时时间*/
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        /*等待聊天*/
        retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1)
        {
            printf("select出错，客户端程序退出\n");
            break;
        }
        else if (retval == 0)
        {
            printf("客户端没有任何输入信息，并且服务器也没有信息到来，waiting...\n");
            continue;
        }
        else
        {

            char recvbuf[BUFFER_SIZE];
            int len;
            len = recv(sock_cli, recvbuf, sizeof(recvbuf), 0);
            printf("receiveProcess: receive len is %d \n", len);
            // message branch
            printf("reveiveProcess get message is %s\n", recvbuf);
            vector<string> ms = messageSplit(recvbuf);
            for (auto it = ms.begin(); it != ms.end(); it++)
            {
                cout << *it << endl;

                if (string(*it) == SAR)
                {
                    //connect to server file transfer port, such as, 7001
                    rq.Push(SAR);
                }
                else if (string(*it) == SAO)
                {
                    //
                    rq.Push(SAO);
                }
                else if (string(*it) == STR)
                {
                    rq.Push(STR);
                }
                else if (string(*it) == STO)
                {
                    printf("Sign tls ok here\n");
                    rq.Push(STO);
                    rq.Empty() ? printf("yes") : printf("no");
                    printf("Sign tls ok here?\n");
                }
                else if (string(*it) == GCR)
                {
                    //get certs ready message from server
                    //connect to server to get it's certs.tar.gz
                    rq.Push(GCR);
                }
                else if (string(*it) == GRLR)
                {
                    //get certs ready message from server
                    //connect to server to get it's certs.tar.gz
                    rq.Push(GRLR);
                }else if (string(*it).substr(0,5) == "#PORT")
                {
                    file_port = atoi(string(*it).substr(5,4).c_str());
                    printf("client-port is %d",file_port);
                }
            }
            memset(recvbuf, 0, sizeof(recvbuf));
        }
    }
}

void sendProcess()
{
    printf("start sendProcess thread\n");
    while (1)
    {

        //get message from send queue
        string sqmessage;
        sq.Pop(sqmessage);
        printf("sendProcess: send message is %s\n", sqmessage.c_str());
        send(sock_cli, sqmessage.c_str(), strlen(sqmessage.c_str()), 0); //send
    }
}

void handleProcess()
{
    printf("start handleProcess thread\n");
    while (1)
    {

        printf("?????why not here\n");
        //get message from queue
        string rpmessage;
        rq.Pop(rpmessage);
        printf("Get message from rq is %s \n", rpmessage.c_str());
        if (rpmessage == SAR)
        {
            //send csr file
            //connect to server file transfer port, such as, 7001
            //sleep(2);
            std::thread t4(fileProcess, 0, 0);
            t4.detach();
        }
        else if (rpmessage == SAO)
        {
            //get pem from server
            std::thread t4(fileProcess, 1, 0);
            t4.detach();
        }
        else if (rpmessage == STR)
        {
            //sleep(2);
            std::thread t4(fileProcess, 0, 1);
            t4.detach();
        }
        else if (rpmessage == STO)
        {
            std::thread t4(fileProcess, 1, 1);
            t4.detach();
        }
        else if (rpmessage == GRLR)
        {
            //get certs ready message from server
            //connect to server to get its crl file
            std::thread t4(fileProcess, 1, 3);
            t4.detach();
        }
        else if (rpmessage == GCR)
        {
            //get certs ready message from server
            //connect to server to get it's certs.tar.gz
            std::thread t4(fileProcess, 1, 2);
            t4.detach();
        }
    }
}

/*********
 * send crs file to server
 * transType: 0 send to server, 1 get from server
 * certType: 0 account crs, 1 tls csr, 2 get all certs file, 3 get crl file.
 * */
void fileProcess(int transType, int certType)
{
    printf("start fileProcess thread\n");
    int file_cli;
    int readLen, byteNum;
    int MAXLINE = 4096;
    char buff[4096];
    ///定义sockfd
    file_cli = socket(AF_INET, SOCK_STREAM, 0);
    ///定义sockaddr_in
    struct sockaddr_in fileaddr;
    memset(&fileaddr, 0, sizeof(fileaddr));
    fileaddr.sin_family = AF_INET;
    fileaddr.sin_port = htons(file_port);               ///服务器端口
    fileaddr.sin_addr.s_addr = inet_addr("192.168.80.160"); ///服务器ip

    //connect to server，0 success，-1 failed
    if (connect(file_cli, (struct sockaddr *)&fileaddr, sizeof(fileaddr)) < 0)
    {
        perror("connect");
        exit(1);
    }
    if (transType == 0)
    {
        //transfer crs file to server

        //open file
        ifstream sfile;
        if (certType == 0)
        {
            //open account pem file
            sfile.open(cCert->getCertFileName("csr", "account"), ios::out | ios::in);
        }
        else if (certType == 1)
        {
            //open tls pem file
            sfile.open(cCert->getCertFileName("csr", "tls"), ios::out | ios::in);
        }
        while (!sfile.eof())
        {
            sfile.read(buff, sizeof(buff));
            readLen = sfile.gcount();
            int sendnum = send(file_cli, buff, readLen, 0);
            printf("my send is %d file_cli is %d",sendnum,file_cli);
        }
        printf("fileProcess: send csr successfully\n");
        //may be the bug is you need to close socket first
        close(file_cli);
        sfile.close();
        //send file get ok message to handle process
        //may be here, client should send get pem file ok message, otherwise we send it again
        return;
    }
    else if (transType == 1)
    {
        //get from server
        //write file
        std::ofstream rfile;
        if (certType == 0)
        {
            //open account pem file
            rfile.open(cCert->getCertFileName("pem", "account"), ios::out);
        }
        else if (certType == 1)
        {
            //open tls pem file
            rfile.open(cCert->getCertFileName("pem", "tls"), ios::out);
        }
        else if (certType == 2)
        {
            //open tar.gz file
            rfile.open(cCert->getCertFileName("compact"), ios::out);
        }
        else if (certType == 3)
        {
            //open csrfile file
            rfile.open(cCert->getCertFileName("crl"), ios::out);
        }
        while (1)
        {
            printf("fileProcess:ready to get pem file\n");
            byteNum = read(file_cli, buff, MAXLINE);
            if (byteNum == 0)
            {
                printf("fileProcess:here1\n");
                break;
            }

            //printf("buff is %s\n", buff);
            rfile.write(buff, byteNum);
        }
        printf("fileProcess:here2\n");
        close(file_cli);
        rfile.close();
        //un tar.gz operation
        if (certType == 2)
        {
            printf("decompressionCerts.........");
            cCert->decompressionCerts();   
        }
        return;
    }
}

void generateCerts()
{
    //call setup.sh
    char current_absolute_path[512];
    //getcwd(current_absolute_path, 512);
    WORKDIR = string("/pca");
    printf("WORKDIR is %s \n", WORKDIR.c_str());
    string signCmd = "sh " + string(WORKDIR) + "/Scripts/client.sh";
    //Todo: error handling
    popen(signCmd.c_str(), "w");
}

void setup()
{
    cCert = &cCert->getInstance();
    signal(SIGINT, sig_handler);
    ///定义sockfd
    sock_cli = socket(AF_INET, SOCK_STREAM, 0);
    ///定义sockaddr_in
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(MYPORT);                 ///服务器端口
    servaddr.sin_addr.s_addr = inet_addr("192.168.80.160"); ///服务器ip

    //连接服务器，成功返回0，错误返回-1
    printf("ready to connect to server \n");
    if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printf("connect to server failed\n");
        perror("connect");
        exit(1);
    }
    printf("connect to server successfully\n");
    //thread : send
    std::thread t1(sendProcess);
    t1.detach();
    //thread : recv
    std::thread t2(receiveProcess);
    t2.detach();

    //thread : handle
    std::thread t3(handleProcess);
    t3.detach();

    //test Sign Account
    //sleep(6);
    //sq.Push(ST);
    //sleep(5);
    //sq.Push(SA);
    //sleep(6);
    //sq.Push(GC);
    //sleep(6);
    //sq.Push(GRL);
    //sleep(6);
    //sq.Push(RC);
    // while (keepRunning)
    // {
    //     sleep(1);
    // }
    // close(sock_cli);
    //return 0;
}

void closesocket()
{
    close(sock_cli);
}