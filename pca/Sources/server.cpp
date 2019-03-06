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
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <list>
#include <map>
#include "cert.hpp"
#include "cqueue.hpp"
#include "cmessage.hpp"

#define PORT 7000
#define IP "127.0.0.1"
#define MAXLINE 4096

typedef struct
{
    int conn;
    string message;
} CInstance;

void getConn();
void getConnFile(int conn, int port);
void fileProcess(int transType, int certType, int conn, int filefd);
void receiveProcess();
void handleRqProcess();
void handleHqProcess();
void sendProcess();
void sig_handler(int sig);

// for easy mode ,we use single process
//int sema = 1;
int messageSock;
struct sockaddr_in servaddr;
socklen_t len;
int Current_Port = 8000;
//socklen_t filelen;

map<int,int> conn_account;
map<int,int> conn_tls;

//debug
int temp_count = 0;
int gacot = 0;
int gtcot = 0;
bool once = false;
int oncetime = 0;

std::list<int> li;
Cert *mCert;
map<string, string> qqq;

//recv message queue
ConcurrentQueue<CInstance> rq;

//send message queue
ConcurrentQueue<CInstance> sq;

//handle message queue
ConcurrentQueue<CInstance> hq;

//file transfer queue
ConcurrentQueue<CInstance> fq;

// ctrl + c interupt
static volatile int keepRunning = 1;

//getConn mutex condition_variable for non-loop
//mutex mtx;
//condition_variable cv;

void sig_handler(int sig)
{
    if (sig == SIGINT)
    {
        keepRunning = 0;
    }
}

void getConn()
{
    while (1)
    {
        //here we may tell the other client that some client is connecting
        printf("waiting for client\n");
        //if (sema > 0)
        //{
        printf("start message listening thread at 7000\n");
        int conn = accept(messageSock, (struct sockaddr *)&servaddr, &len);
        li.push_back(conn);
        //thread : getconnection from client
        printf("current_port is %d", Current_Port);
        CInstance ci;
        ci.conn = conn;
        ci.message = "#PORT" + to_string(Current_Port);
        sq.Push(ci);
        std::thread t0(getConnFile, conn, Current_Port);
        t0.detach();
        Current_Port++;
        std::thread t00(getConnFile, conn, Current_Port);
        t00.detach();
        Current_Port++;
        for (list<int>::iterator it = li.begin(); it != li.end(); ++it)
            cout << ' ' << *it << endl;
        printf("getConn: the connect fd is %d\n", conn);
        //sema--;
        mCert->increaseSerial();
        mCert->insertSerial(conn, mCert->getSerial());
        //}
        // std::unique_lock<std::mutex> lock(mtx);
        // while (sema <= 0)
        // {
        //     printf("blocking for client\n");
        //     cv.wait(lock);
        // }
        //printf("still loop\n");
    }
}

void getConnFile(int conn ,int port)
{
    int connfd = 0;
    socklen_t filelen;
    int byteNum;
    int fileSock;
    struct sockaddr_in fileaddr;
    char buff[MAXLINE];
    CInstance fqmessage;
    //new file socket
    fileSock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&fileaddr, 0, sizeof(fileaddr));
    fileaddr.sin_family = AF_INET;
    fileaddr.sin_port = htons(port);
    fileaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (::bind(fileSock, (struct sockaddr *)&fileaddr, sizeof(fileaddr)) == -1)
    {
        perror("bind");
        exit(1);
    }
    if (listen(fileSock, 20) == -1)
    {
        perror("listen");
        exit(1);
    }
    filelen = sizeof(fileaddr);
    //fqmessage.conn = conn;
    while (1)
    {
        printf("fileProcess: start file transfer listening at %d\n",port);
        if ((connfd = accept(fileSock, (struct sockaddr *)&fileaddr, &filelen)) == -1)
        {
            printf("accept socket error: %s(errno: %d)", strerror(errno), errno);
        }

        
        //printf("fileProcess: get file connection from client, my conn is %d connfd is %d\n", connfd);
        while(1)
        {
            fq.front(fqmessage);
            if(fqmessage.conn == conn && (((port % 2 == 0) && (fqmessage.message == SA || fqmessage.message == GACO||fqmessage.message == GC)) \
            || ((port % 2 == 1) && (fqmessage.message == ST||fqmessage.message == GTCO ))))
                break;
            else
            {
                usleep(500000);
            }
            printf("conn is %d,fqfront is %d , %s",conn,fqmessage.conn,fqmessage.message.c_str());
            
        }
        fq.Pop(fqmessage);
        printf("fqmessage is %s\n",fqmessage.message.c_str());
        //according to fqmessage , decide which fileprocess will be used
        if (fqmessage.message == SA)
        {
            //if single port tell main process to transport file
            //main process ready to receive csr file
            conn_account.insert(std::pair<int,int>(fqmessage.conn,connfd));
            std::thread t4(fileProcess, 0, 0, fqmessage.conn, connfd);
            t4.detach();
            //send sign-ok message
        }
        else if (fqmessage.message == ST)
        {
            //receive tls crs file
            conn_tls.insert(std::pair<int,int>(fqmessage.conn,connfd));
            std::thread t4(fileProcess, 0, 1, fqmessage.conn, connfd);
            t4.detach();
        }
        else if (fqmessage.message == GC)
        {
            //send certs.tar.gz to client
            std::thread t4(fileProcess, 1, 2, fqmessage.conn, connfd);
            t4.detach();
        }
        else if (fqmessage.message == GRL)
        {
            //send crl to client
            std::thread t4(fileProcess, 1, 3, fqmessage.conn, connfd);
            t4.detach();
        }
        else if (fqmessage.message == GACO)
        {
            //sign account certificate
            std::thread t4(fileProcess, 1, 0, fqmessage.conn, connfd);
            t4.detach();
        }
        else if (fqmessage.message == GTCO)
        {
            //sign tls certificate
            std::thread t4(fileProcess, 1, 1, fqmessage.conn, connfd);
            t4.detach();
        }
        else
        {
            printf("getConnFile:wrong message");
        }
    }
}

/*******
 * receiveProcess(): receive messag from client
 * and send it to rq -- receive queue, waiting handleProcess to cope with it
 * ***/
void receiveProcess()
{
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    printf("start receive thread\n");
    while (1)
    {
        std::list<int>::iterator it;
        printf("receiveProcess: wait client to send message\n");
        for (it = li.begin(); it != li.end();)
        {
            printf("receiveProcess: into for loop\n");
            fd_set rfds;
            FD_ZERO(&rfds);
            int maxfd = 0;
            int retval = 0;
            FD_SET(*it, &rfds);
            if (maxfd < *it)
            {
                maxfd = *it;
            }
            retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);
            if (retval == -1)
            {
                printf("select error\n");
            }
            else if (retval == 0)
            {
                //printf("not message\n");
            }
            else
            {
                char rbuf[1024];
                CInstance mCInstance;
                mCInstance.conn = *it;
                printf("receiveProcess: mCInstance conn is %d\n", *it);
                memset(rbuf, 0, sizeof(rbuf));
                int len = recv(*it, rbuf, sizeof(rbuf), 0);
                printf("reveiceProcess: the message is %s\n", rbuf);
                //detect if socket has closed
                if (len == 0)
                {
                    if (errno != EINTR)
                    {
                        // here we need to close file process at the same time.
                        //    sema++;
                        //std::lock_guard<std::mutex> lock(mtx);
                        close(*it);
                        li.erase(it++);
                        mCert->deleteSerial(*it);
                        //Current_Port = Current_Port - 2;
                        //cv.notify_one();
                        continue;
                    }
                }
                vector<string> ms = messageSplit(rbuf);
                for (auto it = ms.begin(); it != ms.end(); it++)
                {
                    cout << *it << endl;

                    if (string(*it) == SA.c_str())
                    {
                        //do get account csr file and sign and return pem
                        printf("start to sign account cert\n");
                        mCInstance.message = SA;
                        //new thread to write file , sign , send done message , send pem file
                        //first prepare a listenning socket and accept, then send ok message to
                        //client for it to send csrfile, when file is complete , start to sign
                        // when sign process is ok, send sign-ok message to client, client start
                        // to listen at a new socket for server to transport file
                        // char sbuf[1024];
                        // strcpy(sbuf,"ready-sign-account");
                        // int len = send(*it, sbuf, sizeof(sbuf), 0);
                        rq.Push(mCInstance);
                    }
                    else if (string(*it) == ST.c_str())
                    {
                        //do get tls csr file and sign and return pem
                        printf("rbuf is fule %s\n", rbuf);
                        printf("start to sign tls cert\n");
                        mCInstance.message = ST;
                        // char sbuf[1024];
                        // strcpy(sbuf,"ready-sign-tls");
                        // int len = send(*it, sbuf, sizeof(sbuf), 0);
                        rq.Push(mCInstance);
                    }
                    else if (string(*it) == GC.c_str())
                    {
                        // transport all pem files
                        printf("start to transport pem files to nodes\n");
                        mCInstance.message = GC;
                        // mCert->getAllCerts();
                        rq.Push(mCInstance);
                    }
                    else if (string(*it) == GRL.c_str())
                    {
                        // transport all pem files
                        printf("start to transport cert revocation list file to nodes\n");
                        mCInstance.message = GRL;
                        // mCert->getAllCerts();
                        rq.Push(mCInstance);
                    }
                    else if (string(*it) == RC.c_str())
                    {
                        // transport all pem files
                        printf("start to transport pem files to nodes\n");
                        mCInstance.message = RC;
                        // mCert->revokeCert();
                        rq.Push(mCInstance);
                    }
                    else
                    {
                        printf("wrong message\n");
                    }
                }
            }
            it++;
        }
        sleep(1);
    }
}

/*******
 * handleRqProcess(): handle message in rq-- receive, and send result to sq -- sendqueue.
 * */
void handleRqProcess()
{
    printf("start handle receive queue thread\n");
    while (1)
    {

        //get message from queue
        CInstance rpmessage;
        CInstance sqmessage;
        rq.Pop(rpmessage);
        //add to file queue
        fq.Push(rpmessage);
        sqmessage.conn = rpmessage.conn;
        if (rpmessage.message == SA)
        {
            //if single port tell main process to transport file
            //main process ready to receive csr file
            printf("handleProcess:why can not be here\n");
            sqmessage.message = SAR;
            sq.Push(sqmessage);

            //send sign-ok message
        }
        else if (rpmessage.message == ST)
        {
            //receive tls crs file
            sqmessage.message = STR;
            sq.Push(sqmessage);
        }
        else if (rpmessage.message == GC)
        {
            //send certs.tar.gz to client
            mCert->getAllCerts();
            sqmessage.message = GCR;
            sq.Push(sqmessage);
        }
        else if (rpmessage.message == GRL)
        {
            //send crl to client
            sqmessage.message = GRLR;
            sq.Push(sqmessage);
        }
        else if (rpmessage.message == RC)
        {
            //invoke this client account and tls cert
            mCert->revokeCert(sqmessage.conn);
        }
        else
        {
            printf("wrong message");
        }
    }
}

/*******
 * handleHqProcess(): handle message in hq-- receive, and send result to sq -- sendqueue.
 * */
void handleHqProcess()
{
    printf("start handle handle queue thread\n");
    while (1)
    {

        CInstance hqmessage;
        CInstance sqmessage;
        hq.Pop(hqmessage);
        fq.Push(hqmessage);
        sqmessage.conn = hqmessage.conn;
        if (hqmessage.message == GACO)
        {
            //sign account certificate
            mCert->signCert(sqmessage.conn, "account");
            sqmessage.message = SAO;
            sq.Push(sqmessage);
        }
        else if (hqmessage.message == GTCO)
        {
            //sign tls certificate
            mCert->signCert(sqmessage.conn, "tls");
            sqmessage.message = STO;
            sq.Push(sqmessage);
        }
    }
}
/**********
 * fileProcess recv or send file from or to client
 * transType: 0 get file from client . certType: 0 get account csr, 1 get tls csr
 * transType: 1 send file to client. certType: 1 send file to client, 0 send account pem, 1 send tls pem , 2 send certs.tar.gz to client, 3 send crl file to client
 * */
void fileProcess(int transType, int certType, int conn, int filefd)
{
    temp_count = 0;
    printf("======waiting for client's request======\n");
    if (transType == 0)
    {
        //get from client
        while (1)
        {
            int byteNum;
            char buff[MAXLINE];
            CInstance hqmessage;
            hqmessage.conn = conn;
            //printf("fileProcess: start file transfer listening at 7001\n");
            printf("fileProcess: get file connection from client, certType is %d my conn is %d connfd is %d\n",certType, conn, filefd);
            //write file
            std::ofstream csrfile;
            if (certType == 0)
            {
                csrfile.open(mCert->getCertFileName(conn, "csr", "account"), std::ios::out | std::ios::trunc);
            }
            else
            {
                csrfile.open(mCert->getCertFileName(conn, "csr", "tls"), std::ios::out | std::ios::trunc);
            }
            printf("xingweizheng zaici1\n");
            while (1)
            {
                printf("xingweizheng zaici2\n");
                if((certType == 0 && conn_account.find(conn)->second == filefd) || (certType == 1 && conn_tls.find(conn)->second == filefd))
                    byteNum = read(filefd, buff, MAXLINE);
                else
                {
                    usleep(200000);
                    continue;
                }   
                
                if (byteNum < 0)
                {
                    printf("error happens conn %d connfd %d errno", conn, filefd, errno);
                }
                printf("fileProcess: why thead not return %d\n", byteNum);
                if (byteNum == 0)
                {
                    close(filefd);
                    csrfile.close();

                    //send file get ok message to handle process
                    if (certType == 0)
                    {
                        hqmessage.message = GACO;
                        gacot++;
                        hq.Push(hqmessage);
                        printf("gacot is %d\n", gacot);
                        printf("orgname is ", mCert->getCertOrgName(conn, 0).c_str());
                    }
                    else
                    {
                        hqmessage.message = GTCO;
                        gtcot++;
                        hq.Push(hqmessage);
                        printf("gtcot is %d\n", gtcot);
                        printf("orgname is ", mCert->getCertOrgName(conn, 1).c_str(), "orgname is \n");
                    }
                    printf("should be ready to return\n");
                    return;
                }
                csrfile.write(buff, byteNum);
                // out debug
                map<int,int>::iterator it;
                it = mCert->CertSerial.begin();
                while(it != mCert->CertSerial.end()){
                    printf("cert conn %d, cert seial %d\n",it->first,it->second);
                    it++;
                }
                // two
                map<int,int>::iterator it2;
                it2 = conn_account.begin();
                while(it2 != conn_account.end()){
                    printf("account conn %d, connfd file %d\n",it2->first,it2->second);
                    it2++;
                }
                // three
                map<int,int>::iterator it3;
                it3 = conn_tls.begin();
                while(it3 != conn_tls.end()){
                    printf("tls conn %d, connfd fle %d\n",it3->first,it3->second);
                    it3++;
                }
                // four
                printf("certType  %d my conn  %d connfd  %d\n",certType, conn, filefd);
                printf("%d%d%d",certType,conn,filefd,buff);
            }
        }
    }
    else
    {
        //send to client
        while (1)
        {
            int byteNum;
            char buff[4096];
            int readLen = 0;
            //open file
            ifstream sfile;
            if (certType == 0)
            {
                //open account pem file
                sfile.open(mCert->getCertFileName(conn, "pem", "account"), ios::out | ios::in);
            }
            else if (certType == 1)
            {
                //open tls pem file
                sfile.open(mCert->getCertFileName(conn, "pem", "tls"), ios::out | ios::in);
            }
            else if (certType == 2)
            {
                //open tar.gz file
                sfile.open(mCert->getCertFileName(conn, "compact"), ios::out | ios::in);
            }
            else if (certType == 3)
            {
                //open csrfile file
                sfile.open(mCert->getCertFileName(conn, "crl"), ios::out | ios::in);
            }
            while (!sfile.eof())
            {
                printf("fileProcess:ready to send pem file, %d\n", certType);
                sfile.read(buff, sizeof(buff));
                //printf("buff is %s\n",buff);
                readLen = sfile.gcount();
                send(filefd, buff, readLen, 0);
                //printf("fileProcess:here1\n");
                temp_count++;
                if (temp_count > 100 && certType == 2)
                {
                    printf("The temp_count > 1000, break\n");
                    break;
                }
            }
            printf("fileProcess:here2\n");
            close(filefd);
            sfile.close();
            //sq.Push("SPO");
            //send file get ok message to handle process
            //may be here, client should send get pem file ok message, otherwise we send it again
            return;
        }
    }
}

void sendProcess()
{
    printf("start send thread\n");
    while (1)
    {

        // char buf[1024];
        // fgets(buf, sizeof(buf), stdin);
        // //printf("you are send %s", buf);

        // // send process get send pem file message, then send file
        // std::list<int>::iterator it;
        // for(it=li.begin(); it!=li.end(); ++it){
        //     send(*it, buf, sizeof(buf), 0);
        // }
        CInstance sqmessage;
        sq.Pop(sqmessage);
        printf("sendProcess: conn is %d get message %s\n", sqmessage.conn, sqmessage.message.c_str());
        // std::list<int>::iterator it;
        // it = li.begin();
        int connfd = sqmessage.conn;
        if (sqmessage.message == SAR)
        {
            //get csr file
            const char *c_s = SAR.c_str();
            char ff[11];
            printf("sendProcess:whyaaaaaaaa %s  %d  %d %d %d \n", SAR.c_str(), sizeof(*SAR.c_str()), sizeof(c_s), sizeof("ssssssssss"), sizeof(ff));
            send(connfd, SAR.c_str(), SAR.length(), 0);
        }
        else if (sqmessage.message == SAO)
        {
            //ready to tranport pem to client
            send(connfd, SAO.c_str(), SAO.length(), 0);
        }
        else if (sqmessage.message == STR)
        {
            //get csr file
            send(connfd, STR.c_str(), STR.length(), 0);
        }
        else if (sqmessage.message == STO)
        {
            //ready to tranport pem to client
            send(connfd, STO.c_str(), STO.length(), 0);
        }
        else if (sqmessage.message == GCR)
        {
            send(connfd, GCR.c_str(), GCR.length(), 0);
        }
        else if (sqmessage.message == GRLR)
        {
            send(connfd, GRLR.c_str(), GRLR.length(), 0);
        }
        else if (sqmessage.message.substr(0, 5) == "#PORT")
        {
            send(connfd, sqmessage.message.c_str(), sqmessage.message.length(), 0);
        }
        else
        {
            printf("wrong send queue message");
        }
    }
}

int main()
{
    mCert = &mCert->getInstance();
    signal(SIGINT, sig_handler);
    //new message socket
    messageSock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (::bind(messageSock, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
    {
        perror("bind");
        exit(1);
    }
    if (listen(messageSock, 20) == -1)
    {
        perror("listen");
        exit(1);
    }
    len = sizeof(servaddr);

    //thread : getconnection from client
    std::thread t(getConn);
    t.detach();
    printf("start get\n");
    //thread : send
    std::thread t1(sendProcess);
    t1.detach();
    //thread : recv
    std::thread t2(receiveProcess);
    t2.detach();

    //thread : handle rq
    std::thread t3(handleRqProcess);
    t3.detach();

    //thread : handle hq
    std::thread t4(handleHqProcess);
    t4.detach();
    while (keepRunning)
    {
        sleep(1);
    }
    cout << "Terminated by Ctrl+C signal." << endl;
    return 0;
}