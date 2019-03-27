#include "cert.hpp"
#include "common.hpp"
#include <fstream>
#include <unistd.h>
#include <sstream>
#include <stdio.h>
#ifdef __linux__
#include <mutex>
#include <condition_variable>
#endif
using namespace std;

int flag = 1;

mutex mtx;
condition_variable cv;

mutex fmtx;

/* **********
 * Call openssl ca command to sign the crs file the client requests.
 */
void Cert::signCert(int conn, string certType)
{
    FILE *stream;
    char result[4096];
    string pemName = getCertFileName(conn, "pem", certType);
    //call openssl command to sign
    printf("start to sign cert\n");
    string signCmd = "openssl ca -config " + configPath + " -in " + getCertFileName(conn, "csr", certType) + " -out " + pemName + " -batch -key 123456";
    //string signCmd = "python /Users/xingweizheng/Demo1.py";
    printf("this command is %s\n", signCmd.c_str());
    //Todo: error handling, lock for single signing
    std::unique_lock<std::mutex> lock(mtx);
    fmtx.lock();
    while (flag == 0)
    {
        fmtx.unlock();
        cv.wait(lock);
    }
    fmtx.unlock();
    lock.unlock();
    fmtx.lock();
    flag--;
    fmtx.unlock();
    if ((stream = popen(signCmd.c_str(), "r")) != NULL)
    {
        printf("stream is not NULL\n",stream);
        fread(result,sizeof(char),sizeof(result),stream);
    }
    pclose(stream);
    string rs(result);
    printf("The result is %s\n",rs.c_str());
    std::unique_lock<std::mutex> lock2(mtx);
    cv.notify_one();
    fmtx.lock();
    flag++;
    fmtx.unlock();
    //printf("ready for exit test\n");
    //exit(1);
    certList.insert(pemName);
    printf("sign cert ok\n");
}

/* **********
 * get all certs at certs/ dir in a tar.gz file
 */
void Cert::getAllCerts()
{
    //wait for an abstract
    //wirte current certList to tarCertList
    set<string>::iterator it;
    if(tarCertList == certList){
        // same set
        return;
    }
    // not equal
    tarCertList.clear();
    for (it = certList.begin(); it != certList.end(); ++it){
        tarCertList.insert(*it);
    }
        //cout << ' ' << *it;
    string compactCmd = " tar -zcvf " + CAPATH + "/certs.tar.gz" + " -C " + CAPATH + " certs ";
    popen(compactCmd.c_str(), "w");
}

/* **********
 * revoke account and tls cert of one node
 */
void Cert::revokeCert(string clientName)
{

    //use ca private key get plaintext(tar.gz including node.pem),digest and node.signature
    //ca server use pem in plaintext to analysis the corresponding signature to make sure its deconding message equaling to digest

    //decoding message
    string dAccount = nodeAccountCert + accountCert + clientName + ".pem";
    string dTls = nodeAccountCert + accountCert + clientName + ".pem";
    string invokeAccountCmd = "openssl ca -config " + configPath + " -revoke " + dAccount + " -key 123456";
    string invokeTlsCmd = "openssl ca -config " + configPath + " -revoke " + dTls + " -key 123456";
    string genCrlCmd = "openssl ca -config " + configPath + " -gencrl -out" + getCertFileName(0, "crl");
    popen(invokeAccountCmd.c_str(), "w");
    popen(invokeTlsCmd.c_str(), "w");
    popen(genCrlCmd.c_str(), "w");

    // delete pem file
    string rmA = "rm " + dAccount;
    string rmT = "rm " + dTls;
    popen(rmA.c_str(), "w");
    popen(rmT.c_str(), "w");
}

/* **********
 * Call openssl ca command to sign the crs file the client requests.
 */
string Cert::getCertFileName(int conn, string fileType, string useType)
{
    string returnmsg;
    if (fileType == "csr")
    {
        if (useType == "account")
        {

            returnmsg = nodeAccountRequest + accountCert + to_string(CertSerial.find(conn)->second) + ".csr";
        }
        else
        {
            returnmsg = nodeTlsRequest + tlsCert + to_string(CertSerial.find(conn)->second) + ".csr";
        }
    }
    else if (fileType == "pem")
    {
        if (useType == "account")
        {
            //returnmsg = nodeAccountCert + accountCert + to_string(CertSerial.find(conn)->second) + getCertOrgName(conn, 0) + ".pem";
            returnmsg = nodeAccountCert + accountCert + getCertOrgName(conn, 0) + ".pem";
        }
        else
        {
            //returnmsg = nodetlsCert + tlsCert + to_string(CertSerial.find(conn)->second) + getCertOrgName(conn, 1) + ".pem";
            returnmsg = nodetlsCert + tlsCert  + getCertOrgName(conn, 1) + ".pem";
        }
    }
    else if (fileType == "crl")
    {
        //crl file contains all certs that have been invoked
        returnmsg = nodeCrl + "invoke.crl";
    }
    else if (fileType == "compact")
    {
        returnmsg = CAPATH + "certs.tar.gz";
    }
    else
    {
        returnmsg = "error";
    }
    printf("Cert::getCertFileName : returnmsg is %s\n", returnmsg.c_str());
    return returnmsg;
}

// 0 account , 1 tls
string Cert::getCertOrgName(int conn, int certType)
{
    //according to conn's csr serial numner to get its orgname
    FILE *fp;
    char buf[1024];
    string signCmd;
    string res = "";
    //call setup.sh
    if(certType == 0)
        signCmd = " openssl req -in /testrsa/requests/account/accountCert" + to_string(CertSerial.find(conn)->second) + ".csr -noout -text |grep Subject:| awk  '{print $4}'|awk -F= '{print $2}'";
    else{
        signCmd = " openssl req -in /testrsa/requests/tls/tlsCert" + to_string(CertSerial.find(conn)->second) + ".csr -noout -text |grep Subject:| awk  '{print $4}'|awk -F= '{print $2}'";
    }
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
        printf("%s\n", buf);
    }
    for(int i = 0;i < 1024;i++){
        if(buf[i] == ',')
            break;
        res += buf[i];
    }
    //string res(buf);
    pclose(fp);
    return res;
}

void Cert::increaseSerial()
{
    serial++;
}

int Cert::getSerial()
{
    return serial;
}

void Cert::insertSerial(int conn, int serial)
{
    CertSerial.insert(pair<int, int>(conn, serial));
}

void Cert::deleteSerial(int conn)
{
    CertSerial.erase(conn);
}

Cert::Cert()
{
    printf("Init CA Server\n");
    //call setup.sh
    char current_absolute_path[512];
    getcwd(current_absolute_path, 512);
    //int index = strrchr( current_absolute_path, '/' ) - current_absolute_path;
    //current_absolute_path[index] = '\0';
    WORKDIR = "/pca";
    printf("WORKDIR is %s \n", WORKDIR.c_str());
    //readConfigFile((WORKDIR+"/Config/config.cfg").c_str(),"CAPATH",CAPATH);
    //printf("CAPATH is %s\n",CAPATH.c_str());
    //printf("nodeCert is %s\n",nodeCert.c_str());
    string signCmd = "sh " + string(WORKDIR) + "/Scripts/setup.sh";
    //Todo: error handling
    popen(signCmd.c_str(), "w");
}
Cert::~Cert()
{
    printf("Clear CA Server\n");
    //call setup.sh
    string signCmd = "sh " + string(WORKDIR) + "/Scripts/clear.sh";
    //Todo: error handling
    //popen(signCmd.c_str(), "w");
}