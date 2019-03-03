#include "client.hpp"
#include "common.hpp"
#include "unistd.h"

string ClientCert::getCertFileName(string fileType, string certType)
{
    string returnmsg;
    if (fileType == "csr")
    {
        if (certType == "account")
        {

            returnmsg = nodeAccountRequest + accountCert + ".csr";
        }
        else
        {
            returnmsg = nodeTlsRequest + tlsCert + ".csr";
        }
    }
    else if (fileType == "pem")
    {
        if (certType == "account")
        {
            returnmsg = nodeAccountCert + accountCert + ".pem";
        }
        else
        {
            returnmsg = nodeTlsCert + tlsCert + ".pem";
        }
    }
    else if (fileType == "crl")
    {
        //crl file contains all certs that have been invoked
        returnmsg = nodeCrl + "invoke.crl";
    }
    else if (fileType == "compact")
    {
        returnmsg = CLIENTPATH + "certs.tar.gz";
    }
    else
    {
        returnmsg = "error: incorrect fileType";
    }
    printf("ClientCert::getCertFileName : returnmsg is %s\n", returnmsg.c_str());
    return returnmsg;
}

void ClientCert::decompressionCerts()
{
    string compactCmd = " tar -zxvf " + CLIENTPATH + "/certs.tar.gz --strip-components 1 " + " -C " + CLIENTPATH + "allcerts";
    popen(compactCmd.c_str(), "r");
}

ClientCert::ClientCert()
{
    printf("Init CA Server\n");
}
ClientCert::~ClientCert()
{
    printf("Clear CA Server\n");
    //call setup.sh
    string signCmd = "sh " + string(WORKDIR) + "/Scripts/clearclient.sh";
    //Todo: error handling
    //popen(signCmd.c_str(), "w");
}