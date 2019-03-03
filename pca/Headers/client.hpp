#include "common.hpp"
class ClientCert
{
  private:
    ClientCert();
    //Cert(Cert const &);
    //void operator=(Cert const &);
    ~ClientCert();
    //root path
    const string CLIENTPATH = "/client/";
    //first-tier path
    const string nodeCert = CLIENTPATH + "certs/";
    const string nodeRequest = CLIENTPATH + "requests/";
    const string nodeCrl = CLIENTPATH + "crl/";

    //sencode-tier path
    const string nodeAccountCert = nodeCert + "account/";
    const string nodeTlsCert = nodeCert + "tls/";
    const string nodeAccountRequest = nodeRequest + "account/";
    const string nodeTlsRequest = nodeRequest + "tls/";
    //const string nodeAccountCrl = nodeCrl + "account";
    //const string nodeTlsCrl = nodeCrl + "tls";

    //filename
    const string accountCert = "account";
    const string tlsCert = "tls";

  public:
    ClientCert(ClientCert const &) = delete;
    void operator=(ClientCert const &) = delete;
    static ClientCert &getInstance()
    {
        static ClientCert theSingleton;
        return theSingleton;
    }
    //set up client cert env, account and tls pem and corresponding csr files
    string getCertFileName(string fileType, string certType = "");
    void decompressionCerts();
};

void fileProcess(int transType, int certType);
void receiveProcess();
void handleProcess();
void sendProcess();
void sig_handler(int sig);

void generateCerts();
void setup();
void closesocket();
void enqueueSA();
void enqueueST();
void enqueueGC();
void enqueueRC();

