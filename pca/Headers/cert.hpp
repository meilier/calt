#include "common.hpp"
#include <map>
#include <set>
class Cert
{
private:
  Cert();
  //Cert(Cert const &);
  //void operator=(Cert const &);
  ~Cert();
  int serial;
  //root path
  const string CAPATH = "/testrsa/";
  const string caCert = CAPATH;
  //first-tier path
  const string nodeCert = CAPATH + "certs/";
  const string nodeRequest = CAPATH + "requests/";
  const string nodeCrl = CAPATH + "crl/";
  const string configPath = CAPATH + "openssl.cnf";

  //sencode-tier path
  const string nodeAccountCert = nodeCert + "account/";
  const string nodetlsCert = nodeCert + "tls/";
  const string nodeAccountRequest = nodeRequest + "account/";
  const string nodeTlsRequest = nodeRequest + "tls/";
  //const string nodeAccountCrl = nodeCrl + "account";
  //const string nodeTlsCrl = nodeCrl + "tls";

  //filename
  const string accountCert = "accountCert";
  const string tlsCert = "tlsCert";

  //certList
  set<string> certList;
  set<string> tarCertList;

public:
  map<int, int> CertSerial;
  Cert(Cert const &) = delete;
  void operator=(Cert const &) = delete;
  static Cert &getInstance()
  {
    static Cert theSingleton;
    return theSingleton;
  }
  void increaseSerial();
  int getSerial();
  void insertSerial(int conn, int serial);
  void deleteSerial(int conn);
  void signCert(int conn,string certType);
  void getAllCerts();
  void revokeCert(int conn);
  string getCertOrgName(int conn, int certType);

  string getCertFileName(int conn, string fileType, string useType = "");
};
