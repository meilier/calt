#ifndef COMMON_H
#define COMMON_H

#define PASSWD "123456"
#define RSA_TYPE 0
#define AES_TYPE 1
#define ECC_TYPE 2

#define CASERVER_CERT "/client/allcerts/cacert.pem"
#define LOCAL_ACCOUNT_DIR "/client/certs/account/"
#define LOCAL_TLS_DIR "/client/certs/tls/"

#define NODE_ACCOUNT_DIR "/client/allcerts/account/"
#define NODE_TLS_DIR "/client/allcerts/tls/"

#define ACCOUNTCERT_POSTFIX "account.pem"
#define ACCOUNTKEY_POSTFIX "account.key.pem"

#define TLSCERT_POSTFIX "tls.pem"
#define TLSKEY_POSTFIX "tls.key.pem"

#define MASTER_NAME "master"

#include <map>
#include <blom.h>
#include <string>

#include "mutex_var.h"
#include "communication.h"

extern std::map<std::string, std::string> name_id_map;
extern std::map<std::string, std::string> name_key_map;
extern blom::Blom_Node blom_node;  //local(master) info about blom

//个位表示证书生成完成, 十位表示nodeName是否收到master节点的nodeName
//百位表示blom info是否完成, 千位表示name_key_map是否完成
extern mutex_var::Stage stage;  //十六进制

//handle Data queue
extern mutex_var::ConcurrentQueue<communication::Commu_Data> hq;
#endif