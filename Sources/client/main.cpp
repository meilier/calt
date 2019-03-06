#include <iostream>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <chrono>
#include <boost/uuid/uuid_io.hpp>
#include <map>

#include "breep/network/tcp.hpp"
#include "blom.h"
#include "crypto_sig.h"
#include "certificates.h"
#include "common.h"
#include "communication.h"
#include "client.hpp"




#include "crypto_sig.h"


using namespace std;


int main(int argc, char* argv[]) {
    
	if (argc != 5 ) {
		std::cout << "Usage: " << argv[0] << " <hosting port> <target container_name> <target port> <hosting name>" << std::endl;
		return 1;
	}

    char *nodeName = (char*)malloc(32*sizeof(char));
    nodeName = argv[4];    

    stage.Set(0x0000);
    cout << "(1) " << nodeName << " begin setup CAClient." << endl;
    
    generateCerts();
    sleep(2);
    setup();
    sleep(6);
    enqueueST();    //TLS证书生成
    enqueueSA();    //ACCOUNT证书生成
    sleep(15);
    enqueueGC();    //向CA请求获得
    sleep(12);
    closesocket();
    
    // cout << "(1) " << nodeName << " setup CAClient Successful" << endl;
    // stage.Calc_Or(0x0001);
    
    // while((stage.Get() & 0x0001) != 0x0001) {
    //     cout << "The Certificates is not ready, Waiting..." << endl;
    //     sleep(1);
    // }

    while (true) {}

    cout << "(2) " << nodeName << " begin check the certificate." << endl;

	char serial[128] = { 0 };
	char out_msg[256] = { 0 };
    
    //test-modify
    string verify_file = "";
    //verify_file = verify_file.append("/").append(string(nodeName)).append(CASERVER_CERT);
    verify_file = verify_file.append(CASERVER_CERT);
    string chain_file = "";
    chain_file = chain_file.append("/").append(string(nodeName)).append(LOCAL_ACCOUNT_DIR).append(string(nodeName)).append(ACCOUNTCERT_POSTFIX);
    //chain_file = chain_file.append(LOCAL_ACCOUNT_DIR).append(string(nodeName)).append(ACCOUNTCERT_POSTFIX);
    string private_key_file = "";
    private_key_file = private_key_file.append("/").append(string(nodeName)).append(LOCAL_ACCOUNT_DIR).append(string(nodeName)).append(ACCOUNTKEY_POSTFIX);
    //private_key_file = private_key_file.append(LOCAL_ACCOUNT_DIR).append(string(nodeName)).append(ACCOUNTKEY_POSTFIX);
    string private_password = PASSWD;
    int iret;

    //account cert : ECC_TYPE
	iret = certificates::Certificates::CheckCertificate(verify_file, chain_file, private_key_file, ECC_TYPE,
        private_password, serial, out_msg);  
    if (0 == iret) {
        printf("check account certificate failed, because \n%s\n", out_msg);
        exit(1);
    }
    else
        printf("check account certificate successful.\n");

    
    //test-modify
    chain_file.clear();
    //chain_file =chain_file.append("/").append(string(nodeName)).append(LOCAL_TLS_DIR).append(string(nodeName)).append(TLSCERT_POSTFIX);
    chain_file =chain_file.append(LOCAL_TLS_DIR).append(string(nodeName)).append(TLSCERT_POSTFIX);
    private_key_file.clear();
    private_key_file = private_key_file.append("/").append(string(nodeName)).append(LOCAL_TLS_DIR).append(string(nodeName)).append(TLSKEY_POSTFIX);
    //private_key_file = private_key_file.append(LOCAL_TLS_DIR).append(string(nodeName)).append(TLSKEY_POSTFIX);
	//tls cert : RSA_TYPE
    iret = certificates::Certificates::CheckCertificate(verify_file, chain_file, private_key_file, RSA_TYPE,
        private_password, serial, out_msg);  
    if (0 == iret) {
        printf("check tls certificate failed, because \n%s\n", out_msg);
        exit(1);
    }
    else
        printf("check tls certificate successful.\n");

    cout << "(2) " << nodeName << " check the certificate successful." << endl;




    cout << "(3) " << nodeName << " begin setup Breep." << endl;

	
	// taking the local hosting port as parameter.
    breep::tcp::peer_manager peer_manager(static_cast<unsigned short>(atoi(argv[1])));

    std::thread t1(communication::timed_message::handleProcess, boost::ref(peer_manager));
    t1.detach();


    // disabling logging.
    peer_manager.set_log_level(breep::log_level::none);
    peer_manager.nodeName = nodeName;

    
    //local nodeName message not include the map name_id_map
    //name_id_map.insert(pair<string, breep::tcp::peer>(nodeName, peer_manager.self()));

    // adding listeners. Of course, more listeners could be added.
    breep::listener_id da_listener_id = peer_manager.add_data_listener(communication::timed_message());
    breep::listener_id co_listener_id = peer_manager.add_connection_listener(&(communication::connection_disconnection));
    breep::listener_id dc_listener_id = peer_manager.add_disconnection_listener(&(communication::connection_disconnection));

    /*
    std::thread t1(communication::handleProcess);
    t1.detach();
    */
    

    // connecting to a remote peer.
    char *str = (char*)malloc(32*sizeof(char));
    communication::getAddr(argv[2], str, 32);
    std::cout<<"target container_name:" << str<< std::endl;
    boost::asio::ip::address address = boost::asio::ip::address::from_string(str);
    //target port -v
    while (!peer_manager.connect(address, static_cast<unsigned short>(atoi(argv[3])))) {
        std::cout << "Connection failed.Maybe the target container is not ready. " << std::endl;
        sleep(1);
    }


    cout << "(3) " << nodeName << " Setup Breep successful." << endl;

    std::cout << "the local name is " << nodeName << "; the local id is " << peer_manager.self().id_as_string() << "." << std::endl;

    while((stage.Get() & 0x0010) != 0x0010) {
        cout << "Do not receive nodeName message from master. Waiting..." << endl;
        sleep(1);
    };

    sleep(30);

    cout << "(4) " << nodeName << " begin send test message to other node." << endl;

    string buf;
    for (int i = 0; i <= 30; i++) {
        buf.clear();
        buf = "message" + to_string(i) + " from " + string(nodeName) + " to ";
        communication::Communication::sendToall(peer_manager, buf, AES_TYPE);
        sleep(1);
    }

    cout << "(4) " << nodeName << " send test message to other node finished." << endl;
    
    //set server number and A
    //printf("the node 0 message:\n");
    //sprintf(buf, "New Blom(list sort p g number A)\n%d\n%d\n%d\n%s\n", ptr, gtr, numtr, (IntArrToString(Atr, sizeof(Atr)/sizeof(Atr[0])).c_str()));
    //client.sendMsg(buf);
    //cout << buf <<endl;
    //printf("create message successful\n");
    /*
    printf("calculate_sum:%lld\n", blom_node.calculate_sum(1));



    blom_master.get_A_num(&numtr, Atr, sizeof(Atr)/sizeof(Atr[0]));

    blom::Blom_Node blom_node1;
    blom_node1.set_p_and_g(ptr, gtr);
    blom_node1.set_A_num(numtr, Atr, sizeof(Atr)/sizeof(Atr[0]));
    

    //set server number and A
    //blom_master.get_A_num(numtr, Atr, sizeof(Atr));
    printf("the node 1 message:\n");
    sprintf(buf, "New Blom(list sort p g number A)\n%d\n%d\n%d\n%s\n", ptr, gtr, numtr, (IntArrToString(Atr, sizeof(Atr)/sizeof(Atr[0])).c_str()));
    //client.sendMsg(buf);
    cout << buf <<endl;
    
    printf("calculate_sum:%lld\n", blom_node1.calculate_sum(0));    
    */

    /*
    string encrypto_key = blom::Blom_general::GetKey(IntArrToString(Atr, sizeof(Atr)/sizeof(Atr[0])));
    cout << "encrypto_key:" << encrypto_key <<endl;
    printf("sizeof(encrypto_key):%d\n", sizeof(encrypto_key));

    string encrypt_string;
    encrypt_string=crypto_sig::Aes::Crypto(buf, blom::Blom_general::GetKey(encrypto_key));
    cout << "encrypt_string message:\n" << encrypt_string <<endl;
    string decryto_string;
    decryto_string=crypto_sig::Aes::Decrypto(encrypt_string, blom::Blom_general::GetKey(encrypto_key));
    cout << "decryto_string message:\n" <<decryto_string <<endl;
    printf("\nThe test of AES encrypto and blom is OK!!\n");



    unsigned char sig[10240] = { 0 };
    unsigned int sig_len = 0;
    if(!crypto_sig::Signature::ECDSASignature(private_key_file.c_str(), PASSWD, buf, sizeof(buf), sig, &sig_len)) {
        cout << "signature message failed\n" <<endl;
        exit(1);
    }
        
    printf("signature:%s\n", sig);
    cout << "signature length:" << sig_len <<endl;

    if(!crypto_sig::Signature::VerifySignature(chain_file.c_str(), buf, sizeof(buf), sig, sig_len))
        cout << "signature and message don's match! " << endl;
    else
        cout << "signature and message match! " << endl;


    */
    while (1) {

    }

	// this is not obligatory, as the peer_manager is going out of scope anyway
	peer_manager.remove_data_listener(da_listener_id);
	peer_manager.remove_connection_listener(co_listener_id);
	peer_manager.remove_disconnection_listener(dc_listener_id);    

    return 0;
} 