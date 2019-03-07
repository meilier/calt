#include <iostream>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <chrono>
#include <boost/uuid/uuid_io.hpp>
#include <map>

#include "breep/network/tcp.hpp"
#include "blom.h"
#include "certificates.h"
#include "communication.h"
#include "common.h"
#include "client.hpp"



#include "crypto_sig.h"


using namespace std;

string IntArrToString(long long Atr[], int size) {
    int i;
    string Astring;
    for(i = 0; i < size; i++) {
        Astring += std::to_string(Atr[i]);
        Astring += " ";
    }
    Astring.erase(Astring.end() - 1);
    //cout <<Astring<<endl;
    return Astring;
}


int main(int argc, char* argv[]) {
    
	if (argc != 3 ) {
		std::cout << "Usage: " << argv[0] << " <hosting port> <hosting name>" << std::endl;
		return 1;
	}

	char *nodeName = (char*)malloc(32*sizeof(char));
    nodeName = argv[2];
    stage.Set(0x0000);

    cout << "(1) " << nodeName << " begin setup CAServer." << endl;

    generateCerts();
    sleep(2);
    setup();
    sleep(6);
    enqueueST();    //TLS证书生成
    enqueueSA();    //ACCOUNT证书生成
    sleep(25);
    enqueueGC();    //向CA请求获得
    //sleep(25);
    //closesocket();

    // cout << "(1) " << nodeName << " setup CAServer Successful" << endl;
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


    //即使线程函数func采用引用方式，thread并不知道这一情形，所以在thread object在构造时会盲目的拷贝peer_manager
    //然后thread将这个对象拷贝到线程地址空间作为internal copy，此后线程函数引用的是线程地址空间的那个internal copy
    //线程执行完毕，thread会销毁internal copy
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
    peer_manager.run();


    cout << "(3) " << nodeName << " Setup Breep successful." << endl;

    std::cout << "the local name is " << nodeName << "; the local id is " << peer_manager.self().id_as_string() << "." << std::endl;

    /*
    sleep(6);
    
    cout << "(4) " << nodeName << " begin setup blom." << endl;
    
    
    //创建blom_master进行密钥的分配
    blom::Blom_Master blom_master;
    blom_master.new_blom();
    int ptr, gtr, numtr;
    long long Atr[LAMDA+1];
    blom_master.get_g_p(&ptr, &gtr);
    blom_master.get_A_num(&numtr, Atr, sizeof(Atr)/sizeof(Atr[0]));
    //printf("p: %d, g: %d\n", ptr, gtr);

    string name_arr[20];
    memset(name_arr, 0, sizeof(name_arr));

    //master num = 0
    stage.Calc_And(0x1011);
    blom_node.set_p_and_g(ptr, gtr);
    blom_node.set_A_num(numtr, Atr, sizeof(Atr)/sizeof(Atr[0]));
    stage.Calc_Or(0x0100);
    name_arr[numtr] = nodeName;
    map<string, string>::iterator name_iter;

    //node
    for(name_iter = name_id_map.begin(); name_iter != name_id_map.end(); name_iter++) {
        blom_master.get_A_num(&numtr, Atr, sizeof(Atr)/sizeof(Atr[0]));
        
        name_arr[numtr] = name_iter->first;
        buf.clear();
        buf = "Blom info:" + to_string(ptr) + " " + to_string(gtr) + " "
                + to_string(numtr) + "\n" + IntArrToString(Atr, sizeof(Atr)/sizeof(Atr[0]));
        communication::Communication::sendTo(peer_manager, name_iter->first, name_iter->second, buf, RSA_TYPE);
    }
    //发送一个数组 数组包含了每个索引对应的nodeName，用来替代节点间发送序号的过程。
    buf.clear();
    buf = "nodeNum.length:" + to_string(numtr+1) + "\n";
    for(int i = 0; i < numtr+1; i++) {
        buf = buf + name_arr[i] + " ";
    }
    buf.pop_back();     //删除队尾空格
    communication::Communication::sendToall(peer_manager, buf, RSA_TYPE);

    stage.Calc_And(0x0111);
    name_key_map.clear();
    // master skip the num = 0(master itself)
    for(int i = 1; i < numtr+1; i++) {
        long long sum = blom_node.calculate_sum(i);
        name_key_map.insert(pair<string, string>(name_arr[i], blom::Blom_general::GetKey(to_string(sum))));
    }
    stage.Calc_Or(0x1000);

    cout << "(4) " << nodeName << " setup blom successful." << endl;
    */
    /*
    if(!blom::Blom_general::setup_blom(peer_manager, out_msg))
        printf("master setup blom failed, because %s\n", out_msg);
    else
       printf("master setup blom successful.\n");
    */
    sleep(30);

    string buf;
    cout << "(4) " << nodeName << " begin send test message to other node." << endl;

    for (int i = 0; i <= 30; i++) {
        buf.clear();
        buf = "message" + to_string(i) + " from " + string(nodeName) + " to ";
        communication::Communication::sendToall(peer_manager, buf, AES_TYPE);
        sleep(1);
    }

    cout << "(4) " << nodeName << " send test message to other node finished." << endl;
    
    while (1) {

    }
    

	// this is not obligatory, as the peer_manager is going out of scope anyway
	peer_manager.remove_data_listener(da_listener_id);
	peer_manager.remove_connection_listener(co_listener_id);
	peer_manager.remove_disconnection_listener(dc_listener_id);

    return 0;
} 