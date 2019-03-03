#include <iostream>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <chrono>
#include <boost/uuid/uuid_io.hpp>
#include <map>
#include <mutex>

#include "breep/network/tcp.hpp"
#include "common.h"
#include "blom.h"
#include "crypto_sig.h"
#include "communication.h"
#include "mutex_var.h"
#include "client.hpp"

std::map<std::string, std::string> name_id_map;     //without local name_id
std::map<std::string, std::string> name_key_map;    //without local name_key
mutex_var::ConcurrentQueue<communication::Commu_Data> hq;
blom::Blom_Node blom_node; 
mutex_var::Stage stage;


namespace communication {

    void timed_message::handleProcess(breep::tcp::peer_manager& peer_manager) {
    //void handleProcess() {
        printf("start handleProcess thread\n");
        while (1) {

        Commu_Data commu_data;
        hq.Pop(commu_data);
        std::string time_info = commu_data.time_info;
        std::string buf = commu_data.data;
        std::string local_nodeName = peer_manager.nodeName;

        std::string remote_id = commu_data.remote_id;

        std::string sig;
        std::string chain_file = "";        //account-cert
        std::string sig_nodeName;           //sig(remote) nodeName

        char out_msg[256] = { 0 };

        //信息类型
        //1. remote nodeName    明文
        //2. local blom info    RSA加密
        //3. nodeName[num]      RSA加密
        //4. message            AES加密
        //5. signout            明文
        if ((buf.length() > 9) && (buf.substr(0, 9) == "nodeName:")) {
            //nodeName:name, unencrypted data
            //no premise
            std::size_t found = buf.rfind("\n");
            
            if(found == std::string::npos) {
                printf("nodeName format is invalid. Maybe it doesn't have the sig. FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                std::cout<< buf << std::endl;
                continue ;  
            }

            sig = buf.substr(found+1, buf.length()-(found+1));
            buf.erase(found+1, buf.length()-(found+1));

            sig_nodeName = buf.substr(9);
            sig_nodeName.pop_back(); //delete \n
            if(sig_nodeName.length() == 0) {
                printf("The nodeName is null, it is invalid.\n");
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                continue ;                        
            }
            
            
            //从CAserver处获取证书
            setup();
            sleep(6);
            enqueueGC();
            sleep(10);
            closesocket();
            

            //test-mofity
            chain_file = chain_file.append("/").append(std::string(local_nodeName)).append(NODE_ACCOUNT_DIR).append(std::string(sig_nodeName)).append(ACCOUNTCERT_POSTFIX);
            std::cout << chain_file << std::endl;
            //chain_file = chain_file.append(LOCAL_TLS_DIR).append(std::string(sig_nodeName)).append(TLSCERT_POSTFIX);
            if(!crypto_sig::Signature::VerifySignature(chain_file.c_str(), buf.c_str(), sizeof(buf), sig, out_msg)) {
                printf("he signature of nodeName:%s is invalid, because %s, maybe attacker disguise itself as %s\n", sig_nodeName.c_str(), out_msg, sig_nodeName.c_str());
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                continue ;
            }

            name_id_map.insert(std::pair<std::string, std::string>(sig_nodeName, remote_id));
            std::cout << time_info << "receive name " << sig_nodeName << " id " << remote_id << std::endl;
            //nodes[std::string(nodeNameT, dataSizeT)] = source;
            if(sig_nodeName == MASTER_NAME)
                stage.Calc_Or(0x0010);


            if(local_nodeName == MASTER_NAME) {
                //有新的节点加入，重新生成blom信息
                stage.Calc_Or(0x0010);
                
                if(!blom::Blom_general::setup_blom(peer_manager, out_msg))
                    printf("master setup blom failed, because %s\n", out_msg);
                else
                    printf("master setup blom successful.\n");
            }
        }
        else
        if ((buf.length() > 9) && (buf.substr(0, 7) == "signout")) {
            //signout, unencrypted data
            //no premise

            if(local_nodeName != MASTER_NAME) {
                //only master will accept this message
                continue;  
            }

            std::size_t found = buf.rfind("\n");
            
            if(found == std::string::npos) {
                printf("nodeName format is invalid. Maybe it doesn't have the sig. FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                std::cout<< buf << std::endl;
                continue ;  
            }

            sig = buf.substr(found+1, buf.length()-(found+1));

            std::map<std::string, std::string>::iterator iter_id;
            for(iter_id = name_id_map.begin(); iter_id != name_id_map.end(); iter_id++) {
                if(remote_id == iter_id->second)
                    break;
            }
            if(iter_id == name_id_map.end()) {
                printf("Cann't find the peer(id) %s in name_id_map.FILE:%s, LINE:%d\n", remote_id.c_str(), __FILE__, __LINE__);
                continue ; 
            }

            sig_nodeName = iter_id->first;

            //test-mofity
            chain_file = chain_file.append("/").append(std::string(local_nodeName)).append(NODE_ACCOUNT_DIR).append(std::string(sig_nodeName)).append(ACCOUNTCERT_POSTFIX);
            std::cout << chain_file << std::endl;
            //chain_file = chain_file.append(LOCAL_TLS_DIR).append(std::string(sig_nodeName)).append(TLSCERT_POSTFIX);
            if(!crypto_sig::Signature::VerifySignature(chain_file.c_str(), buf.c_str(), sizeof(buf), sig, out_msg)) {
                printf("he signature of nodeName:%s is invalid, because %s, maybe attacker disguise itself as %s\n", sig_nodeName.c_str(), out_msg, sig_nodeName.c_str());
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                continue ;
            }


            
            setup();
            sleep(6);
            //TODO:wait modify
            //enqueueRC(sig_nodeName);
            sleep(6);
            enqueueGC();
            sleep(10);
            closesocket();
            


            //node 节点的 name_id_map中对name_id的删除将会在connection_disconnection中完成
            //master 在此处删除，保证name_id_map的更新在生成新的blom信息之前
            // someone disconnected
            //这里需要根据peer的id找到node中的索引  删除。
            std::cout << remote_id.substr(0, 4) << " disconnected" << std::endl;
            for (auto &x : name_id_map)
            {
                if (x.second.compare(remote_id) == 0)
                {
                    name_id_map.erase(x.first);
                    break;
                }
            }

            std::cout << time_info << "name" << sig_nodeName << " id " << remote_id << "signout." << std::endl;

            //有节点退出，重新生成blom信息                
            if(!blom::Blom_general::setup_blom(peer_manager, out_msg))
                printf("master setup blom failed, because %s\n", out_msg);
            else
                printf("master setup blom successful.\n");
        }
        else
        if((stage.Get() & 0x0011) != 0x0011) {
            printf("The stage is %04x. node hasn't received the master nodeName message. Data is push in the hq again.\n", stage.Get());
            hq.Push(commu_data);
            sleep(3);
        }
        else
        if((stage.Get() & 0x1111) == 0x1111) {
            //message ,AES解密
            std::map<std::string, std::string>::iterator iter_id;
            std::string decrypt_string;
            for(iter_id = name_id_map.begin(); iter_id != name_id_map.end(); iter_id++) {
                if(remote_id == iter_id->second)
                    break;
            }
            if(iter_id == name_id_map.end()) {
                printf("Cann't find the peer(id) %s in name_id_map.FILE:%s, LINE:%d\n", remote_id.c_str(), __FILE__, __LINE__);
                continue ; 
            }

            std::map<std::string, std::string>::iterator iter_key;
            iter_key = name_key_map.find(iter_id->first);
            if(iter_key == name_key_map.end()) {
                printf("Cann't find the name %s in name_key_map. Please Check.FILE:%s, LINE:%d\n", iter_id->first.c_str(), __FILE__, __LINE__);
                continue ;
            }
            if((decrypt_string = crypto_sig::Aes::Decrypto(buf, iter_key->second, out_msg)) == "") {
                printf("AES Decrypt failed, because %s\n", out_msg);
                continue ;
            }

            sig_nodeName = iter_id->first;
            std::size_t found = decrypt_string.rfind("\n");
            if(found == std::string::npos) {
                printf("test-message format is invalid. Maybe it doesn't have the sig. FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                std::cout<< buf << std::endl;
                continue ;
            }
            

            sig = decrypt_string.substr(found+1, decrypt_string.length()-(found+1));
            decrypt_string.erase(found+1, decrypt_string.length()-(found+1));

            //test-mofity
            chain_file = chain_file.append("/").append(std::string(local_nodeName)).append(NODE_ACCOUNT_DIR).append(std::string(sig_nodeName)).append(ACCOUNTCERT_POSTFIX);
            //chain_file = chain_file.append(LOCAL_TLS_DIR).append(std::string(sig_nodeName)).append(TLSCERT_POSTFIX);
            if(!crypto_sig::Signature::VerifySignature(chain_file.c_str(), decrypt_string.c_str(), sizeof(decrypt_string), sig, out_msg)) {
                printf("he signature of nodeName:%s is invalid, because %s, maybe attacker disguise itself as %s\n", sig_nodeName.c_str(), out_msg, sig_nodeName.c_str());
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                continue ;
            }
            decrypt_string.pop_back(); //delete \n

            std::cout << time_info << decrypt_string << std::endl;
        }
        else {
            //blom 信息未传递完成,RSA解密
            std::map<std::string, std::string>::iterator iter_id;
            iter_id = name_id_map.find(MASTER_NAME);
            if(iter_id == name_id_map.end()) {
                printf("Can not find the master in name_id_map. Please check. FILE:%s, LINE:%d\n", __FILE__, __LINE__);
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                exit(1);
            }
            if(iter_id->second != remote_id) {
                printf("Master id != data sender id, maybe the attacker disguise itself as master to send blom info.\n");
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                continue ;
            }
            
            std::string tls_key_path = "";

            //test-modify
            //tls_key_path = tls_key_path.append("/").append(local_nodeName).append(LOCAL_TLS_DIR).append(local_nodeName).append(TLSKEY_POSTFIX);
            tls_key_path = tls_key_path.append(LOCAL_TLS_DIR).append(local_nodeName).append(TLSKEY_POSTFIX);
            std::string decrypt_string;
            if((decrypt_string = crypto_sig::Rsa::DecodeRSAKeyFile(tls_key_path, buf, PASSWD, out_msg)) == "") {
                    printf("Rsa Drypto failed, because %s\n", out_msg);
                    continue ;                
            }
            if(decrypt_string.length() == 0) {
                printf("Rsa decrypt failed. Maybe it's the test-message which encrypted by AES \
                        and it's received earlier than blom info. This message will push_back the hq. \
                        If it is the invailed message and cannot decrypted by AES, it will discard late.\n");
                hq.Push(commu_data);
                continue ;
            }


            std::size_t found = decrypt_string.rfind("\n");
            if(found == std::string::npos) {
                printf("blom info or nodeName[num] format is invalid. Maybe it doesn't have the sig. FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                std::cout<< buf << std::endl;
                continue ;
            }


            sig = decrypt_string.substr(found+1, decrypt_string.length()-(found+1));
            decrypt_string.erase(found+1, decrypt_string.length()-(found+1));

            sig_nodeName = MASTER_NAME;


            //test-mofity
            chain_file = chain_file.append("/").append(std::string(local_nodeName)).append(NODE_ACCOUNT_DIR).append(std::string(sig_nodeName)).append(ACCOUNTCERT_POSTFIX);
            //chain_file = chain_file.append(NODE_ACCOUNT_DIR).append(std::string(sig_nodeName)).append(ACCOUNTCERT_POSTFIX);
            if(!crypto_sig::Signature::VerifySignature(chain_file.c_str(), decrypt_string.c_str(), sizeof(decrypt_string), sig, out_msg)) {
                printf("he signature of nodeName:%s is invalid, because %s, maybe attacker disguise itself as %s\n", sig_nodeName.c_str(), out_msg, sig_nodeName.c_str());
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                continue ;
            }
            decrypt_string.pop_back(); //delete \n

            std::cout << time_info << decrypt_string << std::endl;

            if((decrypt_string.length() > 10) && (decrypt_string.substr(0, 10) == "Blom info:")) {
                //local blom info    RSA加密
                int p, g, num;
                long long A[LAMDA+1];

                decrypt_string.erase(0, 10);
                std::size_t found = decrypt_string.find(" ");
                if(found!=std::string::npos)
                    p = std::stoi(decrypt_string.substr(0, found));
                else {
                    printf("Blom info format is wrong.FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                    printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                    std::cout<< decrypt_string << std::endl;
                    continue ;
                }

                decrypt_string.erase(0, found+1);
                found = decrypt_string.find(" ");
                if(found!=std::string::npos)
                    g = std::stoi(decrypt_string.substr(0, found));
                else {
                    printf("Blom info format is wrong.FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                    printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                    std::cout<< decrypt_string << std::endl;
                    continue ;
                }

                decrypt_string.erase(0, found+1);
                found = decrypt_string.find("\n");
                if(found!=std::string::npos)
                    num = std::stoi(decrypt_string.substr(0, found));
                else {
                    printf("Blom info format is wrong.FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                    printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                    std::cout<< decrypt_string << std::endl;
                    continue ;
                }                

                memset(A, 0, sizeof(A));
                decrypt_string.erase(0, found+1);
                int i;
                for(i = 0; i < LAMDA; i++) {
                    found = decrypt_string.find(" ");
                    if(found!=std::string::npos) {
                        A[i] = std::stoi(decrypt_string.substr(0, found));
                        decrypt_string.erase(0, found+1);
                    }
                    else {
                        printf("Blom info format is wrong.FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                        printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                        std::cout<< decrypt_string << std::endl;
                        break ;
                    }
                }
                if(i != LAMDA) continue ;
                A[i] = std::stoi(decrypt_string);
                stage.Calc_And(0x1011);
                blom_node.set_p_and_g(p, g);
                if(!blom_node.set_A_num(num, A, sizeof(A)/sizeof(A[0]), out_msg)) {
                    printf("set matrix A and num failed, %s", out_msg);
                    continue;      
                }
                stage.Calc_Or(0x0100);
            }
            else
            if((stage.Get() & 0x0111) != 0x0111)    {
                printf("The stage is %04x. node hasn't received the blom info message. Data is push in the hq again.\n", stage.Get());
                hq.Push(commu_data);
                sleep(3);                
            }
            else
            if((decrypt_string.length() > 15) && (decrypt_string.substr(0, 15) == "nodeNum.length:")) {
                //nodeName[num]      RSA加密

                //有节点退出时
                
                //从CAserver处获取证书
                setup();
                sleep(6);
                enqueueGC();
                sleep(10);
                closesocket();
                

                decrypt_string.erase(0, 15);
                std::size_t found = decrypt_string.find("\n");
                if(found == std::string::npos) {
                    printf("nodeNum format is wrong.FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                    printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                    std::cout<< decrypt_string << std::endl;
                    continue ;
                }
                int name_arr_len = 0;
                name_arr_len = std::stoi(decrypt_string.substr(0, found));
                if(name_arr_len < 1) {
                    printf("The length of nodeNum is invalid. length:%d.\n", name_arr_len);
                    printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                    continue ;
                }
                decrypt_string.erase(0, found+1);

                std::string name_arr[20];

                int i;
                for(i = 0; i < name_arr_len-1; i++) {
                    found = decrypt_string.find(" ");
                    if(found != std::string::npos) {
                        name_arr[i] = decrypt_string.substr(0, found);
                        decrypt_string.erase(0, found+1);
                    }
                    else {
                        printf("nodeNum format is invalid. FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                        printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                        std::cout<< decrypt_string << std::endl;
                        break ;
                    }
                }
                std::cout<< decrypt_string <<". length:" <<decrypt_string.length() << std::endl;
                if( i != name_arr_len-1) continue ;
                name_arr[i] = decrypt_string;

                stage.Calc_And(0x0111);
                name_key_map.clear();
                for(i = 0; i < name_arr_len; i++) {
                    if(name_arr[i] != local_nodeName) {
                        long long sum;
                        if((sum=blom_node.calculate_sum(i, out_msg)) == -1) {
                            printf("Please check, calculate sum failed, because %s\n", out_msg);
                            break;
                        }
                        
                        name_key_map.insert(std::pair<std::string, std::string>(name_arr[i], blom::Blom_general::GetKey(std::to_string(sum))));
                    }
                }
                if(i != name_arr_len) continue;
                stage.Calc_Or(0x1000);
            }
            else {
                printf("RSA decrypt string format is invalid, but the sig is corrent. Maybe attacker has control some node and send the useless message. FILE:%s, LINE:%d\n.", __FILE__, __LINE__);
                printf("The data sender id is %s, name is %s.\n", remote_id.c_str(), local_nodeName.c_str());
                std::cout<< buf << std::endl;
                continue ;
            }

        }

        }   //while(1)
    }   //handleProcess


	void timed_message::operator()(breep::tcp::peer_manager& peer_manager , const breep::tcp::peer& source, breep::cuint8_random_iterator data,
	                      size_t data_size, bool /* sent_only_to_me */) {

		// print the time and the name of the buddy that sent me something
		time_t now = time(0) - m_starting_time;
		//std::cout << '[' << std::string(ctime(&now)).substr(14,5) << "] " << source.id_as_string().substr(0, 4) << ": ";
        std::string time_info = "[" + std::string(ctime(&now)).substr(14,5) + "]" + source.id_as_string().substr(0, 4) + ": ";
		// prints what he sent.
		//for (; data_size > 0 ; --data_size) {
			//std::cout << static_cast<char>(*data++);
        //}

        char *buf_char = (char *)malloc(data_size * sizeof(char));
        size_t dataSizeT = data_size;
        for (; data_size > 0 ; --data_size) {
			buf_char[dataSizeT - data_size] = static_cast<char>(*data++);
        }
        std::string buf = std::string(buf_char, dataSizeT);
        
        Commu_Data commu_data = { time_info, source.id_as_string(), buf };
        hq.Push(commu_data);

		// we could reply directly here by using the peer_manager passed as parameter.
		//ie : peer_manager.send_to_all("reply"); or peer_manager.send_to(source, "reply");
	}

    const char* getAddr(char* hostName, char* str, int len) {
        char   *ptr, **pptr;
        struct hostent *hptr;
        ptr = hostName;

        if((hptr = gethostbyname(ptr)) == NULL)
        {
            printf(" gethostbyname error for host:%s\n", ptr);
            return NULL;
        } else 
        {
            return inet_ntop(hptr->h_addrtype, hptr->h_addr, str, len);
        }
    }

    /*
    * This method will get called whenever a peer connects // disconnects
    * (connection listeners can be used as disconnection listeners and vice-versa)
    */
    void connection_disconnection(breep::tcp::peer_manager& peer_manager, const breep::tcp::peer &peer)
    {
        if (peer.is_connected())
        {
            char out_msg[256] = { 0 }; 
            // someone connected
            std::cout << peer.id_as_string().substr(0, 4) << " connected!" << std::endl;
            std::string data = std::string("nodeName:") + std::string(peer_manager.nodeName);
            std::string private_key_file = "";

            //test-modify
            //private_key_file = private_key_file.append("/").append(peer_manager.nodeName).append(LOCAL_ACCOUNT_DIR).append(std::string(peer_manager.nodeName)).append(ACCOUNTKEY_POSTFIX);
            private_key_file = private_key_file.append(LOCAL_ACCOUNT_DIR).append(std::string(peer_manager.nodeName)).append(ACCOUNTKEY_POSTFIX);
            std::string private_password = PASSWD;
            std::string sig;

            data = data + "\n";

            if(!crypto_sig::Signature::ECDSASignature(private_key_file.c_str(), private_password.c_str(), data.c_str(), sizeof(data), sig, out_msg)) {
                printf("Signature message failed, because %s\n", out_msg);
                return ;
            }
            data = data + sig;

            peer_manager.send_to(peer, data);
        }
        else
        {
            
            // someone disconnected
            //这里需要根据peer的id找到node中的索引  删除。
            std::cout << peer.id_as_string().substr(0, 4) << " disconnected" << std::endl;
            for (auto &x : name_id_map)
            {
                if (x.second.compare(peer.id_as_string()) == 0)
                {
                    name_id_map.erase(x.first);
                    break;
                }
            }
            
        }
    }

    void Communication::sendTo(breep::tcp::peer_manager& peer_manager, std::string nodeName, std::string nodeID, std::string data, int type)
    {
        /*
        for (auto &x : nodes)
        {
            /*
            if (x.first.compare(nodeName) == 0)
            {
                peer_manager.send_to(x.second, data);
            }
        }
        */
        std::string private_key_file = "";
        char out_msg[256] = { 0 };

        //test-modify
        //private_key_file = private_key_file.append("/").append(peer_manager.nodeName).append(LOCAL_ACCOUNT_DIR).append(std::string(peer_manager.nodeName)).append(ACCOUNTKEY_POSTFIX);
        private_key_file = private_key_file.append(LOCAL_ACCOUNT_DIR).append(std::string(peer_manager.nodeName)).append(ACCOUNTKEY_POSTFIX);

        /*
        //error code to test the signature
        private_key_file.clear();
        private_key_file = private_key_file.append("/").append(nodeName).append(LOCAL_ACCOUNT_DIR).append(std::string(nodeName)).append(ACCOUNTKEY_POSTFIX);
        */
        std::string private_password = PASSWD;
        std::string sig;
        data = data + "\n";

        if(!crypto_sig::Signature::ECDSASignature(private_key_file.c_str(), private_password.c_str(), data.c_str(), sizeof(data), sig, out_msg)) {
            printf("Signature message failed, because %s\n", out_msg);
            return ;
        }

        std::string encrypt_string;
        switch (type)
        {
        case RSA_TYPE: {
            std::string tls_cert_path = "";

            //test-modify
            //tls_cert_path = tls_cert_path.append("/").append(peer_manager.nodeName).append(NODE_TLS_DIR).append(nodeName).append(TLSCERT_POSTFIX);
            tls_cert_path = tls_cert_path.append(NODE_TLS_DIR).append(nodeName).append(TLSCERT_POSTFIX);
            if((encrypt_string = crypto_sig::Rsa::EncodeRSAKeyFile(tls_cert_path, data+sig, out_msg)) == "") {
                    printf("Rsa Crypto failed, because %s\n", out_msg);
                    return ;                
            }
            break;
        }
        case AES_TYPE: {
            std::map<std::string, std::string>::iterator iter_key;
            iter_key = name_key_map.find(nodeName);
            if(iter_key != name_key_map.end())  {
                if((encrypt_string = crypto_sig::Aes::Crypto(data+sig, iter_key->second, out_msg)) == "") {
                    printf("AES Crypto failed, because %s\n", out_msg);
                    return ;
                }
                
            }
            else {
                std::cout<<"Do not Find the nodeName " << nodeName << " in name_key_map."<< std::endl;
                return;
            }
            break;
        }
        default:
            std::cout<<"The encrypto type " << type << " is not supported. " << std::endl;
            return ;
        }
        for (auto&& peer_pair : peer_manager.peers() ) {
            auto& p = peer_pair.second;
            if(p.id_as_string() == nodeID) {
                std::cout<<"Send message " << std::endl << data << "to node " << nodeName << std::endl;
                peer_manager.send_to(p, encrypt_string);
                return ;    //Successful
            }
        }
        //false
        printf("Can not find the id in the m_peers, Please Check. FILE:%s, LINE: %d.\n", __FILE__, __LINE__);
    }

    void Communication::sendToall(breep::tcp::peer_manager& peer_manager, std::string data, int type)
    {
        std::string data_temp;
        std::map<std::string, std::string>::iterator iter_id;
        
        for(iter_id = name_id_map.begin(); iter_id != name_id_map.end(); iter_id++) {
            std::string nodeName = iter_id->first;
            data_temp = data;
            if (type == AES_TYPE) {
                //send test-message
                data_temp = data_temp + nodeName + ".";
            }
            sendTo(peer_manager, nodeName, iter_id->second, data_temp, type);
        }
    }
}
