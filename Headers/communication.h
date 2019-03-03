#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <string>
#include <boost/uuid/uuid_io.hpp>

#include "breep/network/tcp.hpp"

#define LAMDA 15

namespace communication {
//the node communication message

    void connection_disconnection(breep::tcp::peer_manager &peer_manager, const breep::tcp::peer &peer);
    const char* getAddr(char* hostName, char* str, int len);
    void handleProcess();

    class Communication{
    public:
        Communication() {};
        ~Communication() {};
        static void sendTo(breep::tcp::peer_manager&, std::string nodeName, std::string nodeID, std::string data, int type);
        static void sendToall(breep::tcp::peer_manager&, std::string data, int type);
    };

    class timed_message {
    public:
        timed_message(): m_starting_time{time(0)} { };
        void operator()(breep::tcp::peer_manager& peer_manager, const breep::tcp::peer& source, breep::cuint8_random_iterator data,
                            size_t data_size, bool /* sent_only_to_me */);

        static void handleProcess(breep::tcp::peer_manager& peer_manager);

    private:
        const time_t m_starting_time;
    };

    struct Commu_Data {
        std::string time_info;
        //breep::tcp::peer_manager peer_manager;
        std::string remote_id;
        std::string data; 
    };
}

#endif  //COMMUNICATION_H