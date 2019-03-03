#include "common.hpp"
#include <fstream>
#include <iostream>
#include <vector>
string WORKDIR;

bool readConfigFile(const char *cfgfilepath, const string &key, string &value)
{
    fstream cfgFile;
    cfgFile.open(cfgfilepath); //打开文件
    printf("path is %s\n", cfgfilepath);
    if (!cfgFile.is_open())
    {
        cout << "can not open cfg file!" << endl;
        return false;
    }
    char tmp[1000];
    while (!cfgFile.eof()) //read recursive
    {
        cfgFile.getline(tmp, 1000); //
        string line(tmp);
        printf("line is %s\n", line.c_str());
        size_t pos = line.find('='); //find =
        if (pos == string::npos)
            continue;
        string tmpKey = line.substr(0, pos); //get content in front of =
        printf("tmpKey is %s\n", tmpKey.c_str());
        if (key == tmpKey)
        {
            value = line.substr(pos + 1); //get content behind =
            return true;
        }
    }
    return false;
}

vector<string> messageSplit(string message)
{
    //split symbol #
    //m = new char[message.length()+1];
    vector<string> ms;
    //string message("#sign-account#sign-tls");
    int pos = 0;
    int prepos = 0;
    printf("Looking for the '#' character in \"%s\"...\n", message.c_str());
    //printf("pos is %d\n",pos);
    pos = message.find('#', pos);
    while (pos != string::npos)
    {
        printf("found at %d\n", pos);
        //add each message to vector
        if (pos - prepos != 0)
        {
            ms.push_back(message.substr(prepos, pos - prepos));
        }
        prepos = pos;
        pos = message.find('#', pos + 1);
    }
    ms.push_back(message.substr(prepos, message.size() - prepos));
    for (auto it = ms.begin(); it != ms.end(); it++)
    {
        cout << *it << endl;
    }

    return ms;
}
