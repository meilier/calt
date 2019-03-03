#ifndef _COMMON
#define _COMMON

using namespace std;
#include <string>
#ifdef __linux__
#include <vector>
#endif
extern string WORKDIR;
bool readConfigFile(const char *cfgfilepath, const string &key, string &value);
vector<string> messageSplit(string message);
#endif