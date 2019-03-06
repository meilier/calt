#ifndef _COMMON
#define _COMMON

using namespace std;
#include <string>
#ifdef __linux__
#include <vector>
#include <mutex>
#include <condition_variable>
#endif
extern string WORKDIR;
extern mutex my_mutex;
extern condition_variable my_cv;
bool readConfigFile(const char *cfgfilepath, const string &key, string &value);
vector<string> messageSplit(string message);
#endif