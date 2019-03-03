#include "common.hpp"

// control message

// message start
string BEGIN = "CA";

//rq
string SA = "#sign-account";
string ST = "#sign-tls";
string GC = "#get-certs";
string GRL = "#get-revocation-list";
string RC = "#revoke-cert";

//sq
string SAR = "#sign-account-ready";
string SAO = "#sign-account-ok";
string STR = "#sign-tls-ready";
string STO = "#sign-tls-ok";
string GCR = "#get-certs-ready";
string GRLR = "#get-revocation-list-ready";
string RCR = "#revoke-cert-ready";

//hq
string GACO = "#get-account-csr-ok";
string GTCO = "#get-tls-csr-ok";







