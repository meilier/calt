#ifndef CERTIFICATES_H
#define CERTIFICATES_H


#include <stdio.h>
#include <string>
#include <openssl/x509v3.h>


namespace certificates {
//check the cert

    class Certificates {
	public:
		Certificates() {};
		~Certificates() {};

        static X509 *LoadCert(const char *cert, int certlen, char *out_msg);
        static X509 *load_cert(BIO *cert, int format, char *pwd, char *out_msg);
        static EVP_PKEY *load_key(BIO *bio, int type, const char *pass, char *out_msg);
        static EVP_PKEY *LoadKey(const char *key, int keylen, int type, const char *pass, char *out_msg);
        static bool CheckRootCert(const char *root_file_path, char *out_msg);
        static bool CheckRootCert(X509 *x509, char *err_msg);
        static bool GetCertSerial(const char *certfile, char *serial, char *out_msg);
        static bool GetCertSerial(X509 *x509, char *serial, char *out_msg);
        //检查 issuer_cert_file 是否是 subject_cert_file 的签发者
        //检查 subject_cert_file 和 key_file 是否匹配
        static bool CheckEntityCert(const char *issuer_cert_file, const char *subject_cert_file, const char *key_file, int type, const char *password, char *out_msg);
        static bool CheckCertValidity(X509 *x509, char *not_before, char *not_after, char *out_msg);

        static int asn1_time_to_tm(struct tm *tm, const ASN1_TIME *t);
        static int asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d);
        static int OPENSSL_gmtime_adj(struct tm *tm, int off_day, long offset_sec);
        static long date_to_julian(int y, int m, int d);
        static int julian_adj(const struct tm *tm, int off_day, long offset_sec, long *pday, int *psec);
        static void julian_to_date(long jd, int *y, int *m, int *d);
        static int asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d);
        static struct tm *OPENSSL_gmtime(const time_t *timer, struct tm *result);

		// check certificate
        //verify_file 根证书; chain_file 节点证书; private_key_file aes加密后节点的私钥; 
	    static int CheckCertificate(const std::string& verify_file, const std::string& chain_file,
		const std::string& private_key_file, int type, const std::string& private_password, char *serial, char *out_msg);

	};
}

#endif	//CERTIFICATES_H