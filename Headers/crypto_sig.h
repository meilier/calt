#ifndef CRYPTO_SIG_H
#define CRYPTO_SIG_H


#include <stdio.h>
#include <string>


namespace crypto_sig {
//AES, RAS, ECDSA 

    class Aes {
	public:
		Aes() {};
		~Aes() {};
		static std::string Decrypto(const std::string &input, const std::string &key, char *out_msg);
		static std::string Crypto(const std::string &input, const std::string &key, char *out_msg);
	};


    class Rsa {
	public:
		Rsa() {};
		~Rsa() {};
		static std::string EncodeRSAKeyFile(const std::string& strPemFileName, const std::string& strData, char *out_msg);
		static std::string DecodeRSAKeyFile(const std::string& strPemFileName, const std::string& strData, const char *pass, char *out_msg);
	};

	class Signature {
	public:
		Signature() {};
		~Signature() {};
		static bool ECDSASignature(const char * privatekey_path, const char *pass, const char *message, int dlen, std::string& sig_string, char *out_msg);
		static bool VerifySignature(const char * publickey_path, const char *message, int dlen, std::string sig_string, char *out_msg);
	};

}

#endif	//AES_CRYPTO_H