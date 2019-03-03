#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cassert>

#include "crypto_sig.h"
#include "certificates.h"
#include "common.h"


namespace crypto_sig {

	std::string Aes::Decrypto(const std::string &input, const std::string &key, char *out_msg) {
		std::string enc_out;
		do {
			if (key.size() != 16 &&
				key.size() != 24 &&
				key.size() != 32
				) {
				sprintf(out_msg, "The key size is %d, while is invalid", (int)key.size());
				enc_out = "";
				break;
			}

			/* Input data to encrypt */
			//unsigned char aes_input[] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5 };

			/* Init vector */
			unsigned char iv[AES_BLOCK_SIZE];
			memset(iv, 0x00, AES_BLOCK_SIZE);

			/* Buffers for Encryption and Decryption */
			
			enc_out.resize(input.size());

			AES_KEY dec_key;
			/* AES-128 bit CBC Decryption */
			memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
			AES_set_decrypt_key((const unsigned char *)key.c_str(), key.size() * 8, &dec_key); // Size of key is in bits
			AES_cbc_encrypt((const unsigned char *)input.c_str(), (unsigned char *)enc_out.c_str(), enc_out.size(), &dec_key, iv, AES_DECRYPT);
			enc_out.resize(strlen(enc_out.c_str()));
		}while(false);
		return enc_out;
	}

	std::string Aes::Crypto(const std::string &input, const std::string &key, char *out_msg) {
		std::string enc_out;
		do {
			if (key.size() != 16 &&
				key.size() != 24 &&
				key.size() != 32
				) {
				sprintf(out_msg, "The key size is %d, while is invalid", (int)key.size());
				enc_out = "";
				break;
			}

			// set the encryption length
			size_t len = 0;
			if ((input.size() + 1) % AES_BLOCK_SIZE == 0) {
				len = input.size() + 1;
			} else {
				len = ((input.size() + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
			}

			// set the input string
			unsigned char* input_string = (unsigned char*)calloc(len, sizeof(unsigned char));
			if (input_string == NULL) {
				sprintf(out_msg, "Unable to allocate memory for input_string");
				enc_out = "";
				break;
			}
			strncpy((char*)input_string, input.c_str(), input.size());

			/* Init vector */
			unsigned char iv[AES_BLOCK_SIZE];
			memset(iv, 0x00, AES_BLOCK_SIZE);

			/* Buffers for Encryption and Decryption */
			
			enc_out.resize(len);

			/* AES-128 bit CBC Encryption */
			AES_KEY enc_key;
			AES_set_encrypt_key((const unsigned char *)key.c_str(), key.size() * 8, &enc_key);
			AES_cbc_encrypt((const unsigned char *)input.c_str(), (unsigned char *)enc_out.c_str(), input.size(), &enc_key, iv, AES_ENCRYPT);
			delete input_string;
		}while(false);
		return enc_out;
	}
	

	//encrypt
	std::string Rsa::EncodeRSAKeyFile(const std::string& strPemFileName, const std::string& strData, char *out_msg)
	{
		//std::cout<< "strPemFileName: " << strPemFileName << std::endl << "strData: " << strData <<std::endl;
		std::string strRet;
		RSA* pRSAPublicKey;
		FILE* hPubKeyFile;
		EVP_PKEY *pubkey = NULL;
		X509 *rsa_public_x509 = NULL;
		do {
			if (strPemFileName.empty())
			{
				sprintf(out_msg, "The RSA Encrypt strPemFileName is Empty");
				strRet = "";
				break;
			}
			if(strData.empty())
			{
				sprintf(out_msg, "The RSA Encrypt strData is Empty");
				strRet = "";
				break;		
			}
			//printf("first pass\n");
			hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
			if (hPubKeyFile == NULL)
			{
				sprintf(out_msg, "The RSA Encrypt open file %s is failed", strPemFileName.c_str());
				strRet = "";
				break;
			}
			//printf("second pass\n");
			
			/*
			RSA* pRSAPublicKey = RSA_new();
			if (PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
			{
				assert(false);
				return "";
			}
			*/
		
			char err_msg[256] = { 0 };

			rsa_public_x509 = certificates::Certificates::LoadCert(strPemFileName.c_str(), 0, err_msg);
			if (rsa_public_x509 == NULL) {
				sprintf(out_msg, "load cert failed, because %s", err_msg);
				strRet = "";
				break;
			}
			pubkey = X509_get_pubkey(rsa_public_x509);
			if (pubkey->type == EVP_PKEY_RSA)
			{
				//printf("pubkey is ec\n");
				pRSAPublicKey = EVP_PKEY_get1_RSA(pubkey);
				if (!pRSAPublicKey)
				{
					sprintf(out_msg, "get rsa public key fail");
					strRet = "";
					break;
				}
			}

			//printf("third pass\n");
			int nLen = RSA_size(pRSAPublicKey);
			char* pEncode = new char[nLen + 1];
			int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
			if (ret >= 0)
			{
				strRet = std::string(pEncode, ret);
			}
			delete[] pEncode;
		}while(false);

		if (rsa_public_x509) X509_free(rsa_public_x509);
		if (pubkey) EVP_PKEY_free(pubkey);
		if(pRSAPublicKey)
			RSA_free(pRSAPublicKey);
		if(hPubKeyFile)
			fclose(hPubKeyFile);
		CRYPTO_cleanup_all_ex_data();
		return strRet;
	}

	//decrypt
	std::string Rsa::DecodeRSAKeyFile(const std::string& strPemFileName, const std::string& strData, const char *pass, char *out_msg)
	{
		std::string strRet;
		FILE* hPriKeyFile;
		RSA* pRSAPriKey;
		EVP_PKEY *prkey = NULL;
		do {
			if (strPemFileName.empty())
			{
				sprintf(out_msg, "The RSA Decrypt strPemFileName is Empty");
				strRet = "";
				break;
			}
			if(strData.empty())
			{
				sprintf(out_msg, "The RSA Decrypt strData is Empty");
				strRet = "";
				break;			
			}
			hPriKeyFile = fopen(strPemFileName.c_str(), "rb");
			if (hPriKeyFile == NULL)
			{
				sprintf(out_msg, "The RSA Decrypt open file %s is failed", strPemFileName.c_str());
				strRet = "";
				break;
			}

			/*
			RSA* pRSAPriKey = RSA_new();
			if (PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, (void*)pass) == NULL)
			{
				assert(false);
				return "";
			}
			*/
			char err_msg[256] = { 0 };
			
			prkey = certificates::Certificates::LoadKey(strPemFileName.c_str(), 0, RSA_TYPE, pass, err_msg);
			if (prkey == NULL) {
				sprintf(out_msg, "get rsa EVP private key fail, because %s", err_msg);
				strRet = "";
				break;
			}

			if (prkey->type == EVP_PKEY_RSA)
			{
				//printf("pubkey is ec\n");
				pRSAPriKey = EVP_PKEY_get1_RSA(prkey);
				if (!pRSAPriKey)
				{
					sprintf(out_msg, "get rsa public key fail");
					strRet = "";
					break;
				}
			}

			int nLen = RSA_size(pRSAPriKey);
			char* pDecode = new char[nLen + 1];

			int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
			if (ret >= 0)
			{
				strRet = std::string((char*)pDecode, ret);
			}
			delete[] pDecode;
		}while(false);

		if (prkey) EVP_PKEY_free(prkey);
		if(pRSAPriKey)
			RSA_free(pRSAPriKey);
		if(hPriKeyFile)
			fclose(hPriKeyFile);
		CRYPTO_cleanup_all_ex_data();
		return strRet;
	}


	bool Signature::ECDSASignature(const char * privatekey_path, const char *pass, const char *message, int dlen, 
									std::string& sig_string, char *out_msg) {
		bool bret = false;
		EVP_PKEY *prkey = NULL;
		EC_KEY *ec_key = NULL;
		EVP_MD_CTX md_ctx;
		do {
			unsigned char digest[EVP_MAX_MD_SIZE];
			unsigned int digest_len = 0;
			
			//BIO    *pbio_key_file = NULL;
			unsigned char sig_buf[10240] = { 0 };
			unsigned int sig_len = 0;
			/*get key from pem file*/
			/*
			pbio_key_file = BIO_new_file(privatekey_path, "rb");
			ec_key = PEM_read_bio_ECPrivateKey(pbio_key_file, NULL, NULL, (void*)pass);
			if (!ec_key)
			{
				printf("get key fail \n");
				return false;
			}
			*/

			char err_msg[256] = { 0 };	
			prkey = certificates::Certificates::LoadKey(privatekey_path, 0, ECC_TYPE, pass, err_msg);
			if (prkey == NULL) {
				sprintf(out_msg, "get ecc EVP private key fail, because %s", err_msg);
				break;
			}

			if (prkey->type == EVP_PKEY_EC)
			{
				//printf("pubkey is ec\n");
				ec_key = EVP_PKEY_get1_EC_KEY(prkey);
				if (!ec_key)
				{
					sprintf(out_msg, "get ecc private key fail");
					break;
				}
			}

			//sha256:calculate hash
			EVP_MD_CTX_init(&md_ctx);
			if (!EVP_DigestInit(&md_ctx, EVP_sha256()))
			{
				sprintf(out_msg, "EVP_digest fail");
				break;
			}
			if (!EVP_DigestUpdate(&md_ctx, (const void *)message, dlen))
			{
				sprintf(out_msg, "EVP_DigestUpdate fail");
				break;
			}
			if (!EVP_DigestFinal(&md_ctx, digest, &digest_len))
			{
				sprintf(out_msg, "EVP_DigestFinal fail");        
				break;
			}
			
			/*do sign*/
			if (!ECDSA_sign(0, digest, digest_len, sig_buf, &sig_len, ec_key))
			{
				sprintf(out_msg, "ECDSA_sign fail");
				break;
			}
			/*
			if (pbio_key_file)
			{
				BIO_free(pbio_key_file);
				pbio_key_file = NULL;
			}
			*/

			sig_string = reinterpret_cast<char*>(sig_buf);
			
			std::cout << "length of sig:" << sig_string.length() << std::endl;
			bret = true;
		}while(false);

		if (prkey) EVP_PKEY_free(prkey);
		if (ec_key)	EC_KEY_free(ec_key);
		EVP_MD_CTX_cleanup(&md_ctx);
		return bret;
	}

	bool Signature::VerifySignature(const char * publickey_path, const char *message, int dlen, 
									std::string sig_string, char *out_msg) {
		//BIO * pbio_key_file;
		int ret;
		bool bret = false;
		EVP_MD_CTX md_ctx;
		EC_KEY * ec_key;
		EVP_PKEY *pubkey = NULL;
		X509 *usrCert = NULL;
		do {
			unsigned char digest[EVP_MAX_MD_SIZE];
			unsigned int digest_len = 0;
			
			//unsigned char Cert[4099];
			//unsigned long Certlen;
			//unsigned char *pTmp = NULL;
			//X509 *usrCert = NULL;               //the struct of X509 certificate
			//FILE *fp;

			const unsigned char *sig_buf = reinterpret_cast<const unsigned char *>(sig_string.c_str());
			int sig_len = sig_string.length();
			/*
			fp = fopen(publickey_path, "rb");
			if (fp == NULL)
			{
				printf("read cert file fail \n");
				return false;
			}
			Certlen = fread(Cert, 1, 4096, fp);
			fclose(fp);
			
			pTmp = Cert;
			//Convert to x509 data
			usrCert = d2i_X509(NULL, (const unsigned char **)&pTmp, Certlen);
			if (usrCert == NULL)
			{    
				//Determine whether or not is a PEM certificate/
				pbio_key_file = BIO_new_file(publickey_path, "r");
				usrCert = PEM_read_bio_X509(pbio_key_file, NULL, NULL, NULL);
				if (usrCert == NULL)
				{
					printf("format conver error\n");
					return false;
				}
			}
			*/
			char err_msg[256] = { 0 };

			usrCert = certificates::Certificates::LoadCert(publickey_path, 0, err_msg);
			if (usrCert == NULL) {
				sprintf(out_msg, "load cert failed, because %s", err_msg);
				break;
			}
			pubkey = X509_get_pubkey(usrCert);


			//EVP_PKEY * pubKey = X509_get_pubkey(usrCert);
			if (pubkey->type == EVP_PKEY_EC)
			{
				//printf("pubkey is ec\n");
				ec_key = EVP_PKEY_get1_EC_KEY(pubkey);
				if (!ec_key)
				{
					sprintf(out_msg, "get key fail");
					break;
				}
			}
			
			/*
			//printf the key data
			printf("EC_key is: \n");
			derpubkeyLen = i2d_EC_PUBKEY(ec_key, &pTmp);
			for (int i = 0; i < derpubkeyLen; i++)
			{
				printf("%02x", derpubkey[i]);
			}
			*/

			
			EVP_MD_CTX_init(&md_ctx);
			if (!EVP_DigestInit(&md_ctx, EVP_sha256()))
			{
				sprintf(out_msg, "EVP_digest fail");
				break;
			}
			if (!EVP_DigestUpdate(&md_ctx, (const void *)message, dlen))
			{
				sprintf(out_msg, "EVP_DigestUpdate fail");
				break;
			}
			if (!EVP_DigestFinal(&md_ctx, digest, &digest_len))
			{
				sprintf(out_msg, "EVP_DigestFinal fail");
				break;
			}
			
			/*do verify*/
			ret = ECDSA_verify(0, (const unsigned char *)digest, digest_len, sig_buf, sig_len, ec_key);
			if(ret == 1) {
				bret = true;
			}
			else {
				sprintf(out_msg, "Verify Signature is failed ,the sig and the pub key is not match.");
				break;
			}
		}while(false);


		/*
		if (pbio_key_file)
		{
			BIO_free(pbio_key_file);
			pbio_key_file = NULL;
		}
		*/
		if (pubkey) EVP_PKEY_free(pubkey);
		if (ec_key)	EC_KEY_free(ec_key);
		EVP_MD_CTX_cleanup(&md_ctx);
		if (usrCert) X509_free(usrCert);

		return bret;
	}




}