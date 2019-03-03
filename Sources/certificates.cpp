#include <iostream>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>
#include <string.h>
#include <time.h>

#include "certificates.h"
#include "common.h"

#define PRINT_CERTIFICATES true
#define PEM 3
#define SECS_PER_DAY (24 * 60 * 60)

namespace certificates {

    X509 *Certificates::LoadCert(const char *cert, int certlen, char *out_msg) {
        BIO *in = NULL;
        X509 *x509 = NULL;
        if (certlen == 0) {
            if ((in = BIO_new_file(cert, "r")) == NULL) {
                sprintf(out_msg, "open certificate file(%s) failed", cert);
                return NULL;
            }
        }
        else {
            if ((in = BIO_new_mem_buf((void*)cert, certlen)) == NULL) {
                strcpy(out_msg, "make Memory BIO Error");
                return NULL;
            }
        }
        /*
        if ((x509 = load_cert(in, DER, NULL, out_msg)) == NULL)
        {
            BIO_reset(in);
            memset(out_msg, 0, strlen(out_msg));
            x509 = load_cert(in, PEM, NULL, out_msg);  
        }
        */
        if((x509 = load_cert(in, PEM, NULL, out_msg)) == NULL)
            printf("load cert failed in fun LoadCert.ERROR!!\n");
        if (in != NULL) BIO_free(in);
        return x509;
    }

    X509 *Certificates::load_cert(BIO *cert, int format, char *pwd, char *out_msg) {
        X509 *x = NULL;
        bool format_valid = true;
        switch (format)
        {
        /*
        case DER:
            x = d2i_X509_bio(cert, NULL);
            break;
        */
        case PEM:
            x = PEM_read_bio_X509(cert, NULL, NULL, NULL);
            break;
        /*
        case P12:
            {
                PKCS12 *p12 = d2i_PKCS12_bio(cert, NULL);
                PKCS12_parse(p12, pwd, NULL, &x, NULL);
                PKCS12_free(p12);
                p12 = NULL;
            }
            break;
        */
        default:
            format_valid = false;
            strcpy(out_msg, "bad input format specified for input cert");
            break;
        }
        if (x == NULL && format_valid) {
            strcpy(out_msg, "unable to load certificate");
        }
        return x;
    }

    EVP_PKEY *Certificates::load_key(BIO *bio, int type, const char *pass, char *out_msg) {
        EC_KEY *ec_key = NULL;
        RSA *rsa = NULL;
        EVP_PKEY *pkey = NULL;
        bool type_valid = true;
        
        switch (type) {
        case RSA_TYPE:
            rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, (void*)pass);
            break;
        
        case ECC_TYPE:
            //PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u);
            //PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **key, pem_password_cb *cb, void *u);
            ec_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, (void*)pass);
            break;
        /*
        case P12:
            {
                PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
                PKCS12_parse(p12, pass, &pkey, NULL, NULL);
                PKCS12_free(p12);
                p12 = NULL;
            }
            break;
        */
        default:
            type_valid = false;
            sprintf(out_msg, "bad input type specified for key");
            break;
        }

        if (ec_key) {
            pkey = EVP_PKEY_new();
            //int EVP_PKEY_assign_RSA(EVP_PKEY *pkey,RSA *key);
            //int EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey,EC_KEY *key);
            if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
                strcpy(out_msg, "EVP_PKEY_assign_EC_KEY failed");
            }
        }
        else if (rsa) {
            pkey = EVP_PKEY_new();
            if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
                strcpy(out_msg, "EVP_PKEY_assign_RSA failed");
            }
        }
        if (NULL == pkey && type_valid) {
            sprintf(out_msg, "password of Private Key is invalid");
        }
        //printf("type:%d, pass:%s\n", type, pass);
        return pkey;
    }

    EVP_PKEY *Certificates::LoadKey(const char *key, int keylen, int type, const char *pass, char *out_msg) {
        EVP_PKEY *pkey = NULL;
        BIO *in = NULL;
        do {
            OpenSSL_add_all_algorithms();
            if (keylen == 0) {// in file
                if ((in = BIO_new_file(key, "r")) == NULL) {
                    sprintf(out_msg, "open certificate file(%s) failed", key);
                    break;
                }
            }
            else { // in memory
                if ((in = BIO_new_mem_buf((void*)key, keylen)) == NULL) {
                    strcpy(out_msg, "make member bio error");
                    break;
                }
            }
            /*
            if ((pkey = load_key(in, DER, pass, out_msg)) == NULL) {
                // BIO can read and write, so the data in BIO must be clearned; 
                // or BIO only can read, this operation only set the point to head
                BIO_reset(in);
                memset(out_msg, 0, strlen(out_msg));
                pkey = load_key(in, PEM, pass, out_msg);
            }
            */
            if ((pkey = load_key(in, type, pass, out_msg)) == NULL) {
                printf("load key is NULL, please check the key file.ERROR!!!\n");
            }
        } while (false);
        if (in != NULL) BIO_free(in);
        return pkey;
    }

    bool Certificates::CheckRootCert(const char *root_file_path, char *out_msg) {
        bool bret = false;
        X509 *x509 = NULL;
        do {
            x509 = LoadCert(root_file_path, 0, out_msg);
            if (x509 == NULL) {
                break;
            }

            bret = CheckRootCert(x509, out_msg);
        } while (false);

        if (x509) X509_free(x509);
        return bret;
    }

    bool Certificates::CheckRootCert(X509 *x509, char *err_msg) {
        bool bret = false;
        do {
            if (NULL == x509) {
                sprintf(err_msg, "the x509 of the certificate is null");
                break;
            }

            // check the validity
            char not_before[20] = { 0 };
            char not_after[20] = { 0 };
            if (false == CheckCertValidity(x509, not_before, not_after, err_msg)) {
                break;
            }
            /*
            if(PRINT_CERTIFICATES) {
                printf("not_before:%s\n", not_before);
                printf("not_after:%s\n", not_after);
            }
            */
            bret = true;
        } while (false);

        return bret;
    }

    bool Certificates::GetCertSerial(const char *certfile, char *serial, char *out_msg) {
        bool bret = false;
        X509 *x509 = NULL;
        BIGNUM *serial_num = NULL;
        do {
            x509 = LoadCert(certfile, 0, out_msg);
            if (x509 == NULL) {
                sprintf(out_msg, "load ca %s failed", certfile);
                break;
            }
            OpenSSL_add_all_digests();
            ASN1_INTEGER *ai = NULL;
            if ((ai = X509_get_serialNumber(x509)) == NULL) {
                strcpy(out_msg, "X509_get_serialNumber failed");
                break;
            }
            serial_num = BN_new();
            if (ASN1_INTEGER_to_BN(ai, serial_num) == NULL) {
                strcpy(out_msg, "ASN1_INTEGER_to_BN failed");
                break;
            }
            strcpy(serial, BN_bn2hex(serial_num));
            bret = true;
        } while (false);
        if (x509) X509_free(x509);
        if (serial_num) BN_free(serial_num);
        return bret;
    }

    bool Certificates::GetCertSerial(X509 *x509, char *serial, char *out_msg) {
        bool bret = false;
        BIGNUM *serial_num = NULL;
        do {
            if (NULL == x509) {
                sprintf(out_msg, "the handle of the certificate is null");
                break;
            }
            if (NULL == out_msg) {
                break;
            }
            OpenSSL_add_all_digests();
            ASN1_INTEGER *ai = NULL;
            if ((ai = X509_get_serialNumber(x509)) == NULL) {
                strcpy(out_msg, "X509_get_serialNumber failed");
                break;
            }
            serial_num = BN_new();
            if (ASN1_INTEGER_to_BN(ai, serial_num) == NULL) {
                strcpy(out_msg, "ASN1_INTEGER_to_BN failed");
                break;
            }
            strcpy(serial, BN_bn2hex(serial_num));
            bret = true;
        } while (false);

        if (serial_num) BN_free(serial_num);
        return bret;
    }

    bool Certificates::CheckEntityCert(const char *issuer_cert_file, const char *subject_cert_file, const char *key_file, int type, const char *password, char *out_msg) {
        bool bret = false;
        X509 *issuer_x509 = NULL, *subject_x509 = NULL;
        EVP_PKEY *prkey = NULL;
        EVP_PKEY *pubkey = NULL;
        do {
            issuer_x509 = LoadCert(issuer_cert_file, 0, out_msg);
            if (issuer_x509 == NULL) {
                break;
            }
            subject_x509 = LoadCert(subject_cert_file, 0, out_msg);
            if (subject_x509 == NULL) {
                break;
            }

            if (X509_check_issued(issuer_x509, subject_x509) != X509_V_OK) {
                sprintf(out_msg, "the root certificate(%s) is not the issuer of entity certificate(%s)", issuer_cert_file, subject_cert_file);
                break;
            }

            pubkey = X509_get_pubkey(issuer_x509);
            if (!X509_verify(subject_x509, pubkey)) {
                sprintf(out_msg, "the signature of root certificate(%s) doesn't match issuer of entity certificate(%s)", issuer_cert_file, subject_cert_file);
                break;                
            }

            prkey = LoadKey(key_file, 0, type, password, out_msg);
            if (prkey == NULL) {
                break;
            }
            if (!X509_check_private_key(subject_x509, prkey)) {
                sprintf(out_msg, "certificate and private key do not match");
                break;
            }
            if (!CheckCertValidity(subject_x509, NULL, NULL, out_msg)) {
                break;
            }
            bret = true;
        } while (false);

        if (issuer_x509) X509_free(issuer_x509);
        if (subject_x509) X509_free(subject_x509);
        if (prkey) EVP_PKEY_free(prkey);
        return bret;
    }

    bool Certificates::CheckCertValidity(X509 *x509, char *not_before, char *not_after, char *out_msg) {
        bool bret = false;
        do {
            if (NULL == x509) {
                sprintf(out_msg, "certificate can not be null");
                break;
            }

            ASN1_TIME* not_before_time = X509_get_notBefore(x509);
            if (X509_cmp_current_time(not_before_time) > 0) {
                sprintf(out_msg, "the begin time of the certificate can not later than the current time");
                break;
            }

            ASN1_TIME* not_after_time = X509_get_notAfter(x509);
            if (X509_cmp_current_time(not_after_time) < 0) {
                sprintf(out_msg, "the end time of the certificate can not earlier than the current time");
                break;
            }

            struct tm tm_not_before;
            if (asn1_time_to_tm(&tm_not_before, not_before_time) != 1) {
                sprintf(out_msg, "parse begin time failed, maybe the certificate is broken");
                break;
            }

            struct tm tm_not_after;
            if (asn1_time_to_tm(&tm_not_after, not_after_time) != 1) {
                sprintf(out_msg, "parse end time failed, maybe the certificate is broken");
                break;
            }

            if (not_before != NULL) {
                int hour = (1 == tm_not_before.tm_isdst) ? (tm_not_before.tm_hour + 7 >= 24 ? (tm_not_before.tm_hour - 17) : (tm_not_before.tm_hour + 7))
                    : (tm_not_before.tm_hour + 8 >= 24 ? (tm_not_before.tm_hour - 16) : (tm_not_before.tm_hour + 8));
                sprintf(not_before, "%04d%02d%02d%02d%02d%02d", tm_not_before.tm_year + 1900, tm_not_before.tm_mon + 1, tm_not_before.tm_mday,
                    hour, tm_not_before.tm_min, tm_not_before.tm_sec);
            }
            
            if (not_after != NULL) {
                int hour = (1 == tm_not_after.tm_isdst) ? (tm_not_after.tm_hour + 7 >= 24 ? (tm_not_after.tm_hour - 17) : (tm_not_after.tm_hour + 7))
                    : (tm_not_after.tm_hour + 8 >= 24 ? (tm_not_after.tm_hour - 16) : (tm_not_after.tm_hour + 8));
                sprintf(not_after, "%04d%02d%02d%02d%02d%02d", tm_not_after.tm_year + 1900, tm_not_after.tm_mon + 1, tm_not_after.tm_mday,
                    hour, tm_not_after.tm_min, tm_not_after.tm_sec);
            }

            bret = true;
        } while (false);

        return bret;
    }

	int Certificates::CheckCertificate(const std::string& verify_file, const std::string& chain_file,
		const std::string& private_key_file, int type, const std::string& private_password, char *serial, char *out_msg) {
		int iret = 0;
		do {
			char err_msg[256] = { 0 };
			// check certificate
			std::string verify_file_full = verify_file;

			std::string chain_file_full = chain_file;

			std::string priv_key_file_full = private_key_file;

			if (!CheckRootCert(verify_file_full.c_str(), err_msg)) {
				sprintf(out_msg, "this ca certificate is invalid, %s", err_msg);
				break;
			}
            if(PRINT_CERTIFICATES)
                printf("check the ca certificate successful.\n");

			if (!CheckEntityCert(verify_file_full.c_str(), chain_file_full.c_str(), priv_key_file_full.c_str(), type, private_password.c_str(), err_msg)) {
				sprintf(out_msg, "this node certificate is invalid, %s", err_msg);
				break;
			}
            if(PRINT_CERTIFICATES)
                printf("check the node certificate successful.\n");

			// get serial number
			if (!GetCertSerial(chain_file_full.c_str(), serial, err_msg)) {
				sprintf(out_msg, "get serial number failed, %s", err_msg);
				break;
			}
            if(PRINT_CERTIFICATES)
                printf("get the serial number successful.\n");

			iret = 1;
		} while (false);

		return iret;
	}



    //openssl 1.1.1新版本中才有
    int Certificates::asn1_time_to_tm(struct tm *tm, const ASN1_TIME *t) {
        if (t == NULL) {
            time_t now_t;
            time(&now_t);
            if (OPENSSL_gmtime(&now_t, tm))
                return 1;
            return 0;
        }

        if (t->type == V_ASN1_UTCTIME)
            return asn1_utctime_to_tm(tm, t);
        else if (t->type == V_ASN1_GENERALIZEDTIME)
            return asn1_generalizedtime_to_tm(tm, t);

        return 0;
    }

    int Certificates::asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d) {
        static const int min[8] = { 0, 1, 1, 0, 0, 0, 0, 0 };
        static const int max[8] = { 99, 12, 31, 23, 59, 59, 12, 59 };
        char *a;
        int n, i, l, o;

        if (d->type != V_ASN1_UTCTIME)
            return (0);
        l = d->length;
        a = (char *)d->data;
        o = 0;

        if (l < 11)
            goto err;
        for (i = 0; i < 6; i++) {
            if ((i == 5) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
                i++;
                if (tm)
                    tm->tm_sec = 0;
                break;
            }
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            if (++o > l)
                goto err;

            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            if (++o > l)
                goto err;

            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                switch (i) {
                case 0:
                    tm->tm_year = n < 50 ? n + 100 : n;
                    break;
                case 1:
                    tm->tm_mon = n - 1;
                    break;
                case 2:
                    tm->tm_mday = n;
                    break;
                case 3:
                    tm->tm_hour = n;
                    break;
                case 4:
                    tm->tm_min = n;
                    break;
                case 5:
                    tm->tm_sec = n;
                    break;
                }
            }
        }
        if (a[o] == 'Z')
            o++;
        else if ((a[o] == '+') || (a[o] == '-')) {
            int offsign = a[o] == '-' ? -1 : 1, offset = 0;
            o++;
            if (o + 4 > l)
                goto err;
            for (i = 6; i < 8; i++) {
                if ((a[o] < '0') || (a[o] > '9'))
                    goto err;
                n = a[o] - '0';
                o++;
                if ((a[o] < '0') || (a[o] > '9'))
                    goto err;
                n = (n * 10) + a[o] - '0';
                if ((n < min[i]) || (n > max[i]))
                    goto err;
                if (tm) {
                    if (i == 6)
                        offset = n * 3600;
                    else if (i == 7)
                        offset += n * 60;
                }
                o++;
            }
            if (offset && !OPENSSL_gmtime_adj(tm, 0, offset * offsign))
                return 0;
        }
        return o == l;
    err:
        return 0;
    }

    int Certificates::OPENSSL_gmtime_adj(struct tm *tm, int off_day, long offset_sec) {
        int time_sec, time_year, time_month, time_day;
        long time_jd;

        /* Convert time and offset into julian day and seconds */
        if (!julian_adj(tm, off_day, offset_sec, &time_jd, &time_sec))
            return 0;

        /* Convert Julian day back to date */
        julian_to_date(time_jd, &time_year, &time_month, &time_day);
        if (time_year < 1900 || time_year > 9999)
            return 0;

        /* Update tm structure */
        tm->tm_year = time_year - 1900;
        tm->tm_mon = time_month - 1;
        tm->tm_mday = time_day;

        tm->tm_hour = time_sec / 3600;
        tm->tm_min = (time_sec / 60) % 60;
        tm->tm_sec = time_sec % 60;

        return 1;

    }

    long Certificates::date_to_julian(int y, int m, int d) {
        return (1461 * (y + 4800 + (m - 14) / 12)) / 4 +
            (367 * (m - 2 - 12 * ((m - 14) / 12))) / 12 -
            (3 * ((y + 4900 + (m - 14) / 12) / 100)) / 4 + d - 32075;
    }

    int Certificates::julian_adj(const struct tm *tm, int off_day, long offset_sec, long *pday, int *psec)
    {
        int offset_hms, offset_day;
        long time_jd;
        int time_year, time_month, time_day;
        /* split offset into days and day seconds */
        offset_day = offset_sec / SECS_PER_DAY;
        /* Avoid sign issues with % operator */
        offset_hms = offset_sec - (offset_day * SECS_PER_DAY);
        offset_day += off_day;
        /* Add current time seconds to offset */
        offset_hms += tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
        /* Adjust day seconds if overflow */
        if (offset_hms >= SECS_PER_DAY) {
            offset_day++;
            offset_hms -= SECS_PER_DAY;
        }
        else if (offset_hms < 0) {
            offset_day--;
            offset_hms += SECS_PER_DAY;
        }

        /*
        * Convert date of time structure into a Julian day number.
        */
        time_year = tm->tm_year + 1900;
        time_month = tm->tm_mon + 1;
        time_day = tm->tm_mday;

        time_jd = date_to_julian(time_year, time_month, time_day);

        /* Work out Julian day of new date */
        time_jd += offset_day;

        if (time_jd < 0)
            return 0;

        *pday = time_jd;
        *psec = offset_hms;
        return 1;
    }

    void Certificates::julian_to_date(long jd, int *y, int *m, int *d) {
        long L = jd + 68569;
        long n = (4 * L) / 146097;
        long i, j;

        L = L - (146097 * n + 3) / 4;
        i = (4000 * (L + 1)) / 1461001;
        L = L - (1461 * i) / 4 + 31;
        j = (80 * L) / 2447;
        *d = L - (2447 * j) / 80;
        L = j / 11;
        *m = j + 2 - (12 * L);
        *y = 100 * (n - 49) + i + L;
    }

    int Certificates::asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d)
    {
        static const int min[9] = { 0, 0, 1, 1, 0, 0, 0, 0, 0 };
        static const int max[9] = { 99, 99, 12, 31, 23, 59, 59, 12, 59 };
        char *a;
        int n, i, l, o;

        if (d->type != V_ASN1_GENERALIZEDTIME)
            return (0);
        l = d->length;
        a = (char *)d->data;
        o = 0;
        /*
        * GENERALIZEDTIME is similar to UTCTIME except the year is represented
        * as YYYY. This stuff treats everything as a two digit field so make
        * first two fields 00 to 99
        */
        if (l < 13)
            goto err;
        for (i = 0; i < 7; i++) {
            if ((i == 6) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
                i++;
                if (tm)
                    tm->tm_sec = 0;
                break;
            }
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            if (++o > l)
                goto err;

            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            if (++o > l)
                goto err;

            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                switch (i) {
                case 0:
                    tm->tm_year = n * 100 - 1900;
                    break;
                case 1:
                    tm->tm_year += n;
                    break;
                case 2:
                    tm->tm_mon = n - 1;
                    break;
                case 3:
                    tm->tm_mday = n;
                    break;
                case 4:
                    tm->tm_hour = n;
                    break;
                case 5:
                    tm->tm_min = n;
                    break;
                case 6:
                    tm->tm_sec = n;
                    break;
                }
            }
        }
        /*
        * Optional fractional seconds: decimal point followed by one or more
        * digits.
        */
        if (a[o] == '.') {
            if (++o > l)
                goto err;
            i = o;
            while ((a[o] >= '0') && (a[o] <= '9') && (o <= l))
                o++;
            /* Must have at least one digit after decimal point */
            if (i == o)
                goto err;
        }

        if (a[o] == 'Z')
            o++;
        else if ((a[o] == '+') || (a[o] == '-')) {
            int offsign = a[o] == '-' ? -1 : 1, offset = 0;
            o++;
            if (o + 4 > l)
                goto err;
            for (i = 7; i < 9; i++) {
                if ((a[o] < '0') || (a[o] > '9'))
                    goto err;
                n = a[o] - '0';
                o++;
                if ((a[o] < '0') || (a[o] > '9'))
                    goto err;
                n = (n * 10) + a[o] - '0';
                if ((n < min[i]) || (n > max[i]))
                    goto err;
                if (tm) {
                    if (i == 7)
                        offset = n * 3600;
                    else if (i == 8)
                        offset += n * 60;
                }
                o++;
            }
            if (offset && !OPENSSL_gmtime_adj(tm, 0, offset * offsign))
                return 0;
        }
        else if (a[o]) {
            /* Missing time zone information. */
            goto err;
        }
        return (o == l);
    err:
        return (0);
    }

    struct tm *Certificates::OPENSSL_gmtime(const time_t *timer, struct tm *result) {
        struct tm *ts = NULL;

    #if defined(OPENSSL_THREADS) && !defined(OPENSSL_SYS_WIN32) && !defined(OPENSSL_SYS_OS2) && (!defined(OPENSSL_SYS_VMS) || defined(gmtime_r)) && !defined(OPENSSL_SYS_MACOSX) && !defined(OPENSSL_SYS_SUNOS)
        /*
        * should return &data, but doesn't on some systems, so we don't even
        * look at the return value
        */
        gmtime_r(timer, result);
        ts = result;
    #elif !defined(OPENSSL_SYS_VMS) || defined(VMS_GMTIME_OK)
        ts = gmtime(timer);
        if (ts == NULL)
            return NULL;

        memcpy(result, ts, sizeof(struct tm));
        ts = result;
    #endif
    #if defined( OPENSSL_SYS_VMS) && !defined( VMS_GMTIME_OK)
        if (ts == NULL) {
            static $DESCRIPTOR(tabnam, "LNM$DCL_LOGICAL");
            static $DESCRIPTOR(lognam, "SYS$TIMEZONE_DIFFERENTIAL");
            char logvalue[256];
            unsigned int reslen = 0;
    # if __INITIAL_POINTER_SIZE == 64
            ILEB_64 itemlist[2], *pitem;
    # else
            ILE3 itemlist[2], *pitem;
    # endif
            int status;
            time_t t;


            /*
            * Setup an itemlist for the call to $TRNLNM - Translate Logical Name.
            */
            pitem = itemlist;

    # if __INITIAL_POINTER_SIZE == 64
            pitem->ileb_64$w_mbo = 1;
            pitem->ileb_64$w_code = LNM$_STRING;
            pitem->ileb_64$l_mbmo = -1;
            pitem->ileb_64$q_length = sizeof (logvalue);
            pitem->ileb_64$pq_bufaddr = logvalue;
            pitem->ileb_64$pq_retlen_addr = (unsigned __int64 *)&reslen;
            pitem++;
            /* Last item of the item list is null terminated */
            pitem->ileb_64$q_length = pitem->ileb_64$w_code = 0;
    # else
            pitem->ile3$w_length = sizeof (logvalue);
            pitem->ile3$w_code = LNM$_STRING;
            pitem->ile3$ps_bufaddr = logvalue;
            pitem->ile3$ps_retlen_addr = (unsigned short int *) &reslen;
            pitem++;
            /* Last item of the item list is null terminated */
            pitem->ile3$w_length = pitem->ile3$w_code = 0;
    # endif


            /* Get the value for SYS$TIMEZONE_DIFFERENTIAL */
            status = sys$trnlnm(0, &tabnam, &lognam, 0, itemlist);
            if (!(status & 1))
                return NULL;
            logvalue[reslen] = '\0';

            t = *timer;

            /* The following is extracted from the DEC C header time.h */
            /*
            **  Beginning in OpenVMS Version 7.0 mktime, time, ctime, strftime
            **  have two implementations.  One implementation is provided
            **  for compatibility and deals with time in terms of local time,
            **  the other __utc_* deals with time in terms of UTC.
            */
            /*
            * We use the same conditions as in said time.h to check if we should
            * assume that t contains local time (and should therefore be
            * adjusted) or UTC (and should therefore be left untouched).
            */
    # if __CRTL_VER < 70000000 || defined _VMS_V6_SOURCE
            /* Get the numerical value of the equivalence string */
            status = atoi(logvalue);

            /* and use it to move time to GMT */
            t -= status;
    # endif

            /* then convert the result to the time structure */

            /*
            * Since there was no gmtime_r() to do this stuff for us, we have to
            * do it the hard way.
            */
            {
                /*-
                * The VMS epoch is the astronomical Smithsonian date,
                if I remember correctly, which is November 17, 1858.
                Furthermore, time is measure in thenths of microseconds
                and stored in quadwords (64 bit integers).  unix_epoch
                below is January 1st 1970 expressed as a VMS time.  The
                following code was used to get this number:

                #include <stdio.h>
                #include <stdlib.h>
                #include <lib$routines.h>
                #include <starlet.h>

                main()
                {
                unsigned long systime[2];
                unsigned short epoch_values[7] =
                { 1970, 1, 1, 0, 0, 0, 0 };

                lib$cvt_vectim(epoch_values, systime);

                printf("%u %u", systime[0], systime[1]);
                }
                */
                unsigned long unix_epoch[2] = { 1273708544, 8164711 };
                unsigned long deltatime[2];
                unsigned long systime[2];
                struct vms_vectime {
                    short year, month, day, hour, minute, second, centi_second;
                } time_values;
                long operation;

                /*
                * Turn the number of seconds since January 1st 1970 to an
                * internal delta time. Note that lib$cvt_to_internal_time() will
                * assume that t is signed, and will therefore break on 32-bit
                * systems some time in 2038.
                */
                operation = LIB$K_DELTA_SECONDS;
                status = lib$cvt_to_internal_time(&operation, &t, deltatime);

                /*
                * Add the delta time with the Unix epoch and we have the current
                * UTC time in internal format
                */
                status = lib$add_times(unix_epoch, deltatime, systime);

                /* Turn the internal time into a time vector */
                status = sys$numtim(&time_values, systime);

                /* Fill in the struct tm with the result */
                result->tm_sec = time_values.second;
                result->tm_min = time_values.minute;
                result->tm_hour = time_values.hour;
                result->tm_mday = time_values.day;
                result->tm_mon = time_values.month - 1;
                result->tm_year = time_values.year - 1900;

                operation = LIB$K_DAY_OF_WEEK;
                status = lib$cvt_from_internal_time(&operation,
                    &result->tm_wday, systime);
                result->tm_wday %= 7;

                operation = LIB$K_DAY_OF_YEAR;
                status = lib$cvt_from_internal_time(&operation,
                    &result->tm_yday, systime);
                result->tm_yday--;

                result->tm_isdst = 0; /* There's no way to know... */

                ts = result;
            }
        }
    #endif
        return ts;
    }

}