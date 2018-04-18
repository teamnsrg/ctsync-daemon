//g++ Queue.h x509Parser.cpp -std=c++14 -lpthread -o x509Parser -I /usr/local/ssl/include -L /usr/local/ssl/lib -lssl -lcrypto -Wall
// cite from: http://www.zedwood.com/article/c-openssl-parse-x509-certificate-pem
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>
#include "Queue.h"
#include <thread>
#include <atomic>

using namespace std;
atomic<bool> NOT_FINISHED (true);
const int CERTS_NUM = 1000;

X509* getCert(string &cert_str)
{
    BIO *bio_cert = BIO_new(BIO_s_mem());
    BIO_puts(bio_cert, cert_str.c_str());
    X509* cert = X509_new();
    //BIO* bio_cert = BIO_new_file(filename.c_str(), "rb");
    PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
    return cert;
}

void parseCert2(Queue<X509*>& q)
{
    int count = 0;
    while (NOT_FINISHED || !q.empty()) {
	count += 1;
        X509* x509 = q.pop();
        cout <<"--------------------" << endl;
        BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE); 

        long l = X509_get_version(x509);
        BIO_printf(bio_out, "Version: %ld\n", l+1); 

        ASN1_INTEGER *bs = X509_get_serialNumber(x509);
        BIO_printf(bio_out,"Serial: ");
        for(int i=0; i<bs->length; i++) {
            BIO_printf(bio_out,"%02x",bs->data[i] );
        }
        BIO_printf(bio_out,"\n");   

        X509_signature_print(bio_out, x509->sig_alg, NULL); 

        BIO_printf(bio_out,"Issuer: ");
        X509_NAME_print(bio_out,X509_get_issuer_name(x509),0);
        BIO_printf(bio_out,"\n");   

        BIO_printf(bio_out,"Valid From: ");
        ASN1_TIME_print(bio_out,X509_get_notBefore(x509));
        BIO_printf(bio_out,"\n");   

        BIO_printf(bio_out,"Valid Until: ");
        ASN1_TIME_print(bio_out,X509_get_notAfter(x509));
        BIO_printf(bio_out,"\n");   

        BIO_printf(bio_out,"Subject: ");
        X509_NAME_print(bio_out,X509_get_subject_name(x509),0);
        BIO_printf(bio_out,"\n");   

        EVP_PKEY *pkey=X509_get_pubkey(x509);
        if (pkey) {
            switch (pkey->type) {
                // http://www.s-and-b.net/ht_root/src/openssl-0_9_6/include/openssl/evp.h
                case EVP_PKEY_RSA:
                    BIO_printf(bio_out, "%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
                    break;
                case EVP_PKEY_RSA2:
                    BIO_printf(bio_out, "%d bit RSA2 Key\n\n", EVP_PKEY_bits(pkey));
                    break;
                case EVP_PKEY_DSA:
                    BIO_printf(bio_out, "%d bit DSA Key\n\n", EVP_PKEY_bits(pkey));
                    break;
                case EVP_PKEY_DSA1:
                    BIO_printf(bio_out, "%d bit DSA1 Key\n\n", EVP_PKEY_bits(pkey));
                    break;
                case EVP_PKEY_DSA2:
                    BIO_printf(bio_out, "%d bit DSA2 Key\n\n", EVP_PKEY_bits(pkey));
                    break;
                case EVP_PKEY_DSA3:
                    BIO_printf(bio_out, "%d bit DSA3 Key\n\n", EVP_PKEY_bits(pkey));
                    break;
                case EVP_PKEY_DSA4:
                    BIO_printf(bio_out, "%d bit DSA4 Key\n\n", EVP_PKEY_bits(pkey));
                case EVP_PKEY_DH:
                    BIO_printf(bio_out, "%d bit Diffie-Hellman Key\n\n", EVP_PKEY_bits(pkey));
                case EVP_PKEY_NONE:
                    BIO_printf(bio_out, "%d bit No Defined Key\n\n", EVP_PKEY_bits(pkey));
                    break;
                default:
                    BIO_printf(bio_out, "%d bit Unknown Key\n\n", EVP_PKEY_bits(pkey));
                    break;
            }
	    EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
            EVP_PKEY_free(pkey);
        }    

        X509_CINF *ci=x509->cert_info;
        X509V3_extensions_print(bio_out, (char*)"X509v3 extensions", ci->extensions, X509_FLAG_COMPAT, 0);  

        X509_signature_print(bio_out, x509->sig_alg, x509->signature);
        BIO_free(bio_out);
    	return;
    }
}
void produceCerts(Queue<X509*>& q) {
    ifstream infile("/data3/ct_data/log.txt");
    std::string line;
    int count = 0, error_count = 0, precert_count = 0;
    while (count < CERTS_NUM && getline(infile, line)) {
        if (line.empty()) continue;
        count += 1;
	// find cert string
	bool precert = true;
        int comma_count = 0, start_pos = 0, end_pos = 0;
        for (int i = 0, len = line.size(); i < len; ++i) {
            if (start_pos == 0 && (comma_count == 5 || comma_count == 7))    start_pos = i;
            if (end_pos == 0 && (comma_count == 6 || comma_count == 8))    end_pos = i-1;
            if (start_pos > 0 && end_pos > 0) {
                if (start_pos + 1 < end_pos) {
		    if (comma_count == 6)	precert = false;
                    break;
                } else {
                    start_pos = 0;
                    end_pos = 0;
                }
            }
            if (line[i] == ',') comma_count += 1;
        }
        string cert_str = "-----BEGIN CERTIFICATE-----\n" + line.substr(start_pos, end_pos-start_pos) + "\n-----END CERTIFICATE-----\n";
	X509* c = getCert(cert_str);
	if (ASN1_INTEGER_get(c->cert_info->version) != 0) {
		q.push(c);
	} else {
		//cerr << "Invalid Cert: \n" << cert_str << endl;
		error_count += 1;
	}
	if (precert)  precert_count += 1;
    }
    cerr << "Error count" << error_count << endl;
    cerr << "Precert count" << precert_count << endl;
    NOT_FINISHED = false;
}

int  main() {
    OpenSSL_add_all_algorithms();
    Queue<X509*> q;
    thread produceThread(bind(produceCerts, ref(q)));
    thread comsumeThread(bind(&parseCert2, ref(q)));
    produceThread.join();
    comsumeThread.join();
    return 0;
}
