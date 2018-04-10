// g++ x509Parser.cpp -std=c++14 -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -o x509Parser
// cite from: http://www.zedwood.com/article/c-openssl-parse-x509-certificate-pem
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>

using namespace std;


X509* getCert(string &cert_str)
{
    BIO *bio_cert = BIO_new(BIO_s_mem());
    BIO_puts(bio_cert, cert_str.c_str());
    X509* cert = X509_new();
    //BIO* bio_cert = BIO_new_file(filename.c_str(), "rb");
    PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
    return cert;
}

void parseCert2(X509* x509)
{
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
    EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
    EVP_PKEY_free(pkey);
 
    X509_CINF *ci=x509->cert_info;
    X509V3_extensions_print(bio_out, (char*)"X509v3 extensions", ci->extensions, X509_FLAG_COMPAT, 0);
 
    X509_signature_print(bio_out, x509->sig_alg, x509->signature);
    BIO_free(bio_out);
}

void printCert(string filename) {
    ifstream infile(filename);
    std::string line;
    int count = 0, error_count = 0, precert_count = 0;
    while (count < 10000 && std::getline(infile, line)) {
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
		parseCert2(c);
	} else {
		//cerr << "Invalid Cert: \n" << cert_str << endl;
		error_count += 1;
	}
	if (precert)  precert_count += 1;
    }
    cerr << "Error count" << error_count << endl;
    cerr << "Precert count" << precert_count << endl;
}

int  main() {
  OpenSSL_add_all_algorithms();
  printCert("/data3/ct_data/log.txt");
  return 0;
}
