/*
Taneli Leppanen
taneli.leppanen@student.tut.fi
BIE-BEZ Security
*/


#ifndef ENCRYPTRSA_H
#define ENCRYPTRSA_H


#include <string>


using namespace std;


void rsa_encrypt(const char * pubkeyFileName, string inFileName, const char *cipherName);


#endif // ENCRYPTRSA_H
