//
//  rsa.c
//  OpenSSL-for-iOS
//
//  Created by Patrick Yang on 16/4/29.
//  Copyright © 2016年 Immobilienscout24. All rights reserved.
//

#include "rsa.h"

#include <stdio.h>
#include <stdlib.h>

#include <openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include <openssl/bio.h>
#include <fstream>
#include <iostream>
#include <string>
using namespace std;
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

char *private_key = NULL;
char *public_key = NULL;

void generateKey() {
    
    /* 生成公钥 */
    RSA* rsa = RSA_generate_key( 1024, RSA_F4, NULL, NULL);
    BIO *bp = BIO_new( BIO_s_file() );
    BIO_write_filename( bp, (void *)public_key);
    PEM_write_bio_RSAPublicKey(bp, rsa);
    BIO_free_all( bp );
    /* 生成私钥 */
    char passwd[]="1234";
    bp = BIO_new_file(private_key, "w+");
    PEM_write_bio_RSAPrivateKey(bp, rsa, EVP_des_ede3(), (unsigned char*)passwd, 4, NULL, NULL);
    BIO_free_all( bp );
    RSA_free(rsa);
}

void setKey(const char *publicPath, const char *privatePath)
{
    public_key = (char *)malloc(strlen(publicPath) + 1);
    strcpy(public_key, publicPath);
    private_key = (char *)malloc(strlen(privatePath) + 1);
    strcpy(private_key, privatePath);
}

/***********************************************/
const unsigned char *public_key_content = (unsigned char *)"-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8em7eBPuYSd4GdfDi5YAT2Bw+\
hoxXXoSjhwataqjm3LOia+ox1lvcQEQKTQz73brN5Y/yGH2rGSsB/DBSlQrZKNFO\
nwI+/4gCjgzz/78D4jBOCkJb9ROeeveD27OwSnrWsvHdtsbM+73+CZlPTqaovj/s\
pZwezrp3+Ys0S3p3YQIDAQAB\n\
-----END PUBLIC KEY-----";

const unsigned char *private_key_content = (unsigned char *)"-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQC8em7eBPuYSd4GdfDi5YAT2Bw+hoxXXoSjhwataqjm3LOia+ox\
1lvcQEQKTQz73brN5Y/yGH2rGSsB/DBSlQrZKNFOnwI+/4gCjgzz/78D4jBOCkJb\
9ROeeveD27OwSnrWsvHdtsbM+73+CZlPTqaovj/spZwezrp3+Ys0S3p3YQIDAQAB\
AoGBAKtWfZzVWMZ7OBwVcXNCgKkJh7uLYt817EwgPoC9emfMcHyRr6e4n29c+L2I\
h+obCmuMacwCWZOF4KQAVwlrthxcfAuYubHDAn5faAboNqyr6opZRTYfwmJ+qs/V\
ENVU5bLW2njP/+NZYH6gYO0jvxUTclOQkkPaPY6hvw27RiMxAkEA8nz2Qp0B4T8G\
z8kcJWuZ9aOAj5pT6imDXfnl4avSAWIZC2SPPXPpus+AP1QfCRcTqQIBnT7a3TiL\
95u0jzBsRQJBAMb7CFFw9orAjaE3QYtMRdBqugPEAvNruheKc74NCBMa7vSYWv9e\
ZdQaaRwBMg5uDuh6jFP+78xS+4J6/2sTxm0CQG7f8IH45Hknpmev3yzFDHqirg/7\
Us9I+AYqU5BiTf3P6v+olU5WB9MhOdS7FA3F/XlTr4VEzjJEvssS6PZn/7kCQQCn\
M34z4TZqNY9Nbv8WrErl7SjNzUGlhlpjOaY0hwLH+xPcWMHuYEY0ytSUAbUsRvMk\
CwYr9sdN7FUHuY8zTPSpAkBvVsdLcTsAclzbqGyNf59vdJ2O8OSZZFpXcQWtwmgw\
Ilv4oE1xfJp4jQpkhKNPtNPjsTXjsfXY4Bhk38dbNeI7\n\
-----END RSA PRIVATE KEY-----";

RSA *rsa_mem_key(const unsigned char *content, int isPublic)
{
    RSA *rsa = NULL;
    int length = (int)strlen((const char *)content);
    BIO *bio = BIO_new_mem_buf((void*)content, length);
    if (isPublic) {
        rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    }
    return rsa;
}

RSA *rsa_file_key(const char *path, int isPublic)
{
    RSA *rsa = NULL;
    FILE *file = fopen(path,"r");
    if(!file){
        perror("open key file error");
        return NULL;
    }
    if (isPublic) {
        rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
    } else {
        rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
    }
    if (!rsa) {
        ERR_print_errors_fp(stdout);
    }
    return rsa;
}
char *rsa_encrypt(char *str, RSA *key, int isPublic)
{
    int len = RSA_size(key);
    char *enc = (char *)malloc(len+1);
    memset(enc, 0, len + 1);
    
    int ret = 0;
    if (isPublic) {
        ret = RSA_public_encrypt(len,(unsigned char *)str,(unsigned char*)enc, key, RSA_NO_PADDING);
    } else {
        ret = RSA_private_encrypt(len,(unsigned char *)str,(unsigned char*)enc, key, RSA_NO_PADDING);
    }
    if (ret < 0) {
        return NULL;
    }
    return enc;
}
char *rsa_decrypt(char *str, RSA *key, int isPublic)
{
    int len = RSA_size(key);
    char *dec = (char *)malloc(len+1);
    memset(dec, 0, len + 1);
    
    int ret = 0;
    if (isPublic) {
        ret = RSA_public_decrypt(len,(unsigned char *)str,(unsigned char *)dec, key, RSA_NO_PADDING);
    } else {
        ret = RSA_private_decrypt(len,(unsigned char *)str,(unsigned char *)dec, key, RSA_NO_PADDING);
    }
    
    if (ret < 0) {
        return NULL;
    }
    return dec;
}

int test_main(void){
//    RSA *pubkey = rsa_mem_key(public_key_content, 1);
//    RSA *prikey = rsa_mem_key(private_key_content, 0);
    RSA *pubkey = rsa_file_key(public_key, 1);
    RSA *prikey = rsa_file_key(private_key, 0);
    char *source= "i like dancing sdfasfdasfdasdfasdfasfasfasfsafasfasfasdfasddfaaaaabbbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyyzzzz!";
    
    char *ptr_en,*ptr_de;
    printf("source is    :%s\n",source);
    ptr_en = rsa_encrypt(source, pubkey, 1);
    printf("after public encrypt:%s\n",ptr_en);
    ptr_de = rsa_decrypt(ptr_en, prikey, 0);
    printf("after private decrypt:%s\n",ptr_de);
    ptr_en = rsa_encrypt(source,prikey, 0);
    printf("after private encrypt:%s\n",ptr_en);
    ptr_de = rsa_decrypt(ptr_en, pubkey, 1);
    printf("after public decrypt:%s\n",ptr_de);
    if(ptr_en!=NULL){
        free(ptr_en);
    }
    if(ptr_de!=NULL){
        free(ptr_de);
    }
    return 0;
}