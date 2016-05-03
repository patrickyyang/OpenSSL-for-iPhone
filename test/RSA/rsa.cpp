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

std::string bio_read_privateKey(string data) {
    OpenSSL_add_all_algorithms();
    
    BIO* bp = BIO_new( BIO_s_file() );
    
    BIO_read_filename( bp, private_key);
    
    char passwd[]="1234";
    RSA* rsaK = PEM_read_bio_RSAPrivateKey( bp, NULL, NULL, passwd );
    if (NULL == rsaK) {
        perror("read key file fail!");
    }else{
        printf("read success!\n");
    }
    
    int nLen = RSA_size(rsaK);
    //printf("len:%d\n",nLen);
    char *pEncode = new char[nLen + 1];
    int ret = RSA_private_decrypt(data.length(),(const unsigned char*)data.c_str(),(unsigned char *)pEncode,rsaK,RSA_PKCS1_PADDING);
    std::string strRet;
    if (ret >= 0) {
        strRet = std::string(pEncode, ret);
        //printf("%s",strRet.c_str());
    }
    
    delete[] pEncode;
    CRYPTO_cleanup_all_ex_data();
    BIO_free_all( bp );
    RSA_free(rsaK);
    return strRet;
}

std::string bio_read_publicKey(string data){
    OpenSSL_add_all_algorithms();
    BIO* bp = BIO_new( BIO_s_file() );
    BIO_read_filename( bp, public_key);
    RSA* rsaK = PEM_read_bio_RSAPublicKey( bp, NULL, NULL, NULL );
    if (NULL == rsaK) {
        perror("read key file fail!");
    }else{
        printf("read success!");
        int nLen = RSA_size(rsaK);
        printf("len:%d\n",nLen);
    }
    int nLen = RSA_size(rsaK);
    char *pEncode = new char[nLen + 1];
    int ret = RSA_public_encrypt(data.length(),(const unsigned char*)data.c_str(),
                                 (unsigned char *)pEncode,rsaK,RSA_PKCS1_PADDING);
    std::string strRet;
    if (ret >= 0) {
        strRet = std::string(pEncode, ret);
        //printf("%s\n",strRet.c_str());
    }
    delete[] pEncode;
    CRYPTO_cleanup_all_ex_data();
    BIO_free_all( bp );
    RSA_free(rsaK);
    return strRet;
}

void encryptFile(string inputfile,string outputfile){
    ifstream file(inputfile.c_str());
    ofstream outfile(outputfile.c_str());
    string tsum;
    string ss;
    while (getline(file,ss)) {
        tsum.append(ss.append("\n"));
    }
    cout<<"徐加密内容："<<tsum<<endl;
    string mw = bio_read_publicKey(tsum);
    cout<<mw<<endl;
    outfile<<mw;
    outfile.flush();
    outfile.close();
    file.close();
}

void decryptFile(string inputfile,string outputfile){
    ifstream file(inputfile.c_str());
    ofstream outfile(outputfile.c_str());
    std::string tsum,ss;
    while (getline(file,ss)) {
        tsum.append(ss);
    }
    std::string cw = bio_read_privateKey(tsum);
    cout<<"恢复明文："<<cw;
    outfile<<cw;
    outfile.flush();
    outfile.close();
    file.close();
}

void setKey(const char *publicPath, const char *privatePath)
{
    public_key = (char *)malloc(strlen(publicPath) + 1);
    strcpy(public_key, publicPath);
    private_key = (char *)malloc(strlen(privatePath) + 1);
    strcpy(private_key, privatePath);
}

int openssl_main() {
    char *str = "第一步，首先需要在openssl官网下载openssl包http://www.openssl.org/source/；\n第二步，自己查资料去！";
    //system("openssl genrsa -out private.key 1024");
    generateKey();
    printf("原文：%s\n",str);
    std::string m = bio_read_publicKey(str);
    printf("密文：\n------------%s--------------\n\n",m.c_str());
    string miwen = m;
    std::string c = bio_read_privateKey(miwen);
    printf("解密后：\n------------%s--------------\n\n",c.c_str());
    
    printf("----------------加密文件--------------------------\n");
    encryptFile("d:/before.txt","f:/my.txt");
    cout<<"------------------done-------------------------------"<<endl;
    /*
     ifstream infile("f:/my.txt");
     std::string instr,intemp;
     while (getline(infile,intemp)) {
     instr.append(intemp);
     }
     cout<<instr<<endl;
     std::string cwen = bio_read_privateKey(instr);
     cout<<cwen;
     */
    printf("-----------------解密文件----------------------------\n");
    decryptFile("f:/my.txt","f:/jiemihou.txt");
    cout<<"------------------done-------------------------------"<<endl;
    
    return 0;
}


/***********************************************/


char *public_encrypt(char *str,char *path_key){
    char *p_en;
    RSA *p_rsa;
    FILE *file;
    int flen,rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;
    }
    if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){
        //if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   换成这句死活通不过，无论是否将公钥分离源文件
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    flen=strlen(str);
    rsa_len=RSA_size(p_rsa);
    p_en=(char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
    if(RSA_public_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_en;
}

char *public_decrypt(char *str,char *path_key){
    char *p_en;
    RSA *p_rsa;
    FILE *file;
    int flen,rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;
    }
    if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){
        //if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   换成这句死活通不过，无论是否将公钥分离源文件
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    flen=strlen(str);
    rsa_len=RSA_size(p_rsa);
    p_en=(char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
    if(RSA_public_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_en;
}

char *private_encrypt(char *str,char *path_key){
    char *p_de;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;
    }
    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    rsa_len=RSA_size(p_rsa);
    p_de=(char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
    if(RSA_private_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_de;
}

char *private_decrypt(char *str,char *path_key){
    char *p_de;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;
    }
    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    rsa_len=RSA_size(p_rsa);
    p_de=(char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
    if(RSA_private_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_de;
}

int test_main(void){
    char *source="i like dancing !";
    char *ptr_en,*ptr_de;
    printf("source is    :%s\n",source);
    ptr_en = public_encrypt(source,public_key);
    printf("after public encrypt:%s\n",ptr_en);
    ptr_de = private_decrypt(ptr_en,private_key);
    printf("after private decrypt:%s\n",ptr_de);
    ptr_en = private_encrypt(source,private_key);
    printf("after private encrypt:%s\n",ptr_en);
    ptr_de = public_decrypt(ptr_en,public_key);
    printf("after public decrypt:%s\n",ptr_de);
    if(ptr_en!=NULL){
        free(ptr_en);
    }
    if(ptr_de!=NULL){
        free(ptr_de);
    }
    return 0;
}