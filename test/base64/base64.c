//
//  base64.c
//  OpenSSL-for-iOS
//
//  Created by Patrick Yang on 16/5/4.
//  Copyright © 2016年 Immobilienscout24. All rights reserved.
//

#include "base64.h"
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

static void base64_encode(char *str,int str_len,char **encode, size_t *length){
    BIO *bmem,*b64;
    BUF_MEM *bptr;
    b64=BIO_new(BIO_f_base64());
    bmem=BIO_new(BIO_s_mem());
    b64=BIO_push(b64,bmem);
    BIO_write(b64,str,str_len); //encode
    BIO_flush(b64);
    BIO_get_mem_ptr(b64,&bptr);
    *encode = (char *)malloc(bptr->length + 1);
    memcpy(*encode, bptr->data, bptr->length);
    (*encode)[bptr->length] = 0;
    *length = bptr->length;
    BIO_free_all(b64);
}

static void base64_decode(char *str,int str_len,char **decode,size_t *length){
    int len=0;
    BIO *b64,*bmem;
    b64=BIO_new(BIO_f_base64());
    bmem=BIO_new_mem_buf(str,str_len);
    bmem=BIO_push(b64,bmem);
    *decode = (char *)malloc(str_len + 1);
    len=BIO_read(bmem,*decode,str_len);
    (*decode)[len]=0;
    *length = len;
    BIO_free_all(bmem);
}

int base64_main(void)
{
    char *source= "i like dancing!";
    
    char *encode, *decode;
    size_t en_len, de_len;
    base64_encode(source, strlen(source), &encode, &en_len);
    base64_decode(encode, strlen(encode), &decode, &de_len);
    
    return 0;
}