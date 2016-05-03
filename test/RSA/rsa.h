//
//  rsa.h
//  OpenSSL-for-iOS
//
//  Created by Patrick Yang on 16/4/29.
//  Copyright © 2016年 Immobilienscout24. All rights reserved.
//

#ifndef rsa_h
#define rsa_h

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif
    
    void setKey(const char *publicPath, const char *privatePath);
    
    int openssl_main();
    int test_main(void);
    
    

#ifdef __cplusplus
}
#endif

int openssl_main();

#endif /* rsa_h */
