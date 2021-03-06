//
//  OpenSSLTest.m
//  OpenSSL-for-iOS
//
//  Created by Patrick Yang on 16/5/3.
//  Copyright © 2016年 Immobilienscout24. All rights reserved.
//

#import "OpenSSLTest.h"
#import "rsa.h"
#import "aes.h"
#import "base64.h"

@implementation OpenSSLTest

+ (void)rsa
{
    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *pub = [dir stringByAppendingPathComponent:@"rsa_public.pem"];
    NSString *pri = [dir stringByAppendingPathComponent:@"rsa.pem"];
    
    setKey(pub.UTF8String, pri.UTF8String);
    rsa_main();
}

+ (void)aes
{
    aes_main();
}

+ (void)base64
{
    base64_main();
}

@end
