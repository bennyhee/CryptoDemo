//
//  CryptoExtension.h
//  CryptoDemo
//
//  Created by yaclife on 11-11-10.
//  Copyright 2011年 __blogs.yaclife.com__. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface NSData (Cryptoextension)



- (NSData *) md5;
- (NSString *) tobase64;
- (NSData *) decodeBase64;


- (NSData *)Encode3DESWithKey:(NSString *)key;
- (NSData *)Decode3DESWithKey:(NSString *)key;


- (NSData *)EncodeRsa:(SecKeyRef)publicKey;
- (NSData *)DecodeRsa:(SecKeyRef)privateKey;


- (NSData *)getSignatureBytes:(SecKeyRef)prikey;
- (BOOL)verifySignature:(SecKeyRef)publicKey signature:(NSData *)sign ;


@end

SecKeyRef getPublicKeyWithCert(NSData *certdata);
SecKeyRef getPublicKeywithRawKey(NSString *peerNode,NSData *derpckskey);
SecKeyRef getPrivateKeywithRawKey(NSData *pfxkeydata);


