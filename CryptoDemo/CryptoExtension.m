//
//  CryptoExtension.m
//  CryptoDemo
//
//  Created by yaclife on 11-11-10.
//  Copyright 2011年 __blogs.yaclife.com__. All rights reserved.
//

#import "CryptoExtension.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#import "GTMBase64.h"


@implementation NSData (Cryptoextension)



- (NSData*) md5
{
    const char* str = self.bytes;
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(str, strlen(str), result);
    
    NSData *data = [NSData dataWithBytes:result length:CC_MD5_DIGEST_LENGTH];
    
    return data; 
    
}


- (NSString *) tobase64
{
    if ([self length] > 0) {
        return [GTMBase64 stringByEncodingData:self];
    }
    
    return nil;
}


- (NSData *) decodeBase64
{
    if ([self length] > 0) {
        return [GTMBase64 decodeData:self];
    }
    
    return nil;
}



- (NSData *)Encode3DESWithKey:(NSString *)key; {
    
	char keyPtr[kCCKeySize3DES+1]; // room for terminator (unused)
	bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
	
	// fetch key data
	[key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
	
	NSUInteger dataLength = [self length];
	
	//See the doc: For block ciphers, the output size will always be less than or 
	//equal to the input size plus the size of one block.
	//That's why we need to add the size of one block here
	size_t bufferSize = dataLength + kCCBlockSize3DES;
	void *buffer = malloc(bufferSize);
	
	size_t numBytesDecrypted = 0;
    
	CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding|kCCOptionECBMode,
                                          keyPtr, kCCKeySize3DES,
                                          NULL /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
	
	if (cryptStatus == kCCSuccess) {
		//the returned NSData takes ownership of the buffer and will free it on deallocation
		
        return [NSData dataWithBytes:(const void *)buffer length:(NSUInteger)numBytesDecrypted];
        
	}
	
	free(buffer); //free the buffer;
	return nil;
}




- (NSData *)Decode3DESWithKey:(NSString *)key {
	// 'key' should be 32 bytes for AES256, will be null-padded otherwise
	char keyPtr[kCCKeySize3DES+1]; // room for terminator (unused)
	bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
	
	// fetch key data
	[key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
	
	NSUInteger dataLength = [self length];
	
	//See the doc: For block ciphers, the output size will always be less than or 
	//equal to the input size plus the size of one block.
	//That's why we need to add the size of one block here
	size_t bufferSize = dataLength + kCCBlockSize3DES;
	void *buffer = malloc(bufferSize);
	
	size_t numBytesDecrypted = 0;
    
	CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding|kCCOptionECBMode,
                                          keyPtr, kCCKeySize3DES,
                                          NULL /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
	
	if (cryptStatus == kCCSuccess) {
		//the returned NSData takes ownership of the buffer and will free it on deallocation
		return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
	}
	
	free(buffer); //free the buffer;
	return nil;
}




-(NSData *)EncodeRsa:(SecKeyRef)publicKey
{
    
    OSStatus sanityCheck = noErr;
	size_t cipherBufferSize = 0;
	size_t keyBufferSize = 0;
	
    
	NSData * cipher = nil;
	uint8_t * cipherBuffer = NULL;
	
	// Calculate the buffer sizes.
	cipherBufferSize = SecKeyGetBlockSize(publicKey);
	keyBufferSize = [self length];
	
    /*
     if (kTypeOfWrapPadding == kSecPaddingNone) {
     LOGGING_FACILITY( keyBufferSize <= cipherBufferSize, @"Nonce integer is too large and falls outside multiplicative group." );
     } else {
     LOGGING_FACILITY( keyBufferSize <= (cipherBufferSize - 11), @"Nonce integer is too large and falls outside multiplicative group." );
     }
     */
    
	// Allocate some buffer space. I don't trust calloc.
	cipherBuffer = malloc( cipherBufferSize * sizeof(uint8_t) );
	memset((void *)cipherBuffer, 0x0, cipherBufferSize);
	
	// Encrypt using the public key.
	sanityCheck = SecKeyEncrypt(publicKey,
                                kSecPaddingPKCS1,
                                (const uint8_t *)[self bytes],
                                keyBufferSize,
                                cipherBuffer,
                                &cipherBufferSize
								);
	
	//LOGGING_FACILITY1( sanityCheck == noErr, @"Error encrypting, OSStatus == %d.", sanityCheck );
	// Build up cipher text blob.
	cipher = [NSData dataWithBytes:(const void *)cipherBuffer length:(NSUInteger)cipherBufferSize];
	
	if (cipherBuffer) 
    {
        free(cipherBuffer);
    }
	return cipher;
    
    
}



- (NSData *)DecodeRsa:(SecKeyRef)privateKey
{
	OSStatus sanityCheck = noErr;
	size_t cipherBufferSize = 0;
	size_t keyBufferSize = 0;
	
	NSData * key = nil;
	uint8_t * keyBuffer = NULL;
	
	//LOGGING_FACILITY( privateKey != NULL, @"No private key found in the keychain." );
	
	// Calculate the buffer sizes.
	cipherBufferSize = SecKeyGetBlockSize(privateKey);
	keyBufferSize = [self length];
	
	//LOGGING_FACILITY( keyBufferSize <= cipherBufferSize, @"Encrypted nonce is too large and falls outside multiplicative group." );
	
	// Allocate some buffer space. I don't trust calloc.
	keyBuffer = malloc( keyBufferSize * sizeof(uint8_t) );
	memset((void *)keyBuffer, 0x0, keyBufferSize);
	
	// Decrypt using the private key.
	sanityCheck = SecKeyDecrypt(privateKey,
                                kSecPaddingPKCS1,
                                (const uint8_t *) [self bytes],
                                cipherBufferSize,
                                keyBuffer,
                                &keyBufferSize
								);
	
	//LOGGING_FACILITY1( sanityCheck == noErr, @"Error decrypting, OSStatus == %d.", sanityCheck );
	
	// Build up plain text blob.
	key = [NSData dataWithBytes:(const void *)keyBuffer length:(NSUInteger)keyBufferSize];
	
	if (keyBuffer) 
    {
        free(keyBuffer);
    }
	
	return key;
}





- (NSData *)getSignatureBytes:(SecKeyRef)prikey {
    
    
	OSStatus sanityCheck = noErr;
	NSData * signedHash = nil;
	
	uint8_t * signedHashBytes = NULL;
	size_t signedHashBytesSize = 0;
	
    
	signedHashBytesSize = SecKeyGetBlockSize(prikey);
	
	// Malloc a buffer to hold signature.
	signedHashBytes = malloc( signedHashBytesSize * sizeof(uint8_t) );
	memset((void *)signedHashBytes, 0x0, signedHashBytesSize);
	
	// Sign the SHA1 hash.
	sanityCheck = SecKeyRawSign(	prikey, 
                                kSecPaddingPKCS1, 
                                (const uint8_t *)[[self md5] bytes], 
                                CC_MD5_DIGEST_LENGTH, 
                                (uint8_t *)signedHashBytes, 
                                &signedHashBytesSize
								);
	
	//LOGGING_FACILITY1( sanityCheck == noErr, @"Problem signing the SHA1 hash, OSStatus == %d.", sanityCheck );
	
	// Build up signed SHA1 blob.
	signedHash = [NSData dataWithBytes:(const void *)signedHashBytes length:(NSUInteger)signedHashBytesSize];
	
	if (signedHashBytes) free(signedHashBytes);
	
	return signedHash;
}


- (BOOL)verifySignature:(SecKeyRef)publicKey signature:(NSData *)sig {
	size_t signedHashBytesSize = 0;
	OSStatus sanityCheck = noErr;
	
	// Get the size of the assymetric block.
	signedHashBytesSize = SecKeyGetBlockSize(publicKey);
	
	sanityCheck = SecKeyRawVerify(	publicKey, 
                                  kSecPaddingPKCS1, 
                                  (const uint8_t *)[[self md5] bytes],
                                  CC_MD5_DIGEST_LENGTH, 
                                  (const uint8_t *)[sig bytes],
                                  signedHashBytesSize
								  );
	
	return (sanityCheck == noErr) ? YES : NO;
}




@end










SecKeyRef getPublicKeywithRawKey(NSString *peerNode,NSData *publicKey)

{
    
    OSStatus sanityCheck = noErr;
    SecKeyRef peerKeyRef = NULL;
    CFTypeRef persistPeer = NULL;
    
    //LOGGING_FACILITY( peerName != nil, @"Peer name parameter is nil." );
    //LOGGING_FACILITY( publicKey != nil, @"Public key parameter is nil." );
    
    NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];
    
    [peerPublicKeyAttr setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [peerPublicKeyAttr setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [peerPublicKeyAttr setObject:[peerNode dataUsingEncoding:NSUTF8StringEncoding] forKey:(id)kSecAttrApplicationTag];
    [peerPublicKeyAttr setObject:publicKey  forKey:(id)kSecValueData];
    [peerPublicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnPersistentRef];
    
    sanityCheck = SecItemAdd((CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&persistPeer);
    
    // The nice thing about persistent references is that you can write their value out to disk and
    // then use them later. I don't do that here but it certainly can make sense for other situations
    // where you don't want to have to keep building up dictionaries of attributes to get a reference.
    // 
    // Also take a look at SecKeyWrapper's methods (CFTypeRef)getPersistentKeyRefWithKeyRef:(SecKeyRef)key
    // & (SecKeyRef)getKeyRefWithPersistentKeyRef:(CFTypeRef)persistentRef.
    
    // LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecDuplicateItem, @"Problem adding the peer public key to the keychain, OSStatus == %d.", sanityCheck );
    
    if (persistPeer) {
        
        OSStatus sanityCheck = noErr;
        SecKeyRef keyRef = NULL;
        
        //LOGGING_FACILITY(persistPeer != NULL, @"persistentRef object cannot be NULL." );
        
        NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
        
        // Set the SecKeyRef query dictionary.
        [queryKey setObject:(id)persistPeer forKey:(id)kSecValuePersistentRef];
        [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
        
        // Get the persistent key reference.
        sanityCheck = SecItemCopyMatching((CFDictionaryRef)queryKey, (CFTypeRef *)&keyRef);
        [queryKey release];
        
        peerKeyRef = keyRef;
        assert(sanityCheck == noErr);
    } else {
        [peerPublicKeyAttr removeObjectForKey:(id)kSecValueData];
        [peerPublicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
        // Let's retry a different way.
        sanityCheck = SecItemCopyMatching((CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&peerKeyRef);
    }
    
    // LOGGING_FACILITY1( sanityCheck == noErr && peerKeyRef != NULL, @"Problem acquiring reference to the public key, OSStatus == %d.", sanityCheck );
    assert(sanityCheck == noErr);
    [peerPublicKeyAttr release];
    if (persistPeer) CFRelease(persistPeer);
    return peerKeyRef;
}




SecKeyRef getPublicKeyWithCert(NSData *certdata)

{
    
    SecCertificateRef cert = SecCertificateCreateWithData (NULL,(CFDataRef)certdata); 
    
    CFArrayRef certs = CFArrayCreate(kCFAllocatorDefault, (const void **) &cert, 1, NULL); 
    
    SecTrustRef trust;
    SecPolicyRef policy = SecPolicyCreateBasicX509();   
    SecTrustCreateWithCertificates(certs, policy, &trust);
    SecTrustResultType trustResult;
    SecTrustEvaluate(trust, &trustResult);
    
    
    return  SecTrustCopyPublicKey(trust);
    
}



SecKeyRef getPrivateKeywithRawKey(NSData *pfxkeydata)

{
    
    NSMutableDictionary * options = [[[NSMutableDictionary alloc] init] autorelease];
    
    // Set the public key query dictionary
    //change to your .pfx  password here 
    [options setObject:@"yaclife" forKey:(id)kSecImportExportPassphrase];
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    OSStatus securityError = SecPKCS12Import((CFDataRef) pfxkeydata,
                                             (CFDictionaryRef)options, &items);
    
    CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identityApp =
    (SecIdentityRef)CFDictionaryGetValue(identityDict,
                                         kSecImportItemIdentity);
    //NSLog(@"%@", securityError);
    
    assert(securityError == noErr);
    SecKeyRef privateKeyRef;
    SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
    
    return privateKeyRef;
    
}



