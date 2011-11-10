//
//  CryptoDemoAppDelegate.m
//  CryptoDemo
//
//  Created by yaclife on 11-11-10.
//  Copyright 2011年 blogs.yaclife.com. All rights reserved.
//

#import "CryptoDemoAppDelegate.h"
#import "CryptoExtension.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

#import "CryptoDemoViewController.h"



@implementation CryptoDemoAppDelegate



@synthesize window=_window;

@synthesize viewController=_viewController;

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    // Override point for customization after application launch.
     
    self.window.rootViewController = self.viewController;
    [self.window makeKeyAndVisible];
    
    
    
    NSString *plain = @"welcome to blogs.yaclife.com";
    NSLog(@"plain: %@",plain);
    NSData *plainData = [plain dataUsingEncoding:NSUTF8StringEncoding];
    

    //generate SecKeyRef from a raw key  with der encode pkcs12 format
    NSData   *pubkeyData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle]  pathForResource:@"yaclifepubkey" ofType:@"der"]];
    SecKeyRef pubkeyFromRawKey = getPublicKeywithRawKey(@"yaclife",pubkeyData);
    
    //generate SecKeyRef from a cert file
    NSData   *certData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle]  pathForResource:@"yaclifecert" ofType:@"der"]];
    SecKeyRef pubkeyFromCert   = getPublicKeyWithCert(certData);
    
    //generate private key SecKeyRef from a pfx cert file 
    NSData   *pfxData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle]  pathForResource:@"yaclife" ofType:@"pfx"]];
    SecKeyRef privatekey   = getPrivateKeywithRawKey(pfxData);
    
    //just a test
    NSData *ciper1 = [plainData EncodeRsa:pubkeyFromCert];
    NSLog(@"RSACiper1: %@",[ciper1 tobase64] );
    NSData *plainFormciper1 = [ciper1 DecodeRsa:privatekey];
    NSLog(@"RSAplainfromciper1: %@",[[[NSString alloc]initWithData:plainFormciper1 encoding:NSUTF8StringEncoding] autorelease] );
    
    //test
    NSData *ciper2 = [plainData EncodeRsa:pubkeyFromRawKey];
    NSLog(@"RSAciper2: %@",[ciper2 tobase64] );
    NSData *plainFormciper2 = [ciper2 DecodeRsa:privatekey];
    NSLog(@"RSAplainfromciper2: %@",[[[NSString alloc]initWithData:plainFormciper2 encoding:NSUTF8StringEncoding] autorelease] );

    
    return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application
{
    /*
     Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
     Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
     */
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
    /*
     Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later. 
     If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
     */
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
    /*
     Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
     */
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
    /*
     Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
     */
}

- (void)applicationWillTerminate:(UIApplication *)application
{
    /*
     Called when the application is about to terminate.
     Save data if appropriate.
     See also applicationDidEnterBackground:.
     */
}

- (void)dealloc
{
    [_window release];
    [_viewController release];
    [super dealloc];
}

@end
