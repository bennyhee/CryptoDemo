//
//  CryptoDemoAppDelegate.h
//  CryptoDemo
//
//  Created by yaclife on 11-11-10.
//  Copyright 2011年 __blogs.yaclife.com__. All rights reserved.
//

#import <UIKit/UIKit.h>

@class CryptoDemoViewController;

@interface CryptoDemoAppDelegate : NSObject <UIApplicationDelegate> {

}

@property (nonatomic, retain) IBOutlet UIWindow *window;

@property (nonatomic, retain) IBOutlet CryptoDemoViewController *viewController;

@end
