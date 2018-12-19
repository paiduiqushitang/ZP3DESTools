//
//  ZPDESTools.h
//  3DES加密
//
//  Created by xinzhipeng on 2018/12/18.
//  Copyright © 2018 xinzhipeng. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZPDESTools : NSObject
+ (NSString *)encryptWithText:(NSString *)sText; //3DES加密
+ (NSString *)decryptWithText:(NSString *)sText; //3DES解密

//DES加密
+(NSString *) encryptUseDES2:(NSString *)plainText key:(NSString *)key;
//DES解密
+(NSString *)decryptUseDES:(NSString *)cipherText key:(NSString *)key;
@end

NS_ASSUME_NONNULL_END
