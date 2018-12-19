//
//  ZPDESTools.m
//  3DES加密
//
//  Created by xinzhipeng on 2018/12/18.
//  Copyright © 2018 xinzhipeng. All rights reserved.
//

#import "ZPDESTools.h"
#import <CommonCrypto/CommonCrypto.h>

//加密解密的key,与后台一致
#define USER_KEY @"uatspdbcccgame2014061800"
//初始化向量，与后台一致
#define initIv    @""

@implementation ZPDESTools

+ (NSString *)encryptWithText:(NSString *)sText
{
    //kCCEncrypt 加密
    return [self encrypt:sText encryptOrDecrypt:kCCEncrypt key:USER_KEY];
}

+ (NSString *)decryptWithText:(NSString *)sText
{
    //kCCDecrypt 解密
    return [self encrypt:sText encryptOrDecrypt:kCCDecrypt key:USER_KEY];
}

+ (NSString *)encrypt:(NSString *)sText encryptOrDecrypt:(CCOperation)encryptOperation key:(NSString *)key
{
    const void *dataIn;
    size_t dataInLength;
    if (encryptOperation == kCCDecrypt)//传递过来的是decrypt 解码
    {
        //解码 base64
        NSData *decryptData = [[NSData alloc] initWithBase64EncodedString:sText options:NSDataBase64DecodingIgnoreUnknownCharacters];//Base64形式的字符串为data
        dataInLength = [decryptData length];
        dataIn = [decryptData bytes];
    }
    else  //encrypt
    {
        NSData* encryptData = [sText dataUsingEncoding:NSUTF8StringEncoding];
        dataInLength = [encryptData length];
        dataIn = (const void *)[encryptData bytes];
    }
    
    /*
     DES加密 ：用CCCrypt函数加密一下，然后用base64编码下，传过去
     DES解密 ：把收到的数据根据base64，decode一下，然后再用CCCrypt函数解密，得到原本的数据
     */
    CCCryptorStatus ccStatus;
    uint8_t *dataOut = NULL; //可以理解位type/typedef 的缩写（有效的维护了代码，比如：一个人用int，一个人用long。最好用typedef来定义）
    size_t dataOutAvailable = 0; //size_t  是操作符sizeof返回的结果类型
    size_t dataOutMoved = 0;
    
    dataOutAvailable = (dataInLength + kCCBlockSizeDES) & ~(kCCBlockSizeDES - 1);
    dataOut = malloc( dataOutAvailable * sizeof(uint8_t));
    memset((void *)dataOut, 0x0, dataOutAvailable);//将已开辟内存空间buffer的首 1 个字节的值设为值 0
    
    const void *vkey = (const void *) [key UTF8String];
    const void *iv = (const void *) [initIv UTF8String];

    //CCCrypt函数 加密/解密
    ccStatus = CCCrypt(encryptOperation,//  加密/解密
                       kCCAlgorithm3DES,//  加密根据哪个标准（des，3des，aes。。。。）
                       kCCOptionECBMode|kCCOptionPKCS7Padding,//  选项分组密码算法(des:对每块分组加一次密  3DES：对每块分组加三个不同的密)选择ECB模式，默认是CBC模式.
                       vkey,  //密钥    加密和解密的密钥必须一致
                       kCCKeySize3DES,//   DES 密钥的大小（kCCKeySizeDES=8）
                       iv, //  可选的初始矢量 (ECB模式,不用此参数)
                       dataIn, // 数据的存储单元
                       dataInLength,// 数据的大小
                       (void *)dataOut,// 用于返回数据
                       dataOutAvailable,
                       &dataOutMoved);
    NSString *result = nil;
    if (encryptOperation == kCCDecrypt)//encryptOperation==1  解码
    {
        //得到解密出来的data数据，改变为utf-8的字符串
        NSData *data = [NSData dataWithBytesNoCopy:dataOut length:(NSUInteger)dataOutMoved];
        result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    else //encryptOperation==0  （加密过程中，把加好密的数据转成base64的）
    {
        //编码 base64
        NSData *data = [NSData dataWithBytesNoCopy:dataOut length:(NSUInteger)dataOutMoved];
        result = [data base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    }
    return result;
}

//加密
+(NSString *) encryptUseDES2:(NSString *)plainText key:(NSString *)key{
    NSString *ciphertext = nil;
    const char *textBytes = [plainText UTF8String];
    size_t dataLength = [plainText length];
    //==================
    
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (dataLength + kCCBlockSizeDES) & ~(kCCBlockSizeDES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    NSString *testString = key;
    NSData *testData = [testString dataUsingEncoding: NSUTF8StringEncoding];
    Byte *iv = (Byte *)[testData bytes];

    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
                                          kCCOptionECBMode|kCCOptionPKCS7Padding,
                                          [key UTF8String],
                                          kCCKeySizeDES,
                                          iv,
                                          textBytes,
                                          dataLength,
                                          (void *)bufferPtr,
                                          bufferPtrSize,
                                          &movedBytes);
    if (cryptStatus == kCCSuccess) {
//        ciphertext= [ZPDESTools parseByte2HexString:bufferPtr length:(int)movedBytes]; //加密后转成16进制字符
        NSData *data = [NSData dataWithBytes:bufferPtr length:movedBytes];
        ciphertext = [data base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];//加密后转base64
    }
//    ciphertext=[ciphertext uppercaseString];//字符变大写
    return ciphertext;
}

//解密
+(NSString *)decryptUseDES:(NSString *)cipherText key:(NSString *)key
{
//    NSData* cipherData = [ZPDESTools convertHexStrToData:[cipherText lowercaseString]];  //把16进制字符转成NSData
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:cipherText options:NSDataBase64DecodingIgnoreUnknownCharacters];//转成utf-8并decode
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesDecrypted = 0;
    NSString *testString = key;
    NSData *testData = [testString dataUsingEncoding: NSUTF8StringEncoding];
    Byte *iv = (Byte *)[testData bytes];
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmDES,
                                          kCCOptionECBMode|kCCOptionPKCS7Padding,
                                          [key UTF8String],
                                          kCCKeySizeDES,
                                          iv,
                                          [cipherData bytes],
                                          [cipherData length],
                                          buffer,
                                          1024,
                                          &numBytesDecrypted);
    NSString* plainText = nil;
    if (cryptStatus == kCCSuccess) {
        NSData* data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesDecrypted];
        plainText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return plainText;
    
}


+(NSString *) parseByte2HexString:(Byte *) bytes  length:(int)len{
    NSString *hexStr = @"";
    if(bytes)
    {
        for(int i=0;i<len;i++)
        {
            NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i]&0xff]; ///16进制数
            if([newHexStr length]==1)
                hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
            else
            {
                hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
            }
        }
    }
    return hexStr;
}
+ (NSData *)convertHexStrToData:(NSString *)str {
    if (!str || [str length] == 0) {
        return nil;
    }
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:8];
    NSRange range;
    if ([str length] % 2 == 0) {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }
    for (NSInteger i = range.location; i < [str length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [str substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        
        range.location += range.length;
        range.length = 2;
    }
    return hexData;
}


@end
