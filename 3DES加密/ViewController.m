//
//  ViewController.m
//  3DES加密
//
//  Created by xinzhipeng on 2018/12/18.
//  Copyright © 2018 xinzhipeng. All rights reserved.
//

#import "ViewController.h"
#import "ZPDESTools.h"

#define ZPkey @"LKJCARDNUM"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *test1 = @"123456789";
//    NSString *result1 = [ZPDESTools encryptUseDES2:test1 key:ZPkey];
    NSString *result1 = [ZPDESTools encryptWithText:test1];
    NSLog(@"%@",result1);
    NSString *test2 = @"BPJABx6iso6++gxtGq+Esw==";
//    NSString *result2 = [ZPDESTools decryptUseDES:test2 key:ZPkey];
    NSString *result2 = [ZPDESTools decryptWithText:test2];
    NSLog(@"%@",result2);
    
}


@end
