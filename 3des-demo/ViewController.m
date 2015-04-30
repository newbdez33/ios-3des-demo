//
//  ViewController.m
//  3des-demo
//
//  Created by JackyZ on 30/4/15.
//  Copyright (c) 2015 Salmonapps. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCrypto.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    //两组key和iv，这里都被base64 encoded了。
    NSString * base64Key = @"UZKGf4NXJkDyfBCPomElCCATbSUI6VIm";
    NSString * base64Iv = @"AQIDBAUGAQI=";

    NSString * encoded = [self doSKCipher:@"15524552419" enc:kCCEncrypt key:base64Key iv:base64Iv];
    //应该返回 VW7v3uajdIMABXB2oeq/EA==
    NSLog(@"encoded:%@", encoded);
    
}

- (NSString*)doSKCipher:(NSString*)plainText enc:(CCOperation)encryptOrDecrypt key:(NSString *)keyInput iv:(NSString *)ivInput {
    
    const void *vplainText;
    size_t plainTextBufferSize;
    
    //变成nsdata
    NSData *decodedKey = [[NSData alloc] initWithBase64EncodedString:keyInput options:0];
    NSData *decodedIv = [[NSData alloc] initWithBase64EncodedString:ivInput options:0];
    
    if (encryptOrDecrypt == kCCDecrypt) {
        NSData *EncryptData =[[plainText dataUsingEncoding:NSUTF8StringEncoding] base64EncodedDataWithOptions:0];
        plainTextBufferSize = [EncryptData length];
        vplainText = [EncryptData bytes];
    } else {
        plainTextBufferSize = [plainText length];
        vplainText = (const void *) [plainText UTF8String];
    }
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    //  uint8_t ivkCCBlockSize3DES;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    
    unsigned char result1[24];
    memcpy(result1, decodedKey.bytes, decodedKey.length);
    unsigned char IV3[8];
    memcpy(IV3, decodedIv.bytes, decodedIv.length);
    
    uint8_t iv[kCCBlockSize3DES];
    memset((void *) iv, 0x0, (size_t) sizeof(iv));
    
    ccStatus = CCCrypt(encryptOrDecrypt,
                       kCCAlgorithm3DES,
                       kCCOptionPKCS7Padding,
                       result1, //"123456789012345678901234", //key
                       kCCKeySize3DES,
                       IV3 ,  //iv,
                       vplainText,  //plainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    //if (ccStatus == kCCSuccess) NSLog(@"SUCCESS");
    /*else*/ if (ccStatus == kCCParamError) return @"PARAM ERROR";
    else if (ccStatus == kCCBufferTooSmall) return @"BUFFER TOO SMALL";
    else if (ccStatus == kCCMemoryFailure) return @"MEMORY FAILURE";
    else if (ccStatus == kCCAlignmentError) return @"ALIGNMENT";
    else if (ccStatus == kCCDecodeError) return @"DECODE ERROR";
    else if (ccStatus == kCCUnimplemented) return @"UNIMPLEMENTED";
    
    NSString *result;
    
    if (encryptOrDecrypt == kCCDecrypt) {
        result = [ [NSString alloc] initWithData: [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes] encoding:NSASCIIStringEncoding];
    } else {
        NSData *myData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
        NSLog(@"data is: %@", myData);
        result = [myData base64EncodedStringWithOptions:0];

    }
    return result;
}
@end
