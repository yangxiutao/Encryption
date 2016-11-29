//
//  NSString+EntryptionAndDetryption.h
//  EncryptionAndDecryptionDemo
//
//  Created by 杨修涛 on 16/2/23.
//  Copyright © 2016年 googosoft. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (EntryptionAndDetryption)

#pragma mark - MD5
/**
 *  MD5 Encryption
 *
 *  @param input NSString Need MD5 Encryption
 *
 *  @return MD5String
 */
+ (NSString *)md5Encryption:(NSString *)input;  //md5加密


/**
 *  MD5 + Base64 Encryption
 *
 *  @param input NSString Need MD5 Encryption
 *
 *  @return MD5String
 */
+ (NSString *)md5AndBase64Encryption:(NSString *)input;  //md5 + Base64 加密

#pragma mark - DES


/**
 *  DES Encryption
 *
 *  @param input NSString Need DES Encryption
 *
 *  @param key NSString DES Encryption key
 *
 *  @return DES Encryption
 */
+ (NSString *)encryptWithText:(NSString *)input key:(NSString *)key vector:(NSString *)vector;//Base64(des)加密


/**
 *  DES Decryption
 *
 *  @param input NSString Need DES Decryption
 *
 *  @param key NSString DES Decryption key
 *
 *  @return DES Decryption
 */
+ (NSString *)decryptWithText:(NSString *)input key:(NSString *)key vector:(NSString *)vector;//Base64(des)解密

#pragma mark - URL encode and decode


/**
 *  URL encoding on a input string
 *
 *  @param input A string(need encoding) input
 *
 *  @return A string after URL encoded
 */

+ (NSString *)decodeFromPercentEscapeString: (NSString *) input; //对URL进行编码

/**
 *  URL decoding on a input string
 *
 *  @param input A string(need decoding) input
 *
 *  @return decoding String
 */

+ (NSString *)encodeToPercentEscapeString: (NSString *) input; //对URL进行解码

#pragma mark - SHA


/**
 *  SHA1 Encryption
 *
 *  @param input A string need encrypt
 *
 *  @return SHA1 encrypt code
 */

+ (NSString *)sha1EncryptionWithText:(NSString *)input; //sha1 加密

/**
 *  SHA1 + Base64 Encryption
 *
 *  @param input A string need encrypt
 *
 *  @return SHA1 encrypt code
 */

+ (NSString *)sha1AndBase64EncryptionWithText:(NSString *)input; //sha1+Base64 加密


@end
