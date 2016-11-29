//
//  ViewController.m
//  EncryptionAndDecryptionDemo
//
//  Created by 杨修涛 on 16/2/23.
//  Copyright © 2016年 googosoft. All rights reserved.
//

#import "EDViewController.h"
#import "NSString+EntryptionAndDetryption.h"

@interface EDViewController ()

@property (weak, nonatomic) IBOutlet UITextField *inPutTextField;
@property (weak, nonatomic) IBOutlet UITextField *encryptedTextField;
@property (weak, nonatomic) IBOutlet UITextField *decryptedTextField;
@property (weak, nonatomic) IBOutlet UITextField *URLEncodeTextField;
@property (weak, nonatomic) IBOutlet UITextField *URLDecodeTextField;

@end

@implementation EDViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark - MD5
- (IBAction)MD5Entryption:(id)sender {
    self.title = @"MD5Entryption";
    
    self.encryptedTextField.text = [NSString md5Encryption:self.inPutTextField.text];
    
}

- (IBAction)MD5Base64Entryption:(id)sender {
    self.title = @"MD5Base64Entryption";
    
    self.encryptedTextField.text = [NSString md5AndBase64Encryption:self.inPutTextField.text];
}


#pragma mark - SHA1

- (IBAction)SHA1Entryption:(id)sender {
    self.title = @"SHA1Entryption";
    
    self.encryptedTextField.text = [NSString sha1EncryptionWithText:self.inPutTextField.text];
    
}

- (IBAction)SHA1Base64Entryption:(id)sender {
    self.title = @"SHA1Base64Entryption";
    
    self.encryptedTextField.text = [NSString sha1AndBase64EncryptionWithText:self.inPutTextField.text];
}

#pragma mark - DES
- (IBAction)DESEntryption:(id)sender {
    self.title = @"DESEntryption";
    
    self.encryptedTextField.text = [NSString encryptWithText:self.inPutTextField.text key:@"EBSEBSEBSEBSEBSEBSEBSEBS" vector:@"31313131"];
}

- (IBAction)DESDetryption:(id)sender {
    self.title = @"DESDetryption";
    
    if (![self.encryptedTextField.text isEqualToString:@""]) {
        self.decryptedTextField.text = [NSString decryptWithText:self.encryptedTextField.text key:@"EBSEBSEBSEBSEBSEBSEBSEBS" vector:@"31313131"];
    }
}

#pragma mark - iOS URL 编码/解码

- (IBAction)URLEncode:(id)sender {
    self.title = @"URLEncode";
    
    self.URLEncodeTextField.text = [NSString encodeToPercentEscapeString:self.inPutTextField.text];
}

- (IBAction)URLDecode:(id)sender {
    self.title = @"URLDecode";
    
    if (![self.URLEncodeTextField.text isEqualToString:@""]) {
        self.URLDecodeTextField.text = [NSString decodeFromPercentEscapeString:self.URLEncodeTextField.text];
    }
}

@end
