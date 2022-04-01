//
//  XlogDecoder.h
//  ios_xlog_sample
//
//  Created by king on 2022/1/15.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface XlogDecoder : NSObject
- (BOOL)decodeAtPath:(NSString *)path privateKey:(NSString *)privateKey outPath:(NSString *)outPath;
@end

NS_ASSUME_NONNULL_END

