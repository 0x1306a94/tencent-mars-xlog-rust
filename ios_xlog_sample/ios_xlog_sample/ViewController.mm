//
//  ViewController.m
//  ios_xlog_sample
//
//  Created by king on 2022/1/10.
//

#import "ViewController.h"

#import <algorithm>
#import <assert.h>
#import <limits.h>
#import <stdio.h>
#import <sys/xattr.h>

#import <mars/xlog/xlogger_interface.h>

@interface ViewController ()

@end

@implementation ViewController

struct LogConfig {
    std::string name;
    std::string pub_key;
    TAppenderMode mode = kAppenderAsync;
    TCompressMode compress_mode = kZlib;
};

static const char *private_key = "a057c94f1711e2680544080ce622dc6bdb22a1a602d321a0e60ef224515624b7";
static const char *public_key = "ef3fc929569b9f7faaf6d97e601da9db12ed1f7851deed04b5eef525b0dba5cf327c86201c7ea231a3d96c535b5481db230158f94b5d807c6a29fc6c20e27f9c";
static LogConfig logConfigs[] = {
    {
        .name = "zlib_async_crypt",
        .pub_key = public_key,
        .mode = kAppenderAsync,
        .compress_mode = kZlib,
    },
    {
        .name = "zlib_sync_crypt",
        .pub_key = public_key,
        .mode = kAppenderSync,
        .compress_mode = kZlib,
    },
    {
        .name = "zlib_async_no_crypt",
        .pub_key = "",
        .mode = kAppenderAsync,
        .compress_mode = kZlib,
    },
    {
        .name = "zlib_sync_no_crypt",
        .pub_key = "",
        .mode = kAppenderSync,
        .compress_mode = kZlib,
    },
    {
        .name = "zstd_async_crypt",
        .pub_key = public_key,
        .mode = kAppenderAsync,
        .compress_mode = kZstd,
    },
    {
        .name = "zstd_sync_crypt",
        .pub_key = public_key,
        .mode = kAppenderSync,
        .compress_mode = kZstd,
    },
    {
        .name = "zstd_async_no_crypt",
        .pub_key = "",
        .mode = kAppenderAsync,
        .compress_mode = kZstd,
    },
    {
        .name = "zstd_sync_no_crypt",
        .pub_key = "",
        .mode = kAppenderSync,
        .compress_mode = kZstd,
    },
};

void setupLog() {

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *dirName = @"test_xlog";
        NSString *logPath = [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0] stringByAppendingPathComponent:dirName];

        NSLog(@"%@", logPath);

        // set do not backup for logpath
        const char *attrName = "com.apple.MobileBackup";
        u_int8_t attrValue = 1;
        setxattr(logPath.UTF8String, attrName, &attrValue, sizeof(attrValue), 0, 0);

        int count = sizeof(logConfigs) / sizeof(LogConfig);
        for (int i = 0; i < count; i++) {
            LogConfig conf = logConfigs[i];
            XLogConfig config;
            config.logdir_ = logPath.UTF8String;
            config.nameprefix_ = conf.name;
            config.pub_key_ = conf.pub_key;

            mars::comm::XloggerCategory *logger = mars::xlog::NewXloggerInstance(config, kLevelAll);
            mars::xlog::SetConsoleLogOpen(uintptr_t(logger), true);
        }
    });
}

void wirte_log(std::string body) {
    int count = sizeof(logConfigs) / sizeof(LogConfig);
    for (int i = 0; i < count; i++) {
        LogConfig conf = logConfigs[i];
        mars::comm::XloggerCategory *logger = mars::xlog::GetXloggerInstance(conf.name.c_str());
        if (logger == nullptr) {
            continue;
        }
        mars::xlog::XloggerWrite(uintptr_t(logger), NULL, body.c_str());
    }
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    setupLog();
}

- (IBAction)flushAction:(id)sender {

    int count = sizeof(logConfigs) / sizeof(LogConfig);
    for (int i = 0; i < count; i++) {
        LogConfig conf = logConfigs[i];
        mars::comm::XloggerCategory *logger = mars::xlog::GetXloggerInstance(conf.name.c_str());
        if (logger == nullptr) {
            continue;
        }
        mars::xlog::Flush(uintptr_t(logger), true);
    }
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [super touchesBegan:touches withEvent:event];

    wirte_log("test stetts tattdtatdtatftaftatftft");
}
@end

