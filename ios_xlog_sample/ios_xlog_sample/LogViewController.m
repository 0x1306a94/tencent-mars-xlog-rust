//
//  LogViewController.m
//  ios_xlog_sample
//
//  Created by king on 2022/1/17.
//

#import "LogViewController.h"

@interface LogViewController ()
@property (weak, nonatomic) IBOutlet UITextView *textView;
@property (nonatomic, strong) NSString *path;
@end

@implementation LogViewController
- (instancetype)initWithLogPath:(NSString *)path {
    if (self == [super init]) {
        self.path = path;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view from its nib.

    NSString *content = [NSString stringWithContentsOfFile:self.path encoding:NSUTF8StringEncoding error:nil];
    self.textView.text = content;
}

@end

