#import <Foundation/Foundation.h>

@interface Counter : NSObject
- (int)scaled:(int)value;
@end

@implementation Counter
- (int)scaled:(int)value { return value * 3; }
@end

int main(void) {
    Counter *counter = [Counter new];
    int total = [counter scaled:2];
    total += [counter scaled:5];
    return total;
}
