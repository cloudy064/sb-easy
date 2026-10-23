#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
NS_ASSUME_NONNULL_BEGIN
// All operations except cancel are called on PacketTunnelProvider's serial queue.
@interface SBEngine : NSObject
- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider;
- (BOOL)start:(NSString *)configuration directory:(NSURL *)directory error:(NSError **)error;
- (BOOL)reload:(NSString *)configuration error:(NSError **)error;
- (void)stop;
// Thread-safe, nonblocking cancellation of a pending core/NE start.
- (void)interrupt;
- (void)pause;
- (void)wake;
- (nullable NSString *)snapshot:(NSError **)error;
- (BOOL)select:(NSString *)group target:(NSString *)target error:(NSError **)error;
- (BOOL)probe:(NSString *)target error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
