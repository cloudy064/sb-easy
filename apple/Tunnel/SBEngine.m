#import "SBEngine.h"
#import <TargetConditionals.h>
#import <Libbox/Libbox.h>
#import <Network/Network.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <arpa/inet.h>
#import <sys/stat.h>

static BOOL fail(NSError **error, NSString *message) {
    if (error) *error = [NSError errorWithDomain:@"io.sbeasy.tunnel" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
@interface SBStrings : NSObject <LibboxStringIterator>
@property (strong) NSArray<NSString *> *values;
@property (assign) NSUInteger offset;
@end
@implementation SBStrings
- (BOOL)hasNext { return self.offset < self.values.count; }
- (int32_t)len { return (int32_t)self.values.count; }
- (NSString *)next { return [self hasNext] ? self.values[self.offset++] : @""; }
@end
@interface SBInterfaces : NSObject <LibboxNetworkInterfaceIterator>
@property (strong) NSArray<LibboxNetworkInterface *> *values;
@property (assign) NSUInteger offset;
@end
@implementation SBInterfaces
- (BOOL)hasNext { return self.offset < self.values.count; }
- (LibboxNetworkInterface *)next { return [self hasNext] ? self.values[self.offset++] : nil; }
@end
@interface SBPlatform : NSObject <LibboxPlatformInterface, LibboxCommandServerHandler>
@property (weak) NEPacketTunnelProvider *provider;
@property (strong) nw_path_monitor_t monitor;
@property (strong) dispatch_queue_t monitorQueue;
@property (strong) id<LibboxInterfaceUpdateListener> listener;
@property (strong) NSDictionary<NSString *,NSNumber *> *interfaceTypes;
@property (copy) NSString *defaultName;
@property (assign) BOOL expensive;
@property (assign) BOOL cancelled;
@property (strong) dispatch_semaphore_t pendingSettings;
@property (strong) dispatch_semaphore_t pendingPath;
- (void)cancel;
@end
@implementation SBPlatform
- (void)cancel { self.cancelled=YES; dispatch_semaphore_t settings=self.pendingSettings, path=self.pendingPath; if(settings) dispatch_semaphore_signal(settings); if(path) dispatch_semaphore_signal(path); }
- (BOOL)openTun:(id<LibboxTunOptions>)options ret0_:(int32_t *)fd error:(NSError **)error {
    if (self.cancelled || !options || !fd || !options.getAutoRoute) return fail(error,@"Invalid tunnel options");
    if (options.isHTTPProxyEnabled || options.getIncludePackage.hasNext || options.getExcludePackage.hasNext)
        return fail(error,@"Unsupported tunnel policy");
    NEPacketTunnelNetworkSettings *settings = [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:@"127.0.0.1"];
    settings.MTU = @(options.getMTU);
    NSMutableArray *addresses = [NSMutableArray array], *masks = [NSMutableArray array];
    id<LibboxRoutePrefixIterator> iterator = options.getInet4Address;
    while (iterator.hasNext) { LibboxRoutePrefix *prefix = iterator.next; [addresses addObject:prefix.address]; [masks addObject:prefix.mask]; }
    if (addresses.count) {
        NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:addresses subnetMasks:masks];
        NSMutableArray *routes = [NSMutableArray array], *excludes = [NSMutableArray array];
        iterator = options.getInet4RouteAddress;
        while (iterator.hasNext) { LibboxRoutePrefix *p=iterator.next; [routes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:p.address subnetMask:p.mask]]; }
        if (!routes.count) [routes addObject:NEIPv4Route.defaultRoute];
        iterator = options.getInet4RouteExcludeAddress;
        while (iterator.hasNext) { LibboxRoutePrefix *p=iterator.next; [excludes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:p.address subnetMask:p.mask]]; }
        ipv4.includedRoutes=routes; ipv4.excludedRoutes=excludes; settings.IPv4Settings=ipv4;
    }
    addresses=[NSMutableArray array]; masks=[NSMutableArray array]; iterator=options.getInet6Address;
    while (iterator.hasNext) { LibboxRoutePrefix *p=iterator.next; [addresses addObject:p.address]; [masks addObject:@(p.prefix)]; }
    if (addresses.count) {
        NEIPv6Settings *ipv6=[[NEIPv6Settings alloc] initWithAddresses:addresses networkPrefixLengths:masks];
        NSMutableArray *routes=[NSMutableArray array], *excludes=[NSMutableArray array];
        iterator=options.getInet6RouteAddress;
        while(iterator.hasNext) { LibboxRoutePrefix *p=iterator.next; [routes addObject:[[NEIPv6Route alloc] initWithDestinationAddress:p.address networkPrefixLength:@(p.prefix)]]; }
        if (!routes.count) [routes addObject:NEIPv6Route.defaultRoute];
        iterator=options.getInet6RouteExcludeAddress;
        while(iterator.hasNext) { LibboxRoutePrefix *p=iterator.next; [excludes addObject:[[NEIPv6Route alloc] initWithDestinationAddress:p.address networkPrefixLength:@(p.prefix)]]; }
        ipv6.includedRoutes=routes; ipv6.excludedRoutes=excludes; settings.IPv6Settings=ipv6;
    }
    NSError *dnsError=nil;
    id<LibboxStringIterator> dns=[options getDNSServerAddress:&dnsError];
    if(dnsError) return fail(error,@"DNS setup failed");
    NSMutableArray *servers=[NSMutableArray array]; while(dns.hasNext) [servers addObject:dns.next];
    if(!servers.count) return fail(error,@"Tunnel DNS is unavailable");
    settings.DNSSettings=[[NEDNSSettings alloc] initWithServers:servers];
    settings.DNSSettings.matchDomains=@[@""]; settings.DNSSettings.matchDomainsNoSearch=YES;
    dispatch_semaphore_t ready=dispatch_semaphore_create(0);
    self.pendingSettings=ready;
    if(self.cancelled) return fail(error,@"Tunnel cancelled");
    __block NSError *applyError=nil;
    [self.provider setTunnelNetworkSettings:settings completionHandler:^(NSError *e) { applyError=e; dispatch_semaphore_signal(ready); }];
    long timedOut=dispatch_semaphore_wait(ready,dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC));
    self.pendingSettings=nil;
    if(timedOut || self.cancelled || applyError) return fail(error,@"Network settings could not be installed");
    int32_t descriptor=LibboxGetTunnelFileDescriptor();
    if(descriptor<0) return fail(error,@"Tunnel descriptor is unavailable");
    *fd=descriptor; return YES;
}
- (id<LibboxNetworkInterfaceIterator>)getInterfaces:(NSError **)error {
    struct ifaddrs *list=NULL;
    if(getifaddrs(&list)) { fail(error,@"Interfaces unavailable"); return nil; }
    NSMutableDictionary<NSString *,LibboxNetworkInterface *> *interfaces=[NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *,NSMutableArray<NSString *> *> *addresses=[NSMutableDictionary dictionary];
    for(struct ifaddrs *entry=list;entry;entry=entry->ifa_next) {
        if(!entry->ifa_name || !entry->ifa_addr) continue;
        NSString *name=@(entry->ifa_name);
        LibboxNetworkInterface *interface=interfaces[name];
        if(!interface) {
            interface=[LibboxNetworkInterface new]; interface.name=name; interface.index=(int32_t)if_nametoindex(entry->ifa_name); interface.mtu=1500;
            unsigned flags=entry->ifa_flags;
            interface.flags=(int32_t)flags; interface.type=LibboxInterfaceTypeOther;
            @synchronized(self) {
                NSNumber *type=self.interfaceTypes[name]; if(type) interface.type=type.intValue;
                interface.metered=[name isEqualToString:self.defaultName] && self.expensive;
            }
            interfaces[name]=interface; addresses[name]=[NSMutableArray array];
        }
        int family=entry->ifa_addr->sa_family; const void *raw=NULL; const unsigned char *mask=NULL; size_t bytes=0;
        if(family==AF_INET) { raw=&((struct sockaddr_in *)entry->ifa_addr)->sin_addr; if(entry->ifa_netmask) mask=(void *)&((struct sockaddr_in *)entry->ifa_netmask)->sin_addr; bytes=4; }
        if(family==AF_INET6) { raw=&((struct sockaddr_in6 *)entry->ifa_addr)->sin6_addr; if(entry->ifa_netmask) mask=(void *)&((struct sockaddr_in6 *)entry->ifa_netmask)->sin6_addr; bytes=16; }
        char output[INET6_ADDRSTRLEN];
        if(raw && inet_ntop(family,raw,output,sizeof output)) {
            unsigned prefix=0; for(size_t i=0;mask && i<bytes;++i) for(unsigned b=0;b<8;++b) if(mask[i]&(128u>>b)) ++prefix;
            [addresses[name] addObject:[NSString stringWithFormat:@"%s/%u",output,prefix]];
        }
    }
    freeifaddrs(list);
    for(NSString *name in interfaces) { SBStrings *strings=[SBStrings new]; strings.values=addresses[name]; interfaces[name].addresses=strings; }
    SBInterfaces *result=[SBInterfaces new]; result.values=interfaces.allValues; return result;
}
- (BOOL)startDefaultInterfaceMonitor:(id<LibboxInterfaceUpdateListener>)listener error:(NSError **)error {
    if(self.cancelled || !listener || self.monitor) return fail(error,@"Invalid interface monitor");
    self.listener=listener; self.monitor=nw_path_monitor_create(); self.monitorQueue=dispatch_queue_create("io.sbeasy.path",DISPATCH_QUEUE_SERIAL);
    nw_path_monitor_set_queue(self.monitor,self.monitorQueue);
    dispatch_semaphore_t initial=dispatch_semaphore_create(0); self.pendingPath=initial;
    __weak SBPlatform *weakSelf=self;
    nw_path_monitor_set_update_handler(self.monitor,^(nw_path_t path) {
        SBPlatform *strongSelf=weakSelf; if(!strongSelf) return;
        __block NSString *name=@""; __block int32_t index=-1;
        NSMutableDictionary *types=[NSMutableDictionary dictionary];
        nw_path_enumerate_interfaces(path,^bool(nw_interface_t interface) {
            nw_interface_type_t type=nw_interface_get_type(interface);
            NSString *current=@(nw_interface_get_name(interface));
            int32_t value=type==nw_interface_type_wifi ? LibboxInterfaceTypeWIFI : type==nw_interface_type_cellular ? LibboxInterfaceTypeCellular : type==nw_interface_type_wired ? LibboxInterfaceTypeEthernet : LibboxInterfaceTypeOther;
            types[current]=@(value);
            if(index<0 && type!=nw_interface_type_loopback && nw_path_get_status(path)==nw_path_status_satisfied) {
                name=current; index=(int32_t)nw_interface_get_index(interface);
            }
            return true;
        });
        @synchronized(strongSelf) { strongSelf.interfaceTypes=types; strongSelf.defaultName=name; strongSelf.expensive=nw_path_is_expensive(path); }
        [strongSelf.listener updateDefaultInterface:name interfaceIndex:index isExpensive:nw_path_is_expensive(path) isConstrained:nw_path_is_constrained(path)];
        dispatch_semaphore_signal(initial);
    });
    nw_path_monitor_start(self.monitor);
    if(self.cancelled) dispatch_semaphore_signal(initial);
    long timedOut=dispatch_semaphore_wait(initial,dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC)); self.pendingPath=nil;
    if(timedOut || self.cancelled) {
        [self closeDefaultInterfaceMonitor:listener error:nil]; return fail(error,@"Network path unavailable");
    }
    return YES;
}
- (BOOL)closeDefaultInterfaceMonitor:(id<LibboxInterfaceUpdateListener>)listener error:(NSError **)error {
    if(self.monitor) nw_path_monitor_cancel(self.monitor); self.monitor=nil; self.listener=nil; return YES;
}
- (BOOL)underNetworkExtension { return YES; }
- (BOOL)includeAllNetworks { return NO; }
- (BOOL)usePlatformAutoDetectInterfaceControl { return NO; }
- (BOOL)usePlatformBridge { return NO; }
- (BOOL)usePlatformShell { return NO; }
- (BOOL)useProcFS { return NO; }
- (BOOL)autoDetectInterfaceControl:(int32_t)fd error:(NSError **)error { return fail(error,@"Unsupported interface control"); }
- (void)clearDNSCache {}
- (void)registerMyInterface:(NSString *)name {}
- (id<LibboxLocalDNSTransport>)localDNSTransport { return nil; }
- (LibboxWIFIState *)readWIFIState { return nil; }
- (NSString *)tailscaleHostname { return @"sb-easy-apple"; }
- (LibboxConnectionOwner *)findConnectionOwner:(int32_t)protocol sourceAddress:(NSString *)source sourcePort:(int32_t)sourcePort destinationAddress:(NSString *)destination destinationPort:(int32_t)destinationPort error:(NSError **)error { fail(error,@"Process routing is unavailable"); return nil; }
- (BOOL)startNeighborMonitor:(id<LibboxNeighborUpdateListener>)listener error:(NSError **)error { return fail(error,@"Neighbor monitor is unavailable"); }
- (BOOL)closeNeighborMonitor:(id<LibboxNeighborUpdateListener>)listener error:(NSError **)error { return YES; }
- (id<LibboxBridgeSession>)createBridge:(LibboxBridgeOptions *)options error:(NSError **)error { fail(error,@"Bridging is unavailable"); return nil; }
- (BOOL)checkPlatformShell:(NSError **)error { return fail(error,@"Shell is unavailable"); }
- (LibboxPlatformUser *)lookupUser:(NSString *)username error:(NSError **)error { fail(error,@"Shell is unavailable"); return nil; }
- (id<LibboxShellSession>)openShellSession:(LibboxPlatformUser *)user command:(NSString *)command environ:(id<LibboxStringIterator>)environ term:(NSString *)term rows:(int32_t)rows cols:(int32_t)cols error:(NSError **)error { fail(error,@"Shell is unavailable"); return nil; }
- (NSString *)lookupSFTPServer:(NSError **)error { fail(error,@"SFTP is unavailable"); return @""; }
- (NSString *)readSystemSSHHostKey:(NSError **)error { fail(error,@"SSH is unavailable"); return @""; }
- (BOOL)sendNotification:(LibboxNotification *)notification error:(NSError **)error { return fail(error,@"Notification is unavailable"); }
- (BOOL)cancelNotification:(NSString *)identifier typeID:(int32_t)typeID error:(NSError **)error { return YES; }
- (BOOL)connectSSHAgent:(int32_t *)fd error:(NSError **)error { return fail(error,@"SSH is unavailable"); }
- (LibboxSystemProxyStatus *)getSystemProxyStatus:(NSError **)error { return [LibboxSystemProxyStatus new]; }
- (BOOL)setSystemProxyEnabled:(BOOL)enabled error:(NSError **)error { return fail(error,@"System proxy is unavailable"); }
- (BOOL)serviceReload:(NSError **)error { return fail(error,@"Reload requires authenticated app IPC"); }
- (BOOL)serviceStop:(NSError **)error { [self.provider cancelTunnelWithError:nil]; return YES; }
- (BOOL)triggerNativeCrash:(NSError **)error { return fail(error,@"Disabled"); }
- (void)writeDebugMessage:(NSString *)message {}
@end
@interface SBEngine ()
@property (strong) SBPlatform *platform;
@property (strong) LibboxCommandServer *server;
@property (assign) BOOL cancelled;
@end
@implementation SBEngine
- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider {
    if((self=[super init])) { self.platform=[SBPlatform new]; self.platform.provider=provider; } return self;
}
- (BOOL)start:(NSString *)configuration directory:(NSURL *)directory error:(NSError **)error {
    if(self.cancelled || self.server) return fail(error,@"Already started or cancelled");
    umask(0077);
    LibboxSetupOptions *options=[LibboxSetupOptions new];
    options.basePath=directory.path; options.workingPath=directory.path;
    options.tempPath=[directory URLByAppendingPathComponent:@"tmp" isDirectory:YES].path;
    if(![[NSFileManager defaultManager] createDirectoryAtPath:options.tempPath withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0700} error:error]) return NO;
    options.logMaxLines=100; options.crashReportSource=@"NetworkExtension"; options.appVersion=@"1"; options.appMarketingVersion=@"0.1.0";
#if TARGET_OS_OSX
    options.oomKillerDisabled=YES;
#else
    options.oomKillerEnabled=YES;
#endif
    NSError *ignored=nil;
    if(!LibboxSetup(options,&ignored) || !LibboxCheckConfig(configuration,&ignored)) return fail(error,@"Core configuration rejected");
    self.server=LibboxNewCommandServer(self.platform,self.platform,&ignored);
    // Deliberately do not call server.start: only signed NetworkExtension IPC is exposed.
    if(self.cancelled || !self.server || ![self.server appleStartOrReloadService:configuration error:&ignored] || self.cancelled) {
        [self stop]; return fail(error,@"Core could not start");
    }
    return YES;
}
- (BOOL)reload:(NSString *)configuration error:(NSError **)error {
    NSError *ignored=nil;
    if(self.cancelled || !self.server || !LibboxCheckConfig(configuration,&ignored) || ![self.server appleStartOrReloadService:configuration error:&ignored] || self.cancelled) return fail(error,@"Core could not reload");
    return YES;
}
- (void)interrupt {
    self.cancelled=YES; [self.platform cancel];
    LibboxCommandServer *server=self.server;
    if(server) dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{ [server closeService:nil]; });
}
- (void)stop { if(self.server) { [self.server closeService:nil]; [self.server close]; self.server=nil; } [self.platform closeDefaultInterfaceMonitor:nil error:nil]; }
- (void)pause { [self.server pause]; }
- (void)wake { [self.server wake]; [self.server resetNetwork]; }
- (NSString *)snapshot:(NSError **)error {
    if(self.server) return [self.server appleSnapshot:error];
    fail(error,@"Core unavailable");
    return nil;
}
- (BOOL)select:(NSString *)group target:(NSString *)target error:(NSError **)error { return self.server && [self.server appleSelectOutbound:group outboundTag:target error:error]; }
- (BOOL)probe:(NSString *)target error:(NSError **)error { return self.server && [self.server appleURLTest:target error:error]; }
@end
