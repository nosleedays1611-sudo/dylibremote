#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <QuartzCore/QuartzCore.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#import <mach-o/getsect.h>
#import <mach-o/ldsyms.h>

// REMOTE AUTH — KEY + public IPv4, same separated-dylib architecture as EXTERNAL.
// Backend authority: https://remoteios.xyz
// Existing REMOTE backend compatibility. No backend changes are required.
// Login: POST /api/auth/activate with KEY + public IPv4.
// Session validation: GET /api/auth/me with Bearer token.
// The public IPv4 is detected in the dylib the same way the current web panel does.
static NSString * const kEAAPIBaseURL = @"https://remoteios.xyz";
static NSString * const kEAKeychainService = @"app.remote.auth";
static NSString * const kEAKeyAccount = @"license-key";
static NSString * const kEATokenAccount = @"session-token";
static NSString * const kEAMarker = @"REMOTE-AUTH-CURRENT-BACKEND-V4";
static NSTimeInterval const kEACheckInterval = 20.0;
static NSTimeInterval const kEANetworkGrace = 45.0;

#pragma mark - Small helpers

static NSString *EAString(id value) {
    return [value isKindOfClass:[NSString class]] ? (NSString *)value : nil;
}

static NSDictionary *EADictionary(id value) {
    return [value isKindOfClass:[NSDictionary class]] ? (NSDictionary *)value : nil;
}

static BOOL EABool(id value) {
    if ([value respondsToSelector:@selector(boolValue)]) return [value boolValue];
    return NO;
}

static NSString *EANonEmptyString(id value) {
    NSString *s = EAString(value);
    if (!s) return nil;
    s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return s.length ? s : nil;
}

static BOOL EAIsValidIPv4(NSString *value) {
    NSString *ip = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSArray<NSString *> *parts = [ip componentsSeparatedByString:@"."];
    if (parts.count != 4) return NO;
    NSCharacterSet *notDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    for (NSString *part in parts) {
        if (part.length < 1 || part.length > 3) return NO;
        if ([part rangeOfCharacterFromSet:notDigits].location != NSNotFound) return NO;
        NSInteger n = part.integerValue;
        if (n < 0 || n > 255) return NO;
    }
    return YES;
}

static NSString *EAFirstString(NSDictionary *json, NSArray<NSString *> *keys) {
    for (NSString *key in keys) {
        NSString *v = EANonEmptyString(json[key]);
        if (v) return v;
    }
    NSDictionary *session = EADictionary(json[@"session"]);
    NSDictionary *license = EADictionary(json[@"license"]);
    for (NSString *key in keys) {
        NSString *v = EANonEmptyString(session[key]);
        if (v) return v;
        v = EANonEmptyString(license[key]);
        if (v) return v;
    }
    return nil;
}

static NSString *EAErrorCode(NSDictionary *json) {
    return EAFirstString(json, @[@"error", @"code", @"status"]);
}

static NSString *EAHumanError(NSString *code) {
    NSString *c = code.lowercaseString ?: @"";
    if ([c isEqualToString:@"invalid_key"] || [c isEqualToString:@"invalid_key_format"] || [c isEqualToString:@"unauthorized"]) return @"Key inválida.";
    if ([c isEqualToString:@"disabled"]) return @"Key desativada.";
    if ([c isEqualToString:@"paused"]) return @"Key pausada.";
    if ([c isEqualToString:@"expired"]) return @"Key expirada.";
    if ([c isEqualToString:@"ipv4_mismatch"]) return @"IPv4 diferente do vinculado à key.";
    if ([c isEqualToString:@"not_activated"] || [c isEqualToString:@"unused"]) return @"Ative essa key primeiro no site.";
    if ([c isEqualToString:@"invalid_token"]) return @"Sessão inválida.";
    if ([c isEqualToString:@"token_expired"]) return @"Sessão expirada.";
    if ([c isEqualToString:@"session_revoked"]) return @"Sessão revogada.";
    if ([c isEqualToString:@"rate_limited"]) return @"Muitas tentativas. Aguarde um pouco.";
    return @"Não foi possível autenticar.";
}

#pragma mark - Keychain

static NSString *EAKeychainRead(NSString *account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kEAKeychainService,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    CFTypeRef out = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &out);
    if (status != errSecSuccess || !out) return nil;
    NSData *data = CFBridgingRelease(out);
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static void EAKeychainWrite(NSString *account, NSString *value) {
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *base = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kEAKeychainService,
        (__bridge id)kSecAttrAccount: account
    };
    NSDictionary *update = @{ (__bridge id)kSecValueData: data };
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)base, (__bridge CFDictionaryRef)update);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *add = [base mutableCopy];
        add[(__bridge id)kSecValueData] = data;
        add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
        SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    }
}

static void EAKeychainDelete(NSString *account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kEAKeychainService,
        (__bridge id)kSecAttrAccount: account
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

#pragma mark - GIF embedded in __DATA,__eaicon

static NSData *EAEmbeddedGIFData(void) {
    unsigned long size = 0;
    const uint8_t *bytes = getsectiondata((const struct mach_header_64 *)&_mh_dylib_header,
                                          "__DATA", "__eaicon", &size);
    if (!bytes || size == 0) return nil;
    return [NSData dataWithBytes:bytes length:(NSUInteger)size];
}

static NSArray<UIImage *> *EAGIFFrames(void) {
    NSData *data = EAEmbeddedGIFData();
    if (!data) return @[];
    CGImageSourceRef source = CGImageSourceCreateWithData((__bridge CFDataRef)data, NULL);
    if (!source) return @[];
    size_t count = CGImageSourceGetCount(source);
    NSMutableArray<UIImage *> *frames = [NSMutableArray arrayWithCapacity:count];
    for (size_t i = 0; i < count; i++) {
        CGImageRef cg = CGImageSourceCreateImageAtIndex(source, i, NULL);
        if (cg) {
            [frames addObject:[UIImage imageWithCGImage:cg]];
            CGImageRelease(cg);
        }
    }
    CFRelease(source);
    return frames;
}

#pragma mark - Background particles

@interface EARemoteParticlesView : UIView
@property (nonatomic, strong) CADisplayLink *displayLink;
@property (nonatomic) CFTimeInterval startTime;
@end

@implementation EARemoteParticlesView

- (instancetype)initWithFrame:(CGRect)frame {
    if ((self = [super initWithFrame:frame])) {
        self.backgroundColor = UIColor.blackColor;
        self.userInteractionEnabled = NO;
        _startTime = CACurrentMediaTime();
        _displayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(tick:)];
        if (@available(iOS 15.0, *)) {
            _displayLink.preferredFrameRateRange = CAFrameRateRangeMake(50, 50, 50);
        } else {
            _displayLink.preferredFramesPerSecond = 50;
        }
        [_displayLink addToRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];
    }
    return self;
}

- (void)dealloc { [_displayLink invalidate]; }
- (void)tick:(CADisplayLink *)link { [self setNeedsDisplay]; }

- (NSArray<NSValue *> *)points {
    static const CGFloat base[][2] = {
        {0.08,0.13},{0.30,0.10},{0.51,0.18},{0.73,0.09},{0.92,0.20},
        {0.14,0.39},{0.38,0.32},{0.62,0.40},{0.86,0.33},{0.09,0.64},
        {0.32,0.73},{0.54,0.61},{0.74,0.75},{0.93,0.63},{0.18,0.90},
        {0.44,0.84},{0.68,0.92},{0.88,0.85}
    };
    const NSUInteger count = sizeof(base)/sizeof(base[0]);
    CFTimeInterval t = CACurrentMediaTime() - self.startTime;
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:count];
    for (NSUInteger i=0; i<count; i++) {
        CGFloat sx = 0.85 + (CGFloat)(i % 5) * 0.09;
        CGFloat sy = 0.72 + (CGFloat)(i % 7) * 0.07;
        CGFloat x = self.bounds.size.width * base[i][0] + sin(t*sx + i*1.37) * (8.0 + (i%4)*2.0);
        CGFloat y = self.bounds.size.height * base[i][1] + cos(t*sy + i*1.11) * (7.0 + (i%3)*2.2);
        [out addObject:[NSValue valueWithCGPoint:CGPointMake(x,y)]];
    }
    return out;
}

- (void)drawRect:(CGRect)rect {
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    if (!ctx) return;
    [[UIColor blackColor] setFill];
    UIRectFill(rect);
    NSArray<NSValue *> *points = [self points];
    CGContextSetLineWidth(ctx, 0.55);
    for (NSUInteger i=0; i<points.count; i++) {
        CGPoint a = points[i].CGPointValue;
        for (NSUInteger j=i+1; j<points.count; j++) {
            CGPoint b = points[j].CGPointValue;
            CGFloat dx=a.x-b.x, dy=a.y-b.y;
            CGFloat d=sqrt(dx*dx+dy*dy);
            CGFloat limit = 92.0 + ((i*17+j*11)%70);
            if (d < limit) {
                CGFloat alpha = 0.02 + 0.07 * (1.0 - d/limit);
                CGContextSetStrokeColorWithColor(ctx, [UIColor colorWithWhite:1 alpha:alpha].CGColor);
                CGContextMoveToPoint(ctx,a.x,a.y); CGContextAddLineToPoint(ctx,b.x,b.y); CGContextStrokePath(ctx);
            }
        }
    }
    for (NSValue *v in points) {
        CGPoint p=v.CGPointValue;
        CGContextSetFillColorWithColor(ctx,[UIColor colorWithWhite:1 alpha:0.62].CGColor);
        CGContextFillEllipseInRect(ctx,CGRectMake(p.x-1.6,p.y-1.6,3.2,3.2));
    }
}
@end

#pragma mark - Manager

@interface RemoteAuthManager : NSObject <UITextFieldDelegate>
@property (nonatomic, readonly) BOOL unlocked;
@property (nonatomic, copy, readonly) NSString *validatedKey;
@property (nonatomic, copy, readonly) NSString *validatedIPv4;
// Compatibility alias for the older EXTERNAL bridge. On REMOTE this returns the validated public IPv4.
@property (nonatomic, copy, readonly) NSString *validatedHWID;
@property (nonatomic, copy, readonly) NSString *securitySessionToken;
@property (nonatomic, copy, readonly) NSString *securitySessionExpiresAt;
@property (nonatomic, copy, readonly) NSString *heartbeatNonce;
@property (nonatomic, readonly) double lastServerSuccess;
+ (instancetype)shared;
- (void)start;
- (void)logout;
@end

@implementation RemoteAuthManager {
    BOOL _unlocked;
    NSString *_validatedKey;
    NSString *_validatedIPv4;
    NSString *_securitySessionToken;
    NSString *_securitySessionExpiresAt;
    NSString *_heartbeatNonce;
    double _lastServerSuccess;

    UIWindow *_authWindow;
    UIViewController *_rootVC;
    UITextField *_keyField;
    UITextField *_ipv4Field;
    UILabel *_statusLabel;
    UIButton *_loginButton;
    UIButton *_detectButton;
    UIImageView *_gifView;
    NSTimer *_checkTimer;
    NSURLSession *_session;
    BOOL _started;
    BOOL _requestInFlight;
}

+ (instancetype)shared {
    static RemoteAuthManager *manager;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ manager = [RemoteAuthManager new]; });
    return manager;
}

- (instancetype)init {
    if ((self = [super init])) {
        NSURLSessionConfiguration *cfg = NSURLSessionConfiguration.ephemeralSessionConfiguration;
        cfg.timeoutIntervalForRequest = 12.0;
        cfg.timeoutIntervalForResource = 18.0;
        cfg.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        _session = [NSURLSession sessionWithConfiguration:cfg];
        _heartbeatNonce = [NSUUID UUID].UUIDString;
        _securitySessionExpiresAt = @"";
        (void)kEAMarker;
    }
    return self;
}

- (BOOL)unlocked { @synchronized (self) { return _unlocked; } }
- (NSString *)validatedKey { @synchronized (self) { return _validatedKey ?: @""; } }
- (NSString *)validatedIPv4 { @synchronized (self) { return _validatedIPv4 ?: @""; } }
- (NSString *)validatedHWID { return self.validatedIPv4; }
- (NSString *)securitySessionToken { @synchronized (self) { return _securitySessionToken ?: @""; } }
- (NSString *)securitySessionExpiresAt { @synchronized (self) { return _securitySessionExpiresAt ?: @""; } }
- (NSString *)heartbeatNonce { @synchronized (self) { return _heartbeatNonce ?: @""; } }
- (double)lastServerSuccess { @synchronized (self) { return _lastServerSuccess; } }

- (void)start {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self->_started) {
            self->_started = YES;
            [[NSNotificationCenter defaultCenter] addObserver:self
                                                     selector:@selector(applicationBecameActive:)
                                                         name:UIApplicationDidBecomeActiveNotification
                                                       object:nil];
        }
        [self ensureOverlay];
        [self restoreSessionOrShowLogin];
    });
}

- (void)applicationBecameActive:(NSNotification *)note {
    [self ensureOverlay];
    if (self.unlocked) [self checkSession];
}

- (UIWindowScene *)activeWindowScene {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:UIWindowScene.class] && scene.activationState == UISceneActivationStateForegroundActive) {
            return (UIWindowScene *)scene;
        }
    }
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:UIWindowScene.class]) return (UIWindowScene *)scene;
    }
    return nil;
}

- (void)ensureOverlay {
    if (_authWindow) return;
    UIWindowScene *scene = [self activeWindowScene];
    if (!scene) return;

    _authWindow = [[UIWindow alloc] initWithWindowScene:scene];
    _authWindow.frame = UIScreen.mainScreen.bounds;
    _authWindow.windowLevel = UIWindowLevelAlert + 100.0;
    _authWindow.backgroundColor = UIColor.blackColor;

    _rootVC = [UIViewController new];
    _rootVC.view.backgroundColor = UIColor.blackColor;
    _authWindow.rootViewController = _rootVC;

    UIStackView *stack = [[UIStackView alloc] initWithFrame:CGRectZero];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentFill;
    stack.spacing = 14.0;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [_rootVC.view addSubview:stack];

    UIView *gifHolder = [UIView new];
    [gifHolder.heightAnchor constraintEqualToConstant:142.0].active = YES;
    [stack addArrangedSubview:gifHolder];

    _gifView = [[UIImageView alloc] initWithFrame:CGRectZero];
    _gifView.translatesAutoresizingMaskIntoConstraints = NO;
    _gifView.contentMode = UIViewContentModeScaleAspectFill;
    _gifView.layer.cornerRadius = 24.0;
    _gifView.layer.masksToBounds = YES;
    _gifView.backgroundColor = UIColor.blackColor;
    [gifHolder addSubview:_gifView];

    NSArray<UIImage *> *frames = EAGIFFrames();
    if (frames.count) {
        _gifView.image = frames.firstObject;
        _gifView.animationImages = frames;
        _gifView.animationDuration = (NSTimeInterval)frames.count / 50.0;
        _gifView.animationRepeatCount = 0;
        [_gifView startAnimating];
    }

    [NSLayoutConstraint activateConstraints:@[
        [_gifView.centerXAnchor constraintEqualToAnchor:gifHolder.centerXAnchor],
        [_gifView.centerYAnchor constraintEqualToAnchor:gifHolder.centerYAnchor],
        [_gifView.widthAnchor constraintEqualToConstant:142.0],
        [_gifView.heightAnchor constraintEqualToConstant:142.0]
    ]];

    UILabel *subtitle = [UILabel new];
    subtitle.text = @"Digite sua key para continuar";
    subtitle.textColor = [UIColor colorWithWhite:1.0 alpha:0.66];
    subtitle.textAlignment = NSTextAlignmentCenter;
    subtitle.font = [UIFont systemFontOfSize:17.0 weight:UIFontWeightRegular];
    [subtitle.heightAnchor constraintEqualToConstant:34.0].active = YES;
    [stack addArrangedSubview:subtitle];

    UIView *fieldContainer = [UIView new];
    fieldContainer.backgroundColor = [UIColor colorWithWhite:0.065 alpha:1.0];
    fieldContainer.layer.cornerRadius = 17.0;
    fieldContainer.layer.borderWidth = 1.0;
    fieldContainer.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.13].CGColor;
    [fieldContainer.heightAnchor constraintEqualToConstant:64.0].active = YES;
    [stack addArrangedSubview:fieldContainer];

    _keyField = [UITextField new];
    _keyField.translatesAutoresizingMaskIntoConstraints = NO;
    _keyField.textColor = UIColor.whiteColor;
    _keyField.tintColor = UIColor.whiteColor;
    _keyField.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightRegular];
    _keyField.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:@"KEY"
        attributes:@{NSForegroundColorAttributeName:[UIColor colorWithWhite:1.0 alpha:0.28]}];
    _keyField.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    _keyField.autocorrectionType = UITextAutocorrectionTypeNo;
    _keyField.spellCheckingType = UITextSpellCheckingTypeNo;
    _keyField.returnKeyType = UIReturnKeyGo;
    _keyField.delegate = self;
    [fieldContainer addSubview:_keyField];
    [NSLayoutConstraint activateConstraints:@[
        [_keyField.leadingAnchor constraintEqualToAnchor:fieldContainer.leadingAnchor constant:18.0],
        [_keyField.trailingAnchor constraintEqualToAnchor:fieldContainer.trailingAnchor constant:-18.0],
        [_keyField.topAnchor constraintEqualToAnchor:fieldContainer.topAnchor],
        [_keyField.bottomAnchor constraintEqualToAnchor:fieldContainer.bottomAnchor]
    ]];

    UIStackView *ipRow = [[UIStackView alloc] initWithFrame:CGRectZero];
    ipRow.axis = UILayoutConstraintAxisHorizontal;
    ipRow.alignment = UIStackViewAlignmentFill;
    ipRow.distribution = UIStackViewDistributionFill;
    ipRow.spacing = 12.0;
    [ipRow.heightAnchor constraintEqualToConstant:60.0].active = YES;
    [stack addArrangedSubview:ipRow];

    UIView *ipContainer = [UIView new];
    ipContainer.backgroundColor = [UIColor colorWithWhite:0.065 alpha:1.0];
    ipContainer.layer.cornerRadius = 17.0;
    ipContainer.layer.borderWidth = 1.0;
    ipContainer.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.13].CGColor;
    [ipRow addArrangedSubview:ipContainer];

    _ipv4Field = [UITextField new];
    _ipv4Field.translatesAutoresizingMaskIntoConstraints = NO;
    _ipv4Field.textColor = [UIColor colorWithWhite:1.0 alpha:0.82];
    _ipv4Field.font = [UIFont monospacedSystemFontOfSize:14.0 weight:UIFontWeightRegular];
    _ipv4Field.userInteractionEnabled = NO;
    _ipv4Field.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:@"IPV4"
        attributes:@{NSForegroundColorAttributeName:[UIColor colorWithWhite:1.0 alpha:0.28]}];
    [ipContainer addSubview:_ipv4Field];
    [NSLayoutConstraint activateConstraints:@[
        [_ipv4Field.leadingAnchor constraintEqualToAnchor:ipContainer.leadingAnchor constant:18.0],
        [_ipv4Field.trailingAnchor constraintEqualToAnchor:ipContainer.trailingAnchor constant:-12.0],
        [_ipv4Field.topAnchor constraintEqualToAnchor:ipContainer.topAnchor],
        [_ipv4Field.bottomAnchor constraintEqualToAnchor:ipContainer.bottomAnchor]
    ]];

    _detectButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_detectButton setTitle:@"Detectar" forState:UIControlStateNormal];
    [_detectButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    _detectButton.titleLabel.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightSemibold];
    _detectButton.backgroundColor = [UIColor colorWithWhite:0.065 alpha:1.0];
    _detectButton.layer.cornerRadius = 17.0;
    _detectButton.layer.borderWidth = 1.0;
    _detectButton.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.13].CGColor;
    [_detectButton.widthAnchor constraintEqualToConstant:126.0].active = YES;
    [_detectButton addTarget:self action:@selector(detectTapped) forControlEvents:UIControlEventTouchUpInside];
    [ipRow addArrangedSubview:_detectButton];

    _loginButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_loginButton setTitle:@"Entrar" forState:UIControlStateNormal];
    [_loginButton setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    _loginButton.titleLabel.font = [UIFont systemFontOfSize:18.0 weight:UIFontWeightBold];
    _loginButton.backgroundColor = UIColor.whiteColor;
    _loginButton.layer.cornerRadius = 17.0;
    [_loginButton.heightAnchor constraintEqualToConstant:68.0].active = YES;
    [_loginButton addTarget:self action:@selector(loginTapped) forControlEvents:UIControlEventTouchUpInside];
    [stack addArrangedSubview:_loginButton];

    _statusLabel = [UILabel new];
    _statusLabel.textColor = [UIColor colorWithWhite:1.0 alpha:0.58];
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.numberOfLines = 2;
    _statusLabel.font = [UIFont systemFontOfSize:14.0 weight:UIFontWeightMedium];
    [_statusLabel.heightAnchor constraintGreaterThanOrEqualToConstant:18.0].active = YES;
    [stack addArrangedSubview:_statusLabel];

    UILayoutGuide *safe = _rootVC.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:28.0],
        [stack.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-28.0],
        [stack.topAnchor constraintEqualToAnchor:safe.topAnchor constant:102.0]
    ]];

    _authWindow.hidden = NO;
    [_authWindow makeKeyAndVisible];
    [self detectIPv4Silently];
}
- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [self loginTapped];
    return YES;
}

- (void)setBusy:(BOOL)busy text:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_loginButton.enabled = !busy;
        self->_keyField.enabled = !busy;
        self->_detectButton.enabled = !busy;
        self->_loginButton.alpha = busy ? 0.58 : 1.0;
        self->_detectButton.alpha = busy ? 0.58 : 1.0;
        self->_statusLabel.text = text ?: @"";
    });
}

- (void)restoreSessionOrShowLogin {
    NSString *savedKey = EAKeychainRead(kEAKeyAccount);
    NSString *savedToken = EAKeychainRead(kEATokenAccount);
    if (savedKey.length) _keyField.text = savedKey;
    if (savedKey.length && savedToken.length) {
        [self setBusy:YES text:@"Validando sessão..."];
        [self requestMeWithKey:savedKey token:savedToken allowReauth:YES];
    } else {
        [self lockAndShow:@""];
    }
}

- (void)detectIPv4WithCompletion:(void (^)(NSString *ipv4, NSError *error))completion {
    NSURL *url = [NSURL URLWithString:@"https://api.ipify.org?format=json"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"GET";
    request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    request.timeoutInterval = 10.0;

    [[_session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSString *ip = nil;
        if (!error && data.length) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            ip = EANonEmptyString(json[@"ip"]);
            if (!EAIsValidIPv4(ip)) ip = nil;
        }
        if (!ip && !error) {
            error = [NSError errorWithDomain:@"RemoteAuth" code:1001 userInfo:@{NSLocalizedDescriptionKey:@"IPv4 não detectado"}];
        }
        if (completion) completion(ip, error);
    }] resume];
}

- (void)detectIPv4Silently {
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_ipv4Field.text = @"Detectando...";
    });
    [self detectIPv4WithCompletion:^(NSString *ipv4, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_ipv4Field.text = ipv4.length ? ipv4 : @"Não detectado";
        });
    }];
}

- (void)detectTapped {
    if (_requestInFlight) return;
    _detectButton.enabled = NO;
    _ipv4Field.text = @"Detectando...";
    [self detectIPv4WithCompletion:^(NSString *ipv4, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_detectButton.enabled = YES;
            self->_ipv4Field.text = ipv4.length ? ipv4 : @"Não detectado";
            self->_statusLabel.text = error ? @"Não foi possível detectar o IPv4." : @"";
        });
    }];
}

- (void)loginTapped {
    NSString *key = [_keyField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].uppercaseString;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^REMOTE-IOS-[A-Z0-9]{6}$" options:0 error:nil];
    NSRange fullRange = NSMakeRange(0, key.length);
    if (!regex || [regex firstMatchInString:key options:0 range:fullRange] == nil) {
        _statusLabel.text = @"Digite uma key válida.";
        return;
    }
    [_keyField resignFirstResponder];
    [self validateKey:key];
}

- (NSMutableURLRequest *)requestForPath:(NSString *)path method:(NSString *)method token:(NSString *)token {
    NSURL *url = [NSURL URLWithString:[kEAAPIBaseURL stringByAppendingString:path]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = method;
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"REMOTE-iOS/2" forHTTPHeaderField:@"X-Client"];
    if (token.length) [request setValue:[@"Bearer " stringByAppendingString:token] forHTTPHeaderField:@"Authorization"];
    return request;
}

- (void)validateKey:(NSString *)key {
    if (_requestInFlight) return;

    NSString *currentIP = [_ipv4Field.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!EAIsValidIPv4(currentIP)) {
        [self setBusy:YES text:@"Detectando IPv4..."];
        [self detectIPv4WithCompletion:^(NSString *ipv4, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self->_ipv4Field.text = ipv4.length ? ipv4 : @"Não detectado";
            });
            if (error || !ipv4.length) {
                [self setBusy:NO text:@"Não foi possível detectar o IPv4."];
                return;
            }
            [self validateKey:key];
        }];
        return;
    }

    _requestInFlight = YES;
    [self setBusy:YES text:@"Autenticando..."];

    NSMutableURLRequest *req = [self requestForPath:@"/api/auth/activate" method:@"POST" token:nil];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{ @"key": key, @"ipv4": currentIP } options:0 error:nil];

    __weak typeof(self) weakSelf = self;
    [[_session dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        self->_requestInFlight = NO;
        NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        NSInteger status = [(NSHTTPURLResponse *)response statusCode];
        if (error || status < 200 || status >= 300 || ![json isKindOfClass:NSDictionary.class] || !EABool(json[@"ok"])) {
            NSString *code = EAErrorCode(json ?: @{});
            [self lockAndShow:error ? @"Servidor indisponível." : EAHumanError(code)];
            return;
        }

        NSString *token = EAFirstString(json, @[@"token", @"session_token", @"access_token"]);
        NSString *serverKey = EAFirstString(json, @[@"key"]); if (!serverKey) serverKey = key;
        NSString *ipv4 = EAFirstString(json, @[@"ipv4", @"bound_ipv4"]); if (!ipv4) ipv4 = currentIP;
        NSString *expiry = EAFirstString(json, @[@"session_expires_at", @"token_expires_at", @"expires_at"]);

        if (!token.length || !serverKey.length || !ipv4.length) {
            [self lockAndShow:@"Resposta de autenticação incompleta."];
            return;
        }
        [self acceptSessionKey:serverKey ipv4:ipv4 token:token expiresAt:expiry];
    }] resume];
}
- (void)requestMeWithKey:(NSString *)key token:(NSString *)token allowReauth:(BOOL)allowReauth {
    if (_requestInFlight) return;
    _requestInFlight = YES;
    NSMutableURLRequest *req = [self requestForPath:@"/api/auth/me" method:@"GET" token:token];
    __weak typeof(self) weakSelf = self;
    [[_session dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        self->_requestInFlight = NO;
        NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        NSInteger status = [(NSHTTPURLResponse *)response statusCode];
        BOOL authenticated = EABool(json[@"authenticated"]) || (EABool(json[@"ok"]) && ![EAErrorCode(json ?: @{}) length]);
        if (!error && status >= 200 && status < 300 && authenticated) {
            NSString *serverKey = EAFirstString(json, @[@"key"]); if (!serverKey) serverKey = key;
            NSString *ipv4 = EAFirstString(json, @[@"ipv4", @"bound_ipv4"]);
            NSString *expiry = EAFirstString(json, @[@"session_expires_at", @"token_expires_at", @"expires_at"]);
            if (ipv4.length) {
                [self acceptSessionKey:serverKey ipv4:ipv4 token:token expiresAt:expiry];
                return;
            }
        }
        NSString *code = EAErrorCode(json ?: @{});
        BOOL mayRefresh = allowReauth && ([code isEqualToString:@"token_expired"] || [code isEqualToString:@"invalid_token"] || [code isEqualToString:@"unauthorized"] || status == 401);
        if (mayRefresh && key.length) {
            EAKeychainDelete(kEATokenAccount);
            [self validateKey:key];
            return;
        }
        [self lockAndShow:error ? @"Servidor indisponível." : EAHumanError(code)];
    }] resume];
}

- (void)checkSession {
    if (!self.unlocked || _requestInFlight) return;
    NSString *token = self.securitySessionToken;
    NSString *key = self.validatedKey;
    NSString *boundIP = self.validatedIPv4;
    if (!token.length || !key.length || !boundIP.length) {
        [self lockAndShow:@"Sessão inválida."];
        return;
    }

    [self detectIPv4WithCompletion:^(NSString *currentIP, NSError *ipError) {
        if (ipError || !currentIP.length) {
            double age = NSProcessInfo.processInfo.systemUptime - self.lastServerSuccess;
            if (age > kEANetworkGrace) [self lockAndShow:@"Conexão com o servidor perdida."];
            return;
        }

        dispatch_async(dispatch_get_main_queue(), ^{ self->_ipv4Field.text = currentIP; });

        if (![currentIP isEqualToString:boundIP]) {
            [self lockAndShow:@"IPv4 diferente do vinculado à key."];
            return;
        }

        if (self->_requestInFlight) return;
        self->_requestInFlight = YES;
        NSMutableURLRequest *req = [self requestForPath:@"/api/auth/me" method:@"GET" token:token];
        __weak typeof(self) weakSelf = self;
        [[self->_session dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            self->_requestInFlight = NO;
            NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
            NSInteger status = [(NSHTTPURLResponse *)response statusCode];
            BOOL valid = !error && status >= 200 && status < 300 && EABool(json[@"ok"]);
            if (valid) {
                NSString *serverIP = EAFirstString(json, @[@"ipv4", @"bound_ipv4"]);
                if (serverIP.length && ![serverIP isEqualToString:currentIP]) {
                    [self lockAndShow:@"IPv4 diferente do vinculado à key."];
                    return;
                }
                @synchronized (self) {
                    self->_lastServerSuccess = NSProcessInfo.processInfo.systemUptime;
                    self->_heartbeatNonce = [NSUUID UUID].UUIDString;
                }
                return;
            }

            if (error) {
                double age = NSProcessInfo.processInfo.systemUptime - self.lastServerSuccess;
                if (age <= kEANetworkGrace) return;
                [self lockAndShow:@"Conexão com o servidor perdida."];
                return;
            }

            NSString *code = EAErrorCode(json ?: @{});
            if ([code isEqualToString:@"token_expired"] || [code isEqualToString:@"invalid_token"] || [code isEqualToString:@"unauthorized"] || status == 401) {
                EAKeychainDelete(kEATokenAccount);
                [self validateKey:key];
                return;
            }
            [self lockAndShow:EAHumanError(code)];
        }] resume];
    }];
}
- (void)acceptSessionKey:(NSString *)key ipv4:(NSString *)ipv4 token:(NSString *)token expiresAt:(NSString *)expiresAt {
    EAKeychainWrite(kEAKeyAccount, key);
    EAKeychainWrite(kEATokenAccount, token);
    @synchronized (self) {
        _validatedKey = [key copy];
        _validatedIPv4 = [ipv4 copy];
        _securitySessionToken = [token copy];
        _securitySessionExpiresAt = [expiresAt copy] ?: @"";
        _heartbeatNonce = [NSUUID UUID].UUIDString;
        _lastServerSuccess = NSProcessInfo.processInfo.systemUptime;
        _unlocked = YES;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_statusLabel.text = @"";
        self->_authWindow.hidden = YES;
        [self->_checkTimer invalidate];
        self->_checkTimer = [NSTimer scheduledTimerWithTimeInterval:kEACheckInterval
                                                             target:self
                                                           selector:@selector(checkTimerFired:)
                                                           userInfo:nil
                                                            repeats:YES];
        [[NSNotificationCenter defaultCenter] postNotificationName:@"RemoteAuthorizationRefreshed" object:nil];
    });
}

- (void)checkTimerFired:(NSTimer *)timer { [self checkSession]; }

- (void)lockAndShow:(NSString *)message {
    @synchronized (self) {
        _unlocked = NO;
        _validatedKey = nil;
        _validatedIPv4 = nil;
        _securitySessionToken = nil;
        _securitySessionExpiresAt = @"";
        _heartbeatNonce = [NSUUID UUID].UUIDString;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        [self ensureOverlay];
        self->_authWindow.hidden = NO;
        [self->_authWindow makeKeyAndVisible];
        self->_loginButton.enabled = YES;
        self->_keyField.enabled = YES;
        self->_detectButton.enabled = YES;
        self->_loginButton.alpha = 1.0;
        self->_detectButton.alpha = 1.0;
        self->_statusLabel.text = message ?: @"";
        [self->_checkTimer invalidate];
        self->_checkTimer = nil;
        [[NSNotificationCenter defaultCenter] postNotificationName:@"RemoteAuthorizationRevoked" object:nil];
    });
}


- (void)logout {
    EAKeychainDelete(kEATokenAccount);
    @synchronized (self) {
        _unlocked = NO;
        _validatedKey = nil;
        _validatedIPv4 = nil;
        _securitySessionToken = nil;
        _securitySessionExpiresAt = @"";
        _heartbeatNonce = [NSUUID UUID].UUIDString;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        [self ensureOverlay];
        self->_authWindow.hidden = NO;
        [self->_authWindow makeKeyAndVisible];
        self->_statusLabel.text = @"";
        [self->_checkTimer invalidate];
        self->_checkTimer = nil;
        [self detectIPv4Silently];
        [[NSNotificationCenter defaultCenter] postNotificationName:@"RemoteAuthorizationRevoked" object:nil];
    });
}
@end


// Compatibility bridge for the older EXTERNAL loader. If existing app code
// asks for ExternalAuthManager.shared, it receives the REMOTE manager instance.
@interface ExternalAuthManager : NSObject
+ (id)shared;
@end

@implementation ExternalAuthManager
+ (id)shared {
    return [RemoteAuthManager shared];
}
@end

// Same behavior as the EXTERNAL dylib: loading the dylib starts the auth overlay.
__attribute__((constructor))
static void RemoteAuthInit(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.08 * NSEC_PER_SEC)),
            dispatch_get_main_queue(),
            ^{
                [[RemoteAuthManager shared] start];
            }
        );
    });
}

// Keep a concrete marker visible in the Mach-O for build validation.
__attribute__((used, visibility("default")))
const char *REMOTE_AUTH_BUILD_MARKER(void) {
    return "REMOTE-AUTH-CURRENT-BACKEND-V4";
}
