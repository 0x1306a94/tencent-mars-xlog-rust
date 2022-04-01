//
//  XlogDecoder.m
//  ios_xlog_sample
//
//  Created by king on 2022/1/15.
//

#import "XlogDecoder.h"

#import <stdio.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <zlib.h>

static const int XLOG_MARGIC_CRYPT_START = 0x01;
static const int XLOG_MARGIC_COMPRESS_CRYPT_START = 0x02;
static const int XLOG_MARGIC_NO_COMPRESS_START = 0x03;
static const int XLOG_MARGIC_NO_COMPRESS_START1 = 0x06;
static const int XLOG_MARGIC_NO_COMPRESS_NO_CRYPT_START = 0x08;
static const int XLOG_MARGIC_COMPRESS_START = 0x04;
static const int XLOG_MARGIC_COMPRESS_START1 = 0x05;
static const int XLOG_MARGIC_COMPRESS_START2 = 0x07;
static const int XLOG_MARGIC_COMPRESS_NO_CRYPT_START = 0x09;

static const int XLOG_MARGIC_SYNC_ZLIB_START = 0x06;
static const int XLOG_MARGIC_SYNC_NO_CRYPT_ZLIB_START = 0x08;
static const int XLOG_MARGIC_SYNC_ZSTD_START = 0x0A;
static const int XLOG_MARGIC_SYNC_NO_CRYPT_ZSTD_START = 0x0B;
static const int XLOG_MARGIC_ASYNC_ZSTD_START = 0x0C;
static const int XLOG_MARGIC_ASYNC_NO_CRYPT_ZSTD_START = 0x0D;

static const int XLOG_MARGIC_END = 0x00;

typedef const struct uECC_Curve_t *uECC_Curve;

extern uECC_Curve uECC_secp256k1(void);
extern int uECC_shared_secret(const uint8_t *public_key,
                              const uint8_t *private_key,
                              uint8_t *secret,
                              uECC_Curve curve);

typedef struct ZSTD_DCtx_s ZSTD_DCtx;
extern ZSTD_DCtx *ZSTD_createDCtx(void);
extern size_t ZSTD_freeDCtx(ZSTD_DCtx *dctx);

typedef struct ZSTD_inBuffer_s {
    const void *src; /**< start of input buffer */
    size_t size;     /**< size of input buffer */
    size_t pos;      /**< position where reading stopped. Will be updated. Necessarily 0 <= pos <= size */
} ZSTD_inBuffer;

typedef struct ZSTD_outBuffer_s {
    void *dst;   /**< start of output buffer */
    size_t size; /**< size of output buffer */
    size_t pos;  /**< position where writing stopped. Will be updated. Necessarily 0 <= pos <= size */
} ZSTD_outBuffer;

typedef ZSTD_DCtx ZSTD_DStream;
extern size_t ZSTD_decompressStream(ZSTD_DStream *zds, ZSTD_outBuffer *output, ZSTD_inBuffer *input);

@interface XlogDecoderInputBuffer : NSObject
@property (nonatomic, assign, readonly) size_t pos;
@property (nonatomic, assign, readonly) size_t len;
- (instancetype)initWithPtr:(const char *)ptr len:(size_t)len;
@end

@implementation XlogDecoderInputBuffer {
    const char *_ptr;
}

- (instancetype)initWithPtr:(const char *)m_ptr len:(size_t)len {
    if (self == [super init]) {
        _ptr = m_ptr;
        _len = len;
        _pos = 0;
    }
    return self;
}

- (const char *)allBytes {
    return &_ptr[0];
}

- (const char *)bytes {
    return &_ptr[_pos];
}

- (void)seek:(size_t)pos {
    _pos = pos;
}

- (const char *)readAt:(size_t)pos {
    return &_ptr[pos];
}

- (void)readAt:(size_t)pos len:(size_t)len dst:(char **)dst {
    memcpy(*dst, &_ptr[pos], len);
}
@end

@interface XlogDecoder ()
@property (nonatomic, assign) uint16_t lastSeq;
@property (nonatomic, strong) XlogDecoderInputBuffer *inputBuffer;
@property (nonatomic, strong) NSFileHandle *outFileHandle;
@property (nonatomic, copy) NSString *privateKey;
@end

@implementation XlogDecoder
const int XLOG_TEA_BLOCK_LEN = 8;

bool XLOG_Hex2Buffer(const char *str, size_t len, unsigned char *buffer) {
    if (NULL == str || len == 0 || len % 2 != 0) {
        return -1;
    }

    char tmp[3] = {0};
    size_t i;
    for (i = 0; i < len - 1; i += 2) {
        size_t j;
        for (j = 0; j < 2; ++j) {
            tmp[j] = str[i + j];
            if (!(('0' <= tmp[j] && tmp[j] <= '9') ||
                  ('a' <= tmp[j] && tmp[j] <= 'f') ||
                  ('A' <= tmp[j] && tmp[j] <= 'F'))) {
                return false;
            }
        }

        buffer[i / 2] = (unsigned char)strtol(tmp, NULL, 16);
    }
    return true;
}

void XLOG_bytes2hex(unsigned char *src, char *dst, int len) {
    static char HexLookUp[] = "0123456789abcdef";
    while (len--) {
        *dst++ = HexLookUp[*src >> 4];
        *dst++ = HexLookUp[*src & 0x0F];
        src++;
    }
    *dst = 0;
}

void XLOG_teaDecrypt(uint32_t *v, uint32_t *k) {
    uint32_t v0 = v[0], v1 = v[1], sum, i;
    const static uint32_t delta = 0x9e3779b9;
    const static uint32_t totalSum = 0x9e3779b9 << 4;
    sum = totalSum;

    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 16; i++) {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}

bool XLOG_zstdDecompress(const char *compressedBytes, size_t compressedBytesSize, char **outBuffer, size_t *outBufferSize) {
    *outBuffer = NULL;
    *outBufferSize = 0;
    if (compressedBytesSize == 0) {
        return true;
    }

    size_t fullLength = compressedBytesSize;
    size_t halfLength = compressedBytesSize / 2;

    size_t uncompLength = fullLength;
    char *uncomp = (char *)calloc(sizeof(char), uncompLength);

    ZSTD_DCtx *const dctx = ZSTD_createDCtx();

    ZSTD_inBuffer input = {compressedBytes, compressedBytesSize, 0};
    ZSTD_outBuffer output = {NULL, compressedBytesSize, 0};
    bool done = false;

    while (!done) {
        if (output.pos >= uncompLength) {
            char *uncomp2 = (char *)calloc(sizeof(char), uncompLength + halfLength);
            memcpy(uncomp2, uncomp, uncompLength);
            uncompLength += halfLength;
            free(uncomp);
            uncomp = uncomp2;
        }

        output.size = uncompLength;
        output.dst = uncomp;
        ZSTD_decompressStream(dctx, &output, &input);

        if (input.pos == input.size) {
            done = true;
        }
    }

    ZSTD_freeDCtx(dctx);

    *outBuffer = uncomp;
    *outBufferSize = output.pos;
    return true;
}

bool XLOG_zlibDecompress(const char *compressedBytes, size_t compressedBytesSize, char **outBuffer, size_t *outBufferSize) {

    *outBuffer = NULL;
    *outBufferSize = 0;
    if (compressedBytesSize == 0) {
        return true;
    }

    size_t fullLength = compressedBytesSize;
    size_t halfLength = compressedBytesSize / 2;

    size_t uncompLength = fullLength;
    char *uncomp = (char *)calloc(sizeof(char), uncompLength);

    z_stream strm;
    strm.next_in = (Bytef *)compressedBytes;
    strm.avail_in = compressedBytesSize;
    strm.total_out = 0;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;

    bool done = false;

    if (inflateInit2(&strm, (-MAX_WBITS)) != Z_OK) {
        free(uncomp);
        return false;
    }

    while (!done) {
        // If our output buffer is too small
        if (strm.total_out >= uncompLength) {
            // Increase size of output buffer
            char *uncomp2 = (char *)calloc(sizeof(char), uncompLength + halfLength);
            memcpy(uncomp2, uncomp, uncompLength);
            uncompLength += halfLength;
            free(uncomp);
            uncomp = uncomp2;
        }

        strm.next_out = (Bytef *)(uncomp + strm.total_out);
        strm.avail_out = uncompLength - strm.total_out;

        // Inflate another chunk.
        int err = inflate(&strm, Z_SYNC_FLUSH);
        if (err == Z_STREAM_END) {
            done = true;
        } else if (err != Z_OK) {
            break;
        }
    }

    if (inflateEnd(&strm) != Z_OK) {
        free(uncomp);
        return false;
    }

    *outBuffer = uncomp;
    *outBufferSize = strm.total_out;
    return true;
}

- (BOOL)isGoodLogBuffer:(const char *)m_ptr bufferLen:(size_t)buf_len offset:(size_t)offset count:(int)count {

    if (offset > buf_len) {
        return NO;
    }

    if (offset == buf_len) {
        return YES;
    }

    size_t crypt_key_len = 0;
    int magic_value = m_ptr[offset];
    if (XLOG_MARGIC_NO_COMPRESS_START == magic_value || XLOG_MARGIC_COMPRESS_START == magic_value || XLOG_MARGIC_COMPRESS_START1 == magic_value) {
        crypt_key_len = 4;
    } else if (XLOG_MARGIC_COMPRESS_START2 == magic_value || XLOG_MARGIC_NO_COMPRESS_START1 == magic_value || XLOG_MARGIC_NO_COMPRESS_NO_CRYPT_START == magic_value || XLOG_MARGIC_COMPRESS_NO_CRYPT_START == magic_value || XLOG_MARGIC_SYNC_ZSTD_START == magic_value || XLOG_MARGIC_SYNC_NO_CRYPT_ZSTD_START == magic_value || XLOG_MARGIC_ASYNC_ZSTD_START == magic_value || XLOG_MARGIC_ASYNC_NO_CRYPT_ZSTD_START == magic_value) {
        crypt_key_len = 64;
    } else {
        return NO;
    }

    size_t header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;
    if ((offset + header_len + 1 + 1) > buf_len) {
        return NO;
    }

    uint32_t length;
    size_t start = offset + header_len - crypt_key_len - 4;
    memcpy(&length, &m_ptr[start], 4);
    if ((offset + header_len + length + 1) > buf_len) {
        return NO;
    }
    magic_value = m_ptr[offset + header_len + length];
    if (XLOG_MARGIC_END != magic_value) {
        return NO;
    }

    if (count >= 1) {
        return YES;
    }
    return [self isGoodLogBuffer:m_ptr bufferLen:buf_len offset:offset + header_len + length + 1 count:count - 1];
}

- (size_t)getLogStartPos:(const char *)m_ptr bufferLen:(size_t)bufferLen count:(int)count {
    size_t offset = 0;
    while (1) {
        if (offset >= bufferLen) {
            break;
        }
        int magic_value = m_ptr[offset];
        if (XLOG_MARGIC_NO_COMPRESS_START == magic_value || XLOG_MARGIC_NO_COMPRESS_START1 == magic_value || XLOG_MARGIC_COMPRESS_START == magic_value || XLOG_MARGIC_COMPRESS_START1 == magic_value || XLOG_MARGIC_COMPRESS_START2 == magic_value || XLOG_MARGIC_COMPRESS_NO_CRYPT_START == magic_value || XLOG_MARGIC_NO_COMPRESS_NO_CRYPT_START == magic_value || XLOG_MARGIC_SYNC_ZSTD_START == magic_value || XLOG_MARGIC_SYNC_NO_CRYPT_ZSTD_START == magic_value || XLOG_MARGIC_ASYNC_ZSTD_START == magic_value || XLOG_MARGIC_ASYNC_NO_CRYPT_ZSTD_START == magic_value) {
            if ([self isGoodLogBuffer:m_ptr bufferLen:bufferLen offset:offset count:count]) {
                return offset;
            }
        }
        offset += 1;
    }
    return -1;
}

- (size_t)decode:(XlogDecoderInputBuffer *)inputBuffer offset:(size_t)offset {
    size_t in_buf_len = inputBuffer.len;

    if (offset >= in_buf_len) {
        return -1;
    }

    const char *in_buf = [inputBuffer bytes];

    if (![self isGoodLogBuffer:in_buf bufferLen:in_buf_len offset:offset count:1]) {
        size_t buf_len = in_buf_len - offset;
        const char *bytes = [inputBuffer readAt:offset];
        size_t fixpos = [self getLogStartPos:bytes bufferLen:buf_len count:1];
        if (-1 == fixpos) {
            return -1;
        } else {
            offset += fixpos;
        }
    }

    size_t crypt_key_len = 0;
    int magic_value = [inputBuffer bytes][0];
    if (XLOG_MARGIC_NO_COMPRESS_START == magic_value || XLOG_MARGIC_COMPRESS_START == magic_value || XLOG_MARGIC_COMPRESS_START1 == magic_value) {
        crypt_key_len = 4;
    } else if (XLOG_MARGIC_COMPRESS_START2 == magic_value || XLOG_MARGIC_NO_COMPRESS_START1 == magic_value || XLOG_MARGIC_NO_COMPRESS_NO_CRYPT_START == magic_value || XLOG_MARGIC_COMPRESS_NO_CRYPT_START == magic_value || XLOG_MARGIC_SYNC_ZSTD_START == magic_value || XLOG_MARGIC_SYNC_NO_CRYPT_ZSTD_START == magic_value || XLOG_MARGIC_ASYNC_ZSTD_START == magic_value || XLOG_MARGIC_ASYNC_NO_CRYPT_ZSTD_START == magic_value) {
        crypt_key_len = 64;
    } else {
        return -1;
    }

    size_t header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;
    size_t start = offset + header_len - crypt_key_len - 4;
    uint32_t length;
    memcpy(&length, [inputBuffer readAt:start], 4);

    size_t pos = offset + header_len - crypt_key_len - 4 - 2 - 2;
    uint16_t seq;
    memcpy(&seq, [inputBuffer readAt:pos], 2);
    if (seq != 0 && seq != 1 && self.lastSeq != 0 && seq != (self.lastSeq + 1)) {
        ///
    }
    if (seq != 0) {
        self.lastSeq = seq;
    }

    pos = offset + header_len;
    size_t content_buf_len = length;
    uint8_t *content_buf = malloc(sizeof(uint8_t) * content_buf_len);
    if (content_buf == NULL) {
        NSLog(@"Memory error");
        return -1;
    }
    memcpy(content_buf, [inputBuffer readAt:pos], content_buf_len);

#define SAFE_FREE(ptr) \
    if (ptr != NULL) { \
        free(ptr);     \
        ptr = NULL;    \
    }

    magic_value = [inputBuffer readAt:offset][0];
    BOOL isCrypt = self.privateKey.length > 0;
    if (isCrypt && (XLOG_MARGIC_SYNC_ZLIB_START == magic_value || XLOG_MARGIC_SYNC_NO_CRYPT_ZLIB_START == magic_value || XLOG_MARGIC_SYNC_ZSTD_START == magic_value || XLOG_MARGIC_SYNC_NO_CRYPT_ZSTD_START == magic_value)) {
        NSData *data = [NSData dataWithBytes:content_buf length:content_buf_len];
        [self.outFileHandle writeData:data];
        SAFE_FREE(content_buf);

    } else if (!isCrypt && (XLOG_MARGIC_NO_COMPRESS_START1 == magic_value || XLOG_MARGIC_COMPRESS_START2 == magic_value || XLOG_MARGIC_SYNC_ZSTD_START == magic_value || XLOG_MARGIC_ASYNC_ZSTD_START == magic_value)) {
        // pass
        NSData *data = [@"use wrong decode script\n" dataUsingEncoding:NSUTF8StringEncoding];
        [self.outFileHandle writeData:data];
    } else if (isCrypt && (XLOG_MARGIC_COMPRESS_START2 == magic_value || XLOG_MARGIC_ASYNC_ZSTD_START == magic_value)) {
        // 解密

        uint8_t *client_pub_key = malloc(sizeof(uint8_t) * crypt_key_len);
        if (client_pub_key == NULL) {
            NSLog(@"Memory error");
            return -1;
        }
        size_t pos = offset + header_len - crypt_key_len;
        size_t len = crypt_key_len;

        [inputBuffer readAt:pos len:len dst:(char **)&client_pub_key];
        printf("\n");
        for (int i = 0; i < crypt_key_len; i++) {
            printf("%02x", client_pub_key[i]);
        }
        printf("\n");

        unsigned char svrPriKey[32] = {0};
        if (!XLOG_Hex2Buffer(self.privateKey.UTF8String, 64, svrPriKey)) {
            fputs("Get PRIV KEY error", stderr);
            return -1;
        }

        unsigned char ecdhKey[32] = {0};
        if (0 == uECC_shared_secret(client_pub_key, svrPriKey, ecdhKey, uECC_secp256k1())) {
            fputs("Get ECDH key error", stderr);
            SAFE_FREE(client_pub_key);
            return -1;
        }
        SAFE_FREE(client_pub_key);

        uint32_t teaKey[4];
        memcpy(teaKey, ecdhKey, sizeof(teaKey));
        uint32_t tmp[2] = {0};
        size_t cnt = length / XLOG_TEA_BLOCK_LEN;

        size_t i;
        for (i = 0; i < cnt; i++) {
            memcpy(tmp, content_buf + i * XLOG_TEA_BLOCK_LEN, XLOG_TEA_BLOCK_LEN);
            XLOG_teaDecrypt(tmp, teaKey);
            memcpy(content_buf + i * XLOG_TEA_BLOCK_LEN, tmp, XLOG_TEA_BLOCK_LEN);
        }
        char *decompBuffer;
        size_t decompBufferSize;

        if (XLOG_MARGIC_COMPRESS_START2 == magic_value) {
            // zlib
            if (!XLOG_zlibDecompress((const char *)content_buf, content_buf_len, &decompBuffer, &decompBufferSize)) {
                SAFE_FREE(content_buf);
                return -1;
            }
        } else {
            // zstd
            if (!XLOG_zstdDecompress((const char *)content_buf, content_buf_len, &decompBuffer, &decompBufferSize)) {
                SAFE_FREE(content_buf);
                return -1;
            }
        }

        NSData *data = [NSData dataWithBytes:decompBuffer length:decompBufferSize];
        [self.outFileHandle writeData:data];
        SAFE_FREE(content_buf);
        SAFE_FREE(decompBuffer);
    } else if (XLOG_MARGIC_ASYNC_NO_CRYPT_ZSTD_START == magic_value) {
        // zstd
        char *decompBuffer;
        size_t decompBufferSize;
        if (!XLOG_zstdDecompress((const char *)content_buf, content_buf_len, &decompBuffer, &decompBufferSize)) {
            SAFE_FREE(content_buf);
            return -1;
        }
        NSData *data = [NSData dataWithBytes:decompBuffer length:decompBufferSize];
        [self.outFileHandle writeData:data];
        SAFE_FREE(content_buf);
        SAFE_FREE(decompBuffer);
    } else if (XLOG_MARGIC_COMPRESS_START == magic_value || XLOG_MARGIC_COMPRESS_NO_CRYPT_START == magic_value) {
        // zlib
        char *decompBuffer;
        size_t decompBufferSize;
        if (!XLOG_zlibDecompress((const char *)content_buf, content_buf_len, &decompBuffer, &decompBufferSize)) {
            SAFE_FREE(content_buf);
            return -1;
        }
        NSData *data = [NSData dataWithBytes:decompBuffer length:decompBufferSize];
        [self.outFileHandle writeData:data];
        SAFE_FREE(content_buf);
        SAFE_FREE(decompBuffer);
    } else if (XLOG_MARGIC_COMPRESS_START1 == magic_value) {
        // https://github.com/0x1306a94/tencent-mars-xlog-rust/blob/master/src/decode.rs#L397
        if (content_buf_len > 0) {
            // zlib
            size_t pos = 0;
            NSMutableData *data = [NSMutableData dataWithCapacity:1024];
            while (pos < content_buf_len) {
                uint16_t single_log_len = 0;
                memcpy(&single_log_len, &content_buf[pos], 2);
                pos += 2;
                size_t len = single_log_len + 2;
                [data appendBytes:&content_buf[pos] length:len];
                pos = pos + len;
            }
            char *decompBuffer;
            size_t decompBufferSize;
            if (!XLOG_zlibDecompress((const char *)[data bytes], data.length, &decompBuffer, &decompBufferSize)) {
                SAFE_FREE(content_buf);
                return -1;
            }
            SAFE_FREE(content_buf);
            SAFE_FREE(decompBuffer);
        }
    }

    return offset + header_len + length + 1;
}

- (BOOL)decodeAtPath:(NSString *)path privateKey:(NSString *)privateKey outPath:(NSString *)outPath {
    FILE *file = NULL;
    size_t bufferSize = 0;
    char *m_ptr = NULL;
    size_t startPos = 0;
    NSFileHandle *outFileHandle = nil;
    BOOL succeed = YES;
    self.lastSeq = 0;

    file = fopen(path.UTF8String, "rb");
    if (file == NULL) {
        succeed = NO;
        goto faild;
    }

    fseek(file, 0, SEEK_END);
    bufferSize = (size_t)ftell(file);
    rewind(file);

    m_ptr = mmap(NULL, bufferSize, PROT_READ, MAP_SHARED, fileno(file), 0);
    if (m_ptr == NULL) {
        succeed = NO;
        goto faild;
    }

    startPos = [self getLogStartPos:m_ptr bufferLen:bufferSize count:2];
    if (startPos == -1) {
        succeed = NO;
        goto faild;
    }

    if ([[NSFileManager defaultManager] fileExistsAtPath:outPath]) {
        [[NSFileManager defaultManager] removeItemAtPath:outPath error:nil];
    }

    if (![[NSFileManager defaultManager] createFileAtPath:outPath contents:nil attributes:nil]) {
        succeed = NO;
        goto faild;
    }
    outFileHandle = [NSFileHandle fileHandleForWritingAtPath:outPath];
    if (outFileHandle == nil) {
        succeed = NO;
        goto faild;
    }

    self.inputBuffer = [[XlogDecoderInputBuffer alloc] initWithPtr:m_ptr len:bufferSize];
    self.outFileHandle = outFileHandle;
    self.privateKey = privateKey;

    while (1) {
        startPos = [self decode:self.inputBuffer offset:startPos];
        if (startPos == -1) {
            break;
        }
    }
faild:
    if (m_ptr != NULL) {
        munmap(m_ptr, bufferSize);
        m_ptr = NULL;
    }

    if (file != NULL) {
        fclose(file);
        file = NULL;
    }

    if (outFileHandle) {
        [outFileHandle closeFile];
    }

    return succeed;
}
@end

