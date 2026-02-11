#include<stdio.h>
#include<stddef.h>
#include<string.h>
#include<stdint.h>

typedef struct {
	uint32_t state[16];
} Chacha20;

static inline uint32_t rotate32 (uint32_t x, int n) {
	return (x << n) | (x >> (32 - n));
}

static inline uint32_t load32_le (const uint8_t *p) {
	return	((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le (uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); 
}

static inline void quarter_round (uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
	*a += *b; *d ^= *a; *d = rotate32(*d, 16);
	*c += *d; *b ^= *c; *b = rotate32(*b, 12);
	*a += *b; *d ^= *a; *d = rotate32(*d, 8);
	*c += *d; *b ^= *c; *b = rotate32(*b, 7);
}

static void chacha20_block (const Chacha20 *ctx, uint8_t out[64]) {
	uint32_t x[16];
	memcpy(x, ctx->state, sizeof(x));
	
	for (int i = 0; i < 10; i++) {
		quarter_round(&x[0], &x[4], &x[ 8], &x[12]);
		quarter_round(&x[1], &x[5], &x[ 9], &x[13]);
		quarter_round(&x[2], &x[6], &x[10], &x[14]);
		quarter_round(&x[3], &x[7], &x[11], &x[15]);

		quarter_round(&x[0], &x[5], &x[10], &x[15]);
		quarter_round(&x[1], &x[6], &x[11], &x[12]);
		quarter_round(&x[2], &x[7], &x[ 8], &x[13]);
		quarter_round(&x[3], &x[4], &x[ 9], &x[14]);
	}

	for (int i = 0; i < 16; i++) {
		x[i] += ctx->state[i];
		store32_le(out + 4 * i, x[i]);
	}
}

void chacha20_init (Chacha20 *ctx, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
	
	ctx->state[0]  = 0x61707865;
	ctx->state[1]  = 0x3320646e;
	ctx->state[2]  = 0x79622d32;
	ctx->state[3]  = 0x6b206574;

	for (int i = 0; i < 8; i++) {
		ctx->state[4 + i] = load32_le(key + 4 * i);
	}

	ctx->state[12] = counter;
	ctx->state[13] = load32_le(nonce + 0);
	ctx->state[14] = load32_le(nonce + 4);
	ctx->state[15] = load32_le(nonce + 8);
}

void chacha20_xor (Chacha20 *ctx, uint8_t *data, size_t len) {
	uint8_t ks[64];

	while (len > 0) {
		chacha20_block(ctx, ks);

		size_t n = (len < 64) ? len : 64;
		for (size_t i = 0; i < n; i++) {
			data[i] ^= ks[i];
		}

		data += n; len  -= n; ctx->state[12] += 1;
	}
	memset(ks, 0, sizeof(ks));
}

int main (void) {
	uint8_t key[32] = {0};
	uint8_t nonce[12] = {0};
	uint8_t msg[] = "hello, this is the test for Chacha20";

	Chacha20 c;
	chacha20_init(&c, key, nonce, 1);
	chacha20_xor(&c, msg, sizeof(msg)-1);
	puts((char*)msg);

	Chacha20 d;
	chacha20_init(&d, key, nonce, 1);
	chacha20_xor(&d, msg, sizeof(msg)-1);
	puts((char*)msg);
	
	return 0;
}
