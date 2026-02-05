#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_BLOCK_SIZE 4000000u

typedef struct {
  const uint8_t *buf;
  size_t len;
  size_t off;
} reader_t;

static int set_err(char *err, size_t err_len, const char *msg) {
  if (err && err_len) {
    snprintf(err, err_len, "%s", msg);
  }
  return -1;
}

static int read_u32le(reader_t *r, uint32_t *out) {
  if (r->off + 4 > r->len) return -1;
  const uint8_t *p = r->buf + r->off;
  *out = ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  r->off += 4;
  return 0;
}

static int read_u64le(reader_t *r, uint64_t *out) {
  if (r->off + 8 > r->len) return -1;
  const uint8_t *p = r->buf + r->off;
  *out = ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
         ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
  r->off += 8;
  return 0;
}

static int read_bytes(reader_t *r, uint8_t *out, size_t n) {
  if (r->off + n > r->len) return -1;
  if (out) memcpy(out, r->buf + r->off, n);
  r->off += n;
  return 0;
}

static int read_varint(reader_t *r, uint64_t *val, size_t *len_out) {
  if (r->off >= r->len) return -1;
  uint8_t b0 = r->buf[r->off];
  if (b0 < 0xfd) {
    *val = b0;
    *len_out = 1;
    r->off += 1;
    return 0;
  }
  if (b0 == 0xfd) {
    if (r->off + 3 > r->len) return -1;
    uint16_t v = (uint16_t)r->buf[r->off + 1] | ((uint16_t)r->buf[r->off + 2] << 8);
    if (v < 0xfd) return -1;
    *val = v;
    *len_out = 3;
    r->off += 3;
    return 0;
  }
  if (b0 == 0xfe) {
    if (r->off + 5 > r->len) return -1;
    uint32_t v = ((uint32_t)r->buf[r->off + 1]) | ((uint32_t)r->buf[r->off + 2] << 8) |
                 ((uint32_t)r->buf[r->off + 3] << 16) | ((uint32_t)r->buf[r->off + 4] << 24);
    if (v <= 0xffffu) return -1;
    *val = v;
    *len_out = 5;
    r->off += 5;
    return 0;
  }
  if (r->off + 9 > r->len) return -1;
  uint64_t v = ((uint64_t)r->buf[r->off + 1]) | ((uint64_t)r->buf[r->off + 2] << 8) |
               ((uint64_t)r->buf[r->off + 3] << 16) | ((uint64_t)r->buf[r->off + 4] << 24) |
               ((uint64_t)r->buf[r->off + 5] << 32) | ((uint64_t)r->buf[r->off + 6] << 40) |
               ((uint64_t)r->buf[r->off + 7] << 48) | ((uint64_t)r->buf[r->off + 8] << 56);
  if (v <= 0xffffffffull) return -1;
  *val = v;
  *len_out = 9;
  r->off += 9;
  return 0;
}

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t data[64];
  size_t datalen;
} sha256_ctx;

static const uint32_t k256[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t data[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
           ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
  }
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];

  for (int i = 0; i < 64; i++) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + S1 + ch + k256[i] + w[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667u;
  ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u;
  ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu;
  ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu;
  ctx->state[7] = 0x5be0cd19u;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
  size_t i = ctx->datalen;

  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }

  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = (uint8_t)(ctx->bitlen);
  ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
  ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
  ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
  ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
  ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
  ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
  ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
  sha256_transform(ctx, ctx->data);

  for (i = 0; i < 4; ++i) {
    out[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xff);
    out[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xff);
    out[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xff);
    out[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xff);
    out[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xff);
    out[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xff);
    out[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xff);
    out[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xff);
  }
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, out);
}

static void sha256d(const uint8_t *data, size_t len, uint8_t out[32]) {
  uint8_t tmp[32];
  sha256(data, len, tmp);
  sha256(tmp, sizeof(tmp), out);
}

static void reverse32(const uint8_t in[32], uint8_t out[32]) {
  for (int i = 0; i < 32; i++) out[i] = in[31 - i];
}

static int cmp_be(const uint8_t a[32], const uint8_t b[32]) {
  for (int i = 0; i < 32; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

static int build_target_from_bits(uint32_t bits, uint8_t target_be[32]) {
  uint32_t exp = bits >> 24;
  uint32_t mant = bits & 0x00ffffffu;
  if (mant == 0) return -1;
  if (mant & 0x00800000u) return -1;
  if (exp < 3 || exp > 32) return -1;
  memset(target_be, 0, 32);
  int offset = (int)(32 - exp);
  target_be[offset]     = (uint8_t)((mant >> 16) & 0xff);
  target_be[offset + 1] = (uint8_t)((mant >> 8) & 0xff);
  target_be[offset + 2] = (uint8_t)(mant & 0xff);
  return 0;
}

static int compute_merkle_root(const uint8_t *txids, size_t count, uint8_t out[32]) {
  if (count == 0) return -1;
  if (count == 1) {
    memcpy(out, txids, 32);
    return 0;
  }
  size_t cur_count = count;
  uint8_t *cur = (uint8_t *)malloc(cur_count * 32);
  if (!cur) return -1;
  memcpy(cur, txids, cur_count * 32);

  while (cur_count > 1) {
    size_t next_count = (cur_count + 1) / 2;
    uint8_t *next = (uint8_t *)malloc(next_count * 32);
    if (!next) {
      free(cur);
      return -1;
    }
    for (size_t i = 0; i < cur_count; i += 2) {
      uint8_t buf[64];
      const uint8_t *left = cur + i * 32;
      const uint8_t *right = (i + 1 < cur_count) ? (cur + (i + 1) * 32) : left;
      memcpy(buf, left, 32);
      memcpy(buf + 32, right, 32);
      sha256d(buf, sizeof(buf), next + (i / 2) * 32);
    }
    free(cur);
    cur = next;
    cur_count = next_count;
  }
  memcpy(out, cur, 32);
  free(cur);
  return 0;
}

static unsigned leading_zero_bits_be(const uint8_t hash_be[32]) {
  unsigned count = 0;
  for (int i = 0; i < 32; i++) {
    uint8_t b = hash_be[i];
    if (b == 0) {
      count += 8;
      continue;
    }
    for (int bit = 7; bit >= 0; bit--) {
      if (b & (uint8_t)(1u << bit)) return count;
      count++;
    }
  }
  return count;
}

int validate_block_and_get_time(const uint8_t *buf, size_t len, uint32_t *out_time, unsigned min_leading_zero_bits, uint32_t *out_bits, uint8_t out_hash_be[32], char *err, size_t err_len) {
  if (!buf || !out_time) return set_err(err, err_len, "null input");
  if (len < 80) return set_err(err, err_len, "block too small");
  if (len > MAX_BLOCK_SIZE) return set_err(err, err_len, "block too large");
  if (min_leading_zero_bits > 256) return set_err(err, err_len, "min pow too large");

  reader_t r = { buf, len, 0 };

  uint32_t version = 0;
  uint8_t prev_hash[32];
  uint8_t merkle_le[32];
  uint32_t timestamp = 0;
  uint32_t bits = 0;
  uint32_t nonce = 0;
  (void)version;
  (void)nonce;

  if (read_u32le(&r, &version) || read_bytes(&r, prev_hash, 32) ||
      read_bytes(&r, merkle_le, 32) || read_u32le(&r, &timestamp) ||
      read_u32le(&r, &bits) || read_u32le(&r, &nonce)) {
    return set_err(err, err_len, "short header");
  }

  uint64_t tx_count = 0;
  size_t tx_count_len = 0;
  if (read_varint(&r, &tx_count, &tx_count_len)) {
    return set_err(err, err_len, "bad tx count");
  }
  if (tx_count == 0) return set_err(err, err_len, "zero tx count");
  if (tx_count > (uint64_t)(len / 10)) return set_err(err, err_len, "tx count unreasonable");
  if (tx_count > (uint64_t)(SIZE_MAX / 32)) return set_err(err, err_len, "tx count overflow");

  uint8_t *txids = (uint8_t *)malloc((size_t)tx_count * 32);
  if (!txids) return set_err(err, err_len, "oom txids");

  for (uint64_t txi = 0; txi < tx_count; txi++) {
    size_t tx_start = r.off;
    if (r.off + 4 > r.len) {
      free(txids);
      return set_err(err, err_len, "tx truncated");
    }
    const uint8_t *version_ptr = r.buf + r.off;
    r.off += 4;

    bool has_witness = false;
    if (r.off + 2 <= r.len && r.buf[r.off] == 0x00 && r.buf[r.off + 1] == 0x01) {
      has_witness = true;
      r.off += 2;
    }

    size_t in_count_off = r.off;
    uint64_t in_count = 0;
    size_t in_count_len = 0;
    if (read_varint(&r, &in_count, &in_count_len)) {
      free(txids);
      return set_err(err, err_len, "bad input count");
    }
    if (in_count == 0) {
      free(txids);
      return set_err(err, err_len, "zero inputs");
    }
    if (in_count > (uint64_t)(len / 41)) {
      free(txids);
      return set_err(err, err_len, "input count unreasonable");
    }

    size_t inputs_off = r.off;
    bool coinbase_input_ok = false;

    for (uint64_t i = 0; i < in_count; i++) {
      if (r.off + 36 > r.len) {
        free(txids);
        return set_err(err, err_len, "input truncated");
      }
      const uint8_t *prev = r.buf + r.off;
      r.off += 32;
      uint32_t prev_idx = 0;
      if (read_u32le(&r, &prev_idx)) {
        free(txids);
        return set_err(err, err_len, "input index truncated");
      }
      size_t script_len_off = r.off;
      uint64_t script_len = 0;
      size_t script_len_len = 0;
      if (read_varint(&r, &script_len, &script_len_len)) {
        free(txids);
        return set_err(err, err_len, "bad script len");
      }
      if (script_len > (uint64_t)(r.len - r.off)) {
        free(txids);
        return set_err(err, err_len, "script overrun");
      }
      const uint8_t *script_ptr = r.buf + r.off;
      if (read_bytes(&r, NULL, (size_t)script_len)) {
        free(txids);
        return set_err(err, err_len, "script truncated");
      }
      uint32_t seq = 0;
      if (read_u32le(&r, &seq)) {
        free(txids);
        return set_err(err, err_len, "sequence truncated");
      }
      (void)seq;
      (void)script_len_off;

      bool is_null_prev = true;
      for (int b = 0; b < 32; b++) {
        if (prev[b] != 0x00) { is_null_prev = false; break; }
      }
      if (is_null_prev && prev_idx == 0xffffffffu) {
        if (txi == 0 && i == 0 && in_count == 1) {
          if (script_len >= 2 && script_len <= 100) {
            coinbase_input_ok = true;
          }
        } else {
          free(txids);
          return set_err(err, err_len, "unexpected coinbase input");
        }
      }
      (void)script_ptr;
    }

    if (txi == 0 && !coinbase_input_ok) {
      free(txids);
      return set_err(err, err_len, "invalid coinbase");
    }

    size_t inputs_len = r.off - inputs_off;

    size_t out_count_off = r.off;
    uint64_t out_count = 0;
    size_t out_count_len = 0;
    if (read_varint(&r, &out_count, &out_count_len)) {
      free(txids);
      return set_err(err, err_len, "bad output count");
    }
    if (out_count == 0) {
      free(txids);
      return set_err(err, err_len, "zero outputs");
    }
    if (out_count > (uint64_t)(len / 10)) {
      free(txids);
      return set_err(err, err_len, "output count unreasonable");
    }

    size_t outputs_off = r.off;
    for (uint64_t i = 0; i < out_count; i++) {
      uint64_t value = 0;
      if (read_u64le(&r, &value)) {
        free(txids);
        return set_err(err, err_len, "output value truncated");
      }
      uint64_t pk_len = 0;
      size_t pk_len_len = 0;
      if (read_varint(&r, &pk_len, &pk_len_len)) {
        free(txids);
        return set_err(err, err_len, "bad pk script len");
      }
      if (pk_len > (uint64_t)(r.len - r.off)) {
        free(txids);
        return set_err(err, err_len, "pk script overrun");
      }
      if (read_bytes(&r, NULL, (size_t)pk_len)) {
        free(txids);
        return set_err(err, err_len, "pk script truncated");
      }
      (void)value;
    }
    size_t outputs_len = r.off - outputs_off;

    if (has_witness) {
      for (uint64_t i = 0; i < in_count; i++) {
        uint64_t items = 0;
        size_t items_len = 0;
        if (read_varint(&r, &items, &items_len)) {
          free(txids);
          return set_err(err, err_len, "bad witness count");
        }
        for (uint64_t j = 0; j < items; j++) {
          uint64_t item_len = 0;
          size_t item_len_len = 0;
          if (read_varint(&r, &item_len, &item_len_len)) {
            free(txids);
            return set_err(err, err_len, "bad witness item len");
          }
          if (item_len > (uint64_t)(r.len - r.off)) {
            free(txids);
            return set_err(err, err_len, "witness overrun");
          }
          if (read_bytes(&r, NULL, (size_t)item_len)) {
            free(txids);
            return set_err(err, err_len, "witness truncated");
          }
        }
      }
    }

    if (r.off + 4 > r.len) {
      free(txids);
      return set_err(err, err_len, "locktime truncated");
    }
    const uint8_t *locktime_ptr = r.buf + r.off;
    r.off += 4;

    size_t tx_end = r.off;

    uint8_t txid[32];
    if (!has_witness) {
      sha256d(r.buf + tx_start, tx_end - tx_start, txid);
    } else {
      sha256_ctx ctx;
      sha256_init(&ctx);
      sha256_update(&ctx, version_ptr, 4);
      sha256_update(&ctx, r.buf + in_count_off, in_count_len);
      sha256_update(&ctx, r.buf + inputs_off, inputs_len);
      sha256_update(&ctx, r.buf + out_count_off, out_count_len);
      sha256_update(&ctx, r.buf + outputs_off, outputs_len);
      sha256_update(&ctx, locktime_ptr, 4);
      uint8_t tmp[32];
      sha256_final(&ctx, tmp);
      sha256(tmp, sizeof(tmp), txid);
    }
    memcpy(txids + (size_t)txi * 32, txid, 32);
  }

  if (r.off != r.len) {
    free(txids);
    return set_err(err, err_len, "trailing data");
  }

  uint8_t merkle_root[32];
  if (compute_merkle_root(txids, (size_t)tx_count, merkle_root)) {
    free(txids);
    return set_err(err, err_len, "merkle compute failed");
  }
  free(txids);

  if (memcmp(merkle_le, merkle_root, 32) != 0) {
    return set_err(err, err_len, "merkle mismatch");
  }

  uint8_t target_be[32];
  if (build_target_from_bits(bits, target_be)) {
    return set_err(err, err_len, "bad bits");
  }

  uint8_t header_hash[32];
  sha256d(buf, 80, header_hash);
  uint8_t hash_be[32];
  reverse32(header_hash, hash_be);
  if (cmp_be(hash_be, target_be) > 0) {
    return set_err(err, err_len, "pow failed");
  }
  if (min_leading_zero_bits > 0) {
    unsigned lz = leading_zero_bits_be(hash_be);
    if (lz < min_leading_zero_bits) {
      return set_err(err, err_len, "pow below minimum");
    }
  }

  if (out_bits) *out_bits = bits;
  if (out_hash_be) memcpy(out_hash_be, hash_be, 32);
  *out_time = timestamp;
  return 0;
}
