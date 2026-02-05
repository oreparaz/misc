#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#include <sys/wait.h>

int validate_block_and_get_time(const uint8_t *buf, size_t len, uint32_t *out_time, unsigned min_leading_zero_bits, uint32_t *out_bits, uint8_t out_hash_be[32], char *err, size_t err_len);

#define MIN_POW_LEADING_ZERO_BITS 16u

static const char *k_selftest_block_hex =
"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
"29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d"
"65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2"
"052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c7"
"02b6bf11d5fac00000000";

static const uint32_t k_selftest_expected_time = 1231006505u;

static int set_err(char *err, size_t err_len, const char *msg) {
  if (err && err_len) snprintf(err, err_len, "%s", msg);
  return -1;
}

static int fetch_url_to_buf(const char *url, uint8_t **out, size_t *out_len, char *err, size_t err_len) {
  if (!url || !out || !out_len) return set_err(err, err_len, "bad args");
  char cmd[512];
  if (snprintf(cmd, sizeof(cmd), "curl -fsSL --proto =https --proto-redir =https --connect-timeout 10 --max-time 20 '%s'", url) >= (int)sizeof(cmd)) {
    return set_err(err, err_len, "url too long");
  }
  FILE *fp = popen(cmd, "r");
  if (!fp) return set_err(err, err_len, "popen failed");

  size_t cap = 0;
  size_t len = 0;
  uint8_t *buf = NULL;
  uint8_t tmp[4096];
  size_t n = 0;
  while ((n = fread(tmp, 1, sizeof(tmp), fp)) > 0) {
    if (len + n < len) { /* overflow */
      free(buf);
      pclose(fp);
      return set_err(err, err_len, "size overflow");
    }
    if (len + n > cap) {
      size_t newcap = cap ? cap : 65536;
      while (newcap < len + n) {
        if (newcap > (size_t)-1 / 2) {
          free(buf);
          pclose(fp);
          return set_err(err, err_len, "size overflow");
        }
        newcap *= 2;
      }
      uint8_t *nbuf = (uint8_t *)realloc(buf, newcap);
      if (!nbuf) {
        free(buf);
        pclose(fp);
        return set_err(err, err_len, "oom");
      }
      buf = nbuf;
      cap = newcap;
    }
    memcpy(buf + len, tmp, n);
    len += n;
  }
  if (ferror(fp)) {
    free(buf);
    pclose(fp);
    return set_err(err, err_len, "read failed");
  }
  int status = pclose(fp);
  if (status == -1) {
    free(buf);
    return set_err(err, err_len, "pclose failed");
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    free(buf);
    return set_err(err, err_len, "curl failed");
  }
  if (len == 0) {
    free(buf);
    return set_err(err, err_len, "empty response");
  }

  *out = buf;
  *out_len = len;
  return 0;
}

static int fetch_text(const char *url, char **out, char *err, size_t err_len) {
  uint8_t *buf = NULL;
  size_t len = 0;
  if (fetch_url_to_buf(url, &buf, &len, err, err_len)) return -1;
  char *s = (char *)malloc(len + 1);
  if (!s) {
    free(buf);
    return set_err(err, err_len, "oom");
  }
  memcpy(s, buf, len);
  s[len] = '\0';
  free(buf);
  *out = s;
  return 0;
}

static void trim_ws(char *s) {
  if (!s) return;
  size_t len = strlen(s);
  while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
  size_t i = 0;
  while (s[i] && isspace((unsigned char)s[i])) i++;
  if (i > 0) memmove(s, s + i, strlen(s + i) + 1);
}

static int is_hex_str(const char *s) {
  if (!s) return 0;
  for (size_t i = 0; s[i]; i++) {
    if (!isxdigit((unsigned char)s[i])) return 0;
  }
  return 1;
}

static int hex_val(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_to_bytes(const char *hex, uint8_t **out, size_t *out_len, char *err, size_t err_len) {
  if (!hex || !out || !out_len) return set_err(err, err_len, "bad args");
  size_t hex_len = strlen(hex);
  if (hex_len == 0 || (hex_len % 2) != 0) return set_err(err, err_len, "bad hex length");
  size_t blen = hex_len / 2;
  if (blen > 4000000u) return set_err(err, err_len, "hex too large");
  uint8_t *buf = (uint8_t *)malloc(blen);
  if (!buf) return set_err(err, err_len, "oom");
  for (size_t i = 0; i < blen; i++) {
    int hi = hex_val((unsigned char)hex[i * 2]);
    int lo = hex_val((unsigned char)hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      free(buf);
      return set_err(err, err_len, "bad hex");
    }
    buf[i] = (uint8_t)((hi << 4) | lo);
  }
  *out = buf;
  *out_len = blen;
  return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out, size_t out_len) {
  static const char *hex = "0123456789abcdef";
  if (out_len < len * 2 + 1) return;
  for (size_t i = 0; i < len; i++) {
    out[i * 2]     = hex[(bytes[i] >> 4) & 0x0f];
    out[i * 2 + 1] = hex[bytes[i] & 0x0f];
  }
  out[len * 2] = '\0';
}

static void run_selftest_or_die(void) {
  char err[128] = {0};
  uint8_t *block = NULL;
  size_t block_len = 0;
  if (hex_to_bytes(k_selftest_block_hex, &block, &block_len, err, sizeof(err))) {
    assert(0 && "selftest hex decode failed");
  }
  uint32_t block_time = 0;
  int rc = validate_block_and_get_time(block, block_len, &block_time, MIN_POW_LEADING_ZERO_BITS, NULL, NULL, err, sizeof(err));
  free(block);
  assert(rc == 0);
  assert(block_time == k_selftest_expected_time);
}

int main(int argc, char **argv) {
  char err[256] = {0};
  int use_selftest = 0;
  if (argc > 1) {
    if (strcmp(argv[1], "--selftest") == 0) {
      use_selftest = 1;
    } else {
      fprintf(stderr, "usage: %s [--selftest]\n", argv[0]);
      return 1;
    }
  }

  run_selftest_or_die();
  if (use_selftest) return 0;

  const char *tip_url = "https://blockstream.info/api/blocks/tip/height";
  long long height = -1;
  uint8_t *block = NULL;
  size_t block_len = 0;

  if (use_selftest) {
    height = 0;
    if (hex_to_bytes(k_selftest_block_hex, &block, &block_len, err, sizeof(err))) {
      fprintf(stderr, "selftest decode failed: %s\n", err);
      return 1;
    }
  } else {
    char *height_str = NULL;
    if (fetch_text(tip_url, &height_str, err, sizeof(err))) {
      fprintf(stderr, "fetch height failed: %s\n", err);
      return 1;
    }
    trim_ws(height_str);
    char *end = NULL;
    height = strtoll(height_str, &end, 10);
    if (end == height_str) {
      fprintf(stderr, "bad height\n");
      free(height_str);
      return 1;
    }
    while (end && *end) {
      if (!isspace((unsigned char)*end)) {
        fprintf(stderr, "bad height\n");
        free(height_str);
        return 1;
      }
      end++;
    }
    free(height_str);

    char hash_url[256];
    snprintf(hash_url, sizeof(hash_url), "https://blockstream.info/api/block-height/%lld", height);
    char *hash_str = NULL;
    if (fetch_text(hash_url, &hash_str, err, sizeof(err))) {
      fprintf(stderr, "fetch hash failed: %s\n", err);
      return 1;
    }
    trim_ws(hash_str);
    if (strlen(hash_str) != 64 || !is_hex_str(hash_str)) {
      fprintf(stderr, "bad hash\n");
      free(hash_str);
      return 1;
    }

    char raw_url[512];
    snprintf(raw_url, sizeof(raw_url), "https://blockstream.info/api/block/%s/raw", hash_str);
    free(hash_str);

    if (fetch_url_to_buf(raw_url, &block, &block_len, err, sizeof(err))) {
      fprintf(stderr, "fetch block failed: %s\n", err);
      return 1;
    }
  }

  uint32_t block_time = 0;
  uint32_t bits = 0;
  uint8_t hash_be[32];
  if (validate_block_and_get_time(block, block_len, &block_time, MIN_POW_LEADING_ZERO_BITS, &bits, hash_be, err, sizeof(err))) {
    fprintf(stderr, "block validation failed: %s\n", err);
    free(block);
    return 1;
  }
  free(block);

  printf("height: %lld\n", height);
  char hash_hex[65];
  bytes_to_hex(hash_be, sizeof(hash_be), hash_hex, sizeof(hash_hex));
  printf("hash: %s\n", hash_hex);
  printf("bits: 0x%08x (%u)\n", bits, bits);
  printf("time: %u", block_time);
  time_t t = (time_t)block_time;
  struct tm *tm = gmtime(&t);
  if (tm) {
    char buf[64];
    if (strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", tm)) {
      printf(" (%s)", buf);
    }
  }
  printf("\n");
  return 0;
}
