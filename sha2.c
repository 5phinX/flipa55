#include "sha2.h"
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <math.h>

static unsigned char dataBuf[128]; // 128 bytes to accomodate the biggest block needed for SHA-512

static const uint32_t K256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t H32[8];
static int dataBufSize = 0;
static int totalMsgSize = 0;

/**
 * @brief Computes unsigned modulo
 *
 * @returns @a a mod @a m
 */
int mod( int a, int m )
{
  int ret = a;
  while ( ret < 0 )
  {
    ret += m;
  }

  while ( ret >= m )
  {
    ret -= m;
  }

  return ret;
}

/**
 * @brief Computes unsigned modulo
 *
 * @returns @a a mod @a m
 */
float modfloat( float a, float m )
{
  float ret = a;
  while ( ret < 0 )
  {
    ret += m;
  }

  while ( ret >= m )
  {
    ret -= m;
  }

  return ret;
}

/**
 * @brief Left circular rotate of 32-bit word
 */
uint32_t rotl32( uint32_t x, unsigned int rot )
{
  return (uint32_t)( (x << (rot%32)) | ( x >> (32 - (rot%32)) ) );
}

/**
 * @brief Right circular rotate of 32-bit word
 */
uint32_t rotr32( uint32_t x, unsigned int rot )
{
  return (uint32_t)( (x >> (rot%32)) | ( x << (32 - (rot%32)) ) );
}

/**
 * @brief Ch function on 32-bit words
 *
 * Performs function (@a x AND @a y) XOR ( (NOT @a x) AND @a z)
 */
uint32_t Ch32( uint32_t x, uint32_t y, uint32_t z )
{
  return ( (x & y) ^ ((~x) & z) );
}

/**
 * @brief Maj function on 32-bit words
 *
 * Performs function (@a x AND @a y) XOR (@a x AND @a z) XOR (@a y AND @a z)
 */
uint32_t Maj32( uint32_t x, uint32_t y, uint32_t z )
{
  return ( (x & y) ^ (x & z) ^ (y & z) );
}

/**
 * @brief Sum from zero to 256 function (eq. 4.4 of FIPS 180-4)
 */
uint32_t sum0_256( uint32_t x )
{
  return (rotr32(x,2) ^ rotr32(x,13) ^ rotr32(x,22));
}

/**
 * @brief Sum from one to 256 function (eq. 4.5 of FIPS 180-4)
 */
uint32_t sum1_256( uint32_t x )
{
  return (rotr32(x,6) ^ rotr32(x,11) ^ rotr32(x,25));
}

/**
 * @brief Sigma 0 to 256 (eq. 4.6 of FIPS 180-4)
 */
uint32_t sigma0_256( uint32_t x)
{
  return (rotr32(x,7) ^ rotr32(x,18) ^ (x >> 3));
}

/**
 * @brief Sigma 1 to 256 (eq. 4.7 of FIPS 180-4)
 */
uint32_t sigma1_256( uint32_t x)
{
  return (rotr32(x,17) ^ rotr32(x,19) ^ (x >> 10));
}

void sha256_addData(const unsigned char *data, int len)
{
  uint32_t W[64];
  uint32_t a, b, c, d, e, f, g, h, T1, T2;
  int byte;
  unsigned int i;
  int blk;
  int j;
  int t;

  unsigned char *msg = (unsigned char*)malloc(dataBufSize+len);
  unsigned int msgLen = dataBufSize+len;
  totalMsgSize += len;

  memcpy(msg, dataBuf, dataBufSize);
  memcpy(&msg[dataBufSize], data, len);

  // Process all of the message blocks that do not need to be padded
  for ( i = 0; i < msgLen/64; i++ )
  {
    // Copy message block from input
    byte = i*64;
    for ( blk = 0; blk < 16; blk++ )
    {
      W[blk] = 0;
      for ( j = 0; j < 4; j++ )
      {
        W[blk] |= (uint32_t)msg[byte++] << ((3-j)*8);
      }
    }
    // Fill the rest of the message schedule
    for ( blk = 16; blk < 64; blk++ )
    {
      W[blk] = sigma1_256(W[blk-2]) + W[blk-7] + sigma0_256(W[blk-15]) + W[blk-16];
    }
#ifdef SHA2_DEBUG
    printf("Block contents [%d]:\n", i);
    for ( blk = 0; blk < 16; blk++ )
    {
      printf("  W[%d] = %.8X\n", blk, W[blk]);
    }
#endif

    // Initialize working variables
    a = H32[0];
    b = H32[1];
    c = H32[2];
    d = H32[3];
    e = H32[4];
    f = H32[5];
    g = H32[6];
    h = H32[7];

    for ( t = 0; t < 64; t++ )
    {
      T1 = h + sum1_256(e) + Ch32(e,f,g) + K256[t] + W[t];
      T2 = sum0_256(a) + Maj32(a,b,c);
      h  = g;
      g  = f;
      f  = e;
      e  = d + T1;
      d  = c;
      c  = b;
      b  = a;
      a  = T1 + T2;
#ifdef SHA2_DEBUG
      printf("t=%s%d: %.8X %.8X %.8X %.8X %.8X %.8X %.8X %.8X\n", t<10?" ":"", t, a, b, c, d, e, f, g, h);
#endif
    }

    // Compute the intermediate hash
#ifdef SHA2_DEBUG
    printf(" H[0] = %.8X + %.8X = %.8X\n", H32[0], a, H32[0] + a);
#endif
    H32[0] += a;
#ifdef SHA2_DEBUG
    printf(" H[1] = %.8X + %.8X = %.8X\n", H32[1], b, H32[1] + b);
#endif
    H32[1] += b;
#ifdef SHA2_DEBUG
    printf(" H[2] = %.8X + %.8X = %.8X\n", H32[2], c, H32[2] + c);
#endif
    H32[2] += c;
#ifdef SHA2_DEBUG
    printf(" H[3] = %.8X + %.8X = %.8X\n", H32[3], d, H32[3] + d);
#endif
    H32[3] += d;
#ifdef SHA2_DEBUG
    printf(" H[4] = %.8X + %.8X = %.8X\n", H32[4], e, H32[4] + e);
#endif
    H32[4] += e;
#ifdef SHA2_DEBUG
    printf(" H[5] = %.8X + %.8X = %.8X\n", H32[5], f, H32[5] + f);
#endif
    H32[5] += f;
#ifdef SHA2_DEBUG
    printf(" H[6] = %.8X + %.8X = %.8X\n", H32[6], g, H32[6] + g);
#endif
    H32[6] += g;
#ifdef SHA2_DEBUG
    printf(" H[7] = %.8X + %.8X = %.8X\n", H32[7], h, H32[7] + h);
#endif
    H32[7] += h;
  }

  // Copy the end of the message
  byte = msgLen-(msgLen%64);
  memcpy(dataBuf, &msg[byte], msgLen-byte);
  dataBufSize = msgLen-byte;
  free(msg);
}

void sha256_finalize(unsigned char *hash)
{
  int len = dataBufSize;
  uint32_t W[64];
  uint32_t a, b, c, d, e, f, g, h, T1, T2;
  int byte;
  int blk;
  int j;
  int t;
  int i;

  // Process the last blocks of the message
  int padding_size = (mod(448-(totalMsgSize*8+1), 512)+1)/8;
  // Copy the end of the message
  byte = 0;
  while ( padding_size > 0 )
  {
    for ( blk = 0; blk < 16; blk++ )
    {
      W[blk] = 0;
      for ( j = 0; j < 4; j++ )
      {
        if ( byte == len )
        {
          W[blk] |= (uint32_t)0x80 << ((3-j)*8);
          padding_size--;
          byte++;
        }
        else if ( byte >= len )
        {
          W[blk] |= (uint32_t)0x00 << ((3-j)*8);
          padding_size--;
        }
        else
        {
          W[blk] |= (uint32_t)dataBuf[byte++] << ((3-j)*8);
        }
      }
    }
    if ( padding_size <= 0 )
    {
      W[14] = (uint32_t)((uint64_t)(totalMsgSize*8) >> 32);
      W[15] = (uint32_t)((uint64_t)(totalMsgSize*8) & 0xFFFFFFFF);
    }
    // Fill the rest of the message schedule
    for ( blk = 16; blk < 64; blk++ )
    {
      W[blk] = sigma1_256(W[blk-2]) + W[blk-7] + sigma0_256(W[blk-15]) + W[blk-16];
    }
#ifdef SHA2_DEBUG
    printf("Block contents:\n");
    for ( blk = 0; blk < 16; blk++ )
    {
      printf("  W[%d] = %.8X\n", blk, W[blk]);
    }
#endif

    // Initialize working variables
    a = H32[0];
    b = H32[1];
    c = H32[2];
    d = H32[3];
    e = H32[4];
    f = H32[5];
    g = H32[6];
    h = H32[7];

    for ( t = 0; t < 64; t++ )
    {
      T1 = h + sum1_256(e) + Ch32(e,f,g) + K256[t] + W[t];
      T2 = sum0_256(a) + Maj32(a,b,c);
      h  = g;
      g  = f;
      f  = e;
      e  = d + T1;
      d  = c;
      c  = b;
      b  = a;
      a  = T1 + T2;
#ifdef SHA2_DEBUG
      printf("t=%s%d: %.8X %.8X %.8X %.8X %.8X %.8X %.8X %.8X\n", t<10?" ":"", t, a, b, c, d, e, f, g, h);
#endif
    }
    // Compute the intermediate hash
#ifdef SHA2_DEBUG
    printf(" H[0] = %.8X + %.8X = %.8X\n", H32[0], a, H32[0] + a);
#endif
    H32[0] += a;
#ifdef SHA2_DEBUG
    printf(" H[1] = %.8X + %.8X = %.8X\n", H32[1], b, H32[1] + b);
#endif
    H32[1] += b;
#ifdef SHA2_DEBUG
    printf(" H[2] = %.8X + %.8X = %.8X\n", H32[2], c, H32[2] + c);
#endif
    H32[2] += c;
#ifdef SHA2_DEBUG
    printf(" H[3] = %.8X + %.8X = %.8X\n", H32[3], d, H32[3] + d);
#endif
    H32[3] += d;
#ifdef SHA2_DEBUG
    printf(" H[4] = %.8X + %.8X = %.8X\n", H32[4], e, H32[4] + e);
#endif
    H32[4] += e;
#ifdef SHA2_DEBUG
    printf(" H[5] = %.8X + %.8X = %.8X\n", H32[5], f, H32[5] + f);
#endif
    H32[5] += f;
#ifdef SHA2_DEBUG
    printf(" H[6] = %.8X + %.8X = %.8X\n", H32[6], g, H32[6] + g);
#endif
    H32[6] += g;
#ifdef SHA2_DEBUG
    printf(" H[7] = %.8X + %.8X = %.8X\n", H32[7], h, H32[7] + h);
#endif
    H32[7] += h;
  }

  byte = 0;
  for ( i = 0; i < 8; i++ )
  {
    hash[byte++] = (H32[i] >> 24) & 0xff;
    hash[byte++] = (H32[i] >> 16) & 0xff;
    hash[byte++] = (H32[i] >> 8) & 0xff;
    hash[byte++] = H32[i] & 0xff;
  }
}

void sha256_initialize()
{
  dataBufSize=0;
  totalMsgSize=0;
  H32[0] = 0x6a09e667;
  H32[1] = 0xbb67ae85;
  H32[2] = 0x3c6ef372;
  H32[3] = 0xa54ff53a;
  H32[4] = 0x510e527f;
  H32[5] = 0x9b05688c;
  H32[6] = 0x1f83d9ab;
  H32[7] = 0x5be0cd19;
}

