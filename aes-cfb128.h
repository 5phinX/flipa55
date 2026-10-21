#ifndef __AES_CFB128_H__
#define __AES_CFB128_H__

#if defined(__cplusplus)
  extern "C" {
#endif

unsigned int encrypt_cfb128(const unsigned char *key, const unsigned char *input, unsigned char *output, unsigned int dataBlocks, int keySize);
unsigned int decrypt_cfb128(const unsigned char *key, const unsigned char *input, unsigned char *output, unsigned int dataBlocks, int keySize);

#if defined(__cplusplus)
  } //extern
#endif

#endif /* __AES_CFB128_H__ */
