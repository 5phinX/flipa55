#ifndef __SHA2_H__
#define __SHA2_H__


#if defined(__cplusplus)
  extern "C" {
#endif

#include <stdint.h>

void sha256_addData(const unsigned char *data, int len);
void sha256_finalize(unsigned char *hash);
void sha256_initialize();

#if defined(__cplusplus)
  } //extern
#endif

#endif /* __SHA2_H__ */
