

#include <stdint.h>


typedef uint32_t UINT4;


typedef struct {
	UINT4 i[2];		
	UINT4 buf[4];		
	unsigned char in[64];	
	unsigned char digest[16];	
} MD5_CTX;

void MD5Init(MD5_CTX * mdContext);
void MD5Update(MD5_CTX *, unsigned const char *, unsigned int);
void MD5Final(MD5_CTX *);

