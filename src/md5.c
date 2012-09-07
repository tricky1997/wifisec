

#include "md5.h"



static void Transform(UINT4 *, UINT4 *);

#ifdef	__STDC__
static const
#else
static
#endif
unsigned char PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))


#if	defined(FAST_MD5) && defined(__GNUC__) && defined(mc68000)
inline UINT4 ROTATE_LEFT(UINT4 x, int n)
{
      asm("roll %2,%0": "=d"(x):"0"(x), "Ir"(n));
	return x;
}
#else
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#endif



#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

void MD5Init(mdContext)
MD5_CTX *mdContext;
{
	mdContext->i[0] = mdContext->i[1] = (UINT4) 0;

	mdContext->buf[0] = (UINT4) 0x67452301;
	mdContext->buf[1] = (UINT4) 0xefcdab89;
	mdContext->buf[2] = (UINT4) 0x98badcfe;
	mdContext->buf[3] = (UINT4) 0x10325476;
}

void MD5Update(mdContext, inBuf, inLen)
MD5_CTX *mdContext;
unsigned const char *inBuf;
unsigned int inLen;
{
	UINT4 in[16];
	int mdi;
	unsigned int i, ii;

	
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

	
	if ((mdContext->i[0] + ((UINT4) inLen << 3)) < mdContext->i[0])
		mdContext->i[1]++;
	mdContext->i[0] += ((UINT4) inLen << 3);
	mdContext->i[1] += ((UINT4) inLen >> 29);

	while (inLen--) {
		
		mdContext->in[mdi++] = *inBuf++;

		
		if (mdi == 0x40) {
			for (i = 0, ii = 0; i < 16; i++, ii += 4)
				in[i] =
				    (((UINT4) mdContext->in[ii +
							    3]) << 24) |
				    (((UINT4) mdContext->in[ii + 2]) << 16) |
				    (((UINT4) mdContext->in[ii + 1]) << 8) |
				    ((UINT4) mdContext->in[ii]);
			Transform(mdContext->buf, in);
			mdi = 0;
		}
	}
}


void MD5Final(mdContext)
MD5_CTX *mdContext;
{
	UINT4 in[16];
	int mdi;
	unsigned int i, ii;
	unsigned int padLen;

	
	in[14] = mdContext->i[0];
	in[15] = mdContext->i[1];

	
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

	
	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
	MD5Update(mdContext, PADDING, padLen);

	
	for (i = 0, ii = 0; i < 14; i++, ii += 4)
		in[i] = (((UINT4) mdContext->in[ii + 3]) << 24) |
		    (((UINT4) mdContext->in[ii + 2]) << 16) |
		    (((UINT4) mdContext->in[ii + 1]) << 8) |
		    ((UINT4) mdContext->in[ii]);
	Transform(mdContext->buf, in);

	
	for (i = 0, ii = 0; i < 4; i++, ii += 4) {
		mdContext->digest[ii] =
		    (unsigned char)(mdContext->buf[i] & 0xFF);
		mdContext->digest[ii + 1] =
		    (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
		mdContext->digest[ii + 2] =
		    (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
		mdContext->digest[ii + 3] =
		    (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
	}
}

static void Transform(buf, in)
UINT4 *buf;
UINT4 *in;
{
	UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

	
#define S11 7
#define S12 12
#define S13 17
#define S14 22

	FF(a, b, c, d, in[0], S11, 0xd76aa478);	
	FF(d, a, b, c, in[1], S12, 0xe8c7b756);	
	FF(c, d, a, b, in[2], S13, 0x242070db);	
	FF(b, c, d, a, in[3], S14, 0xc1bdceee);	
	FF(a, b, c, d, in[4], S11, 0xf57c0faf);	
	FF(d, a, b, c, in[5], S12, 0x4787c62a);	
	FF(c, d, a, b, in[6], S13, 0xa8304613);	
	FF(b, c, d, a, in[7], S14, 0xfd469501);	
	FF(a, b, c, d, in[8], S11, 0x698098d8);	
	FF(d, a, b, c, in[9], S12, 0x8b44f7af);	
	FF(c, d, a, b, in[10], S13, 0xffff5bb1);	
	FF(b, c, d, a, in[11], S14, 0x895cd7be);	
	FF(a, b, c, d, in[12], S11, 0x6b901122);	
	FF(d, a, b, c, in[13], S12, 0xfd987193);	
	FF(c, d, a, b, in[14], S13, 0xa679438e);	
	FF(b, c, d, a, in[15], S14, 0x49b40821);	

	
#define S21 5
#define S22 9
#define S23 14
#define S24 20
	GG(a, b, c, d, in[1], S21, 0xf61e2562);	
	GG(d, a, b, c, in[6], S22, 0xc040b340);	
	GG(c, d, a, b, in[11], S23, 0x265e5a51);	
	GG(b, c, d, a, in[0], S24, 0xe9b6c7aa);	
	GG(a, b, c, d, in[5], S21, 0xd62f105d);	
	GG(d, a, b, c, in[10], S22, 0x2441453);	
	GG(c, d, a, b, in[15], S23, 0xd8a1e681);	
	GG(b, c, d, a, in[4], S24, 0xe7d3fbc8);	
	GG(a, b, c, d, in[9], S21, 0x21e1cde6);	
	GG(d, a, b, c, in[14], S22, 0xc33707d6);	
	GG(c, d, a, b, in[3], S23, 0xf4d50d87);	
	GG(b, c, d, a, in[8], S24, 0x455a14ed);	
	GG(a, b, c, d, in[13], S21, 0xa9e3e905);	
	GG(d, a, b, c, in[2], S22, 0xfcefa3f8);	
	GG(c, d, a, b, in[7], S23, 0x676f02d9);	
	GG(b, c, d, a, in[12], S24, 0x8d2a4c8a);	

	
#define S31 4
#define S32 11
#define S33 16
#define S34 23
	HH(a, b, c, d, in[5], S31, 0xfffa3942);	
	HH(d, a, b, c, in[8], S32, 0x8771f681);	
	HH(c, d, a, b, in[11], S33, 0x6d9d6122);	
	HH(b, c, d, a, in[14], S34, 0xfde5380c);	
	HH(a, b, c, d, in[1], S31, 0xa4beea44);	
	HH(d, a, b, c, in[4], S32, 0x4bdecfa9);	
	HH(c, d, a, b, in[7], S33, 0xf6bb4b60);	
	HH(b, c, d, a, in[10], S34, 0xbebfbc70);	
	HH(a, b, c, d, in[13], S31, 0x289b7ec6);	
	HH(d, a, b, c, in[0], S32, 0xeaa127fa);	
	HH(c, d, a, b, in[3], S33, 0xd4ef3085);	
	HH(b, c, d, a, in[6], S34, 0x4881d05);	
	HH(a, b, c, d, in[9], S31, 0xd9d4d039);	
	HH(d, a, b, c, in[12], S32, 0xe6db99e5);	
	HH(c, d, a, b, in[15], S33, 0x1fa27cf8);	
	HH(b, c, d, a, in[2], S34, 0xc4ac5665);	

	
#define S41 6
#define S42 10
#define S43 15
#define S44 21
	II(a, b, c, d, in[0], S41, 0xf4292244);	
	II(d, a, b, c, in[7], S42, 0x432aff97);	
	II(c, d, a, b, in[14], S43, 0xab9423a7);	
	II(b, c, d, a, in[5], S44, 0xfc93a039);	
	II(a, b, c, d, in[12], S41, 0x655b59c3);	
	II(d, a, b, c, in[3], S42, 0x8f0ccc92);	
	II(c, d, a, b, in[10], S43, 0xffeff47d);	
	II(b, c, d, a, in[1], S44, 0x85845dd1);	
	II(a, b, c, d, in[8], S41, 0x6fa87e4f);	
	II(d, a, b, c, in[15], S42, 0xfe2ce6e0);	
	II(c, d, a, b, in[6], S43, 0xa3014314);	
	II(b, c, d, a, in[13], S44, 0x4e0811a1);	
	II(a, b, c, d, in[4], S41, 0xf7537e82);	
	II(d, a, b, c, in[11], S42, 0xbd3af235);	
	II(c, d, a, b, in[2], S43, 0x2ad7d2bb);	
	II(b, c, d, a, in[9], S44, 0xeb86d391);	

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

