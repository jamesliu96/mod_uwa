/* UWA crypt */

#define UWA_ENCRYPT 1  /* EVP library conventions */
#define UWA_DECRYPT 0

void uwa_crypt_seed();
int  uwa_crypt_init(); 
int  uwa_crypt(int mode, char *out, int *outlen, char *in, int inlen); 

