/* ========================================================================
 * Copyright (c) 2006-2007 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/* crypt routines for uwa */


#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>


#define UC (unsigned char*)

#include "openssl/evp.h"
#include "uwa_crypt.h"

static EVP_CIPHER_CTX *ct[2] = {NULL,NULL};

/* Initialize the keys.  This is one for all processes. */

/* call this few times prior to init */
void uwa_crypt_seed()
{
   struct timeval tv;
   gettimeofday(&tv,NULL);
   RAND_seed(&tv.tv_usec, 4);
}

int uwa_crypt_init()
{
   const EVP_CIPHER *c;
   const EVP_MD *m;
   int i, s;
   unsigned char key[EVP_MAX_KEY_LENGTH],iv[EVP_MAX_KEY_LENGTH];
   char text[32];

   if (ct[0]) return(1);

   /* printf("UWA: crypt init\n"); */

   uwa_crypt_seed();
   c = EVP_aes_128_ecb();  /* AES */
   m = EVP_dss();
   if (!(c&&m)) return (0);

   uwa_crypt_seed();
   RAND_bytes(text, 32);
   EVP_BytesToKey(c, m, NULL, UC text, 32, 1, key, iv);

   for (i=0;i<2;i++) {
     ct[i]=(EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
     EVP_CipherInit(ct[i], c, key, iv, i);
   }
   return (1);
}


/* Crypt routine:
   mode = UWA_ENCRYPT:  plaintext (in) -> ciphertext (out)
   mode = UWA_DECRYPT:  ciphertext (in) -> plaintext (out)
   */

int uwa_crypt(int mode, char *out, int *outlen, char *in, int inlen)
{
   int ol;
   int len;

   /* PRINTF("uwa crypt pid (%d) %d:%x\n", getpid(), mode, ct[0]); */
   EVP_CipherInit(ct[mode], NULL, NULL, NULL, mode);
   EVP_CipherUpdate(ct[mode], UC out, &ol, UC in, inlen);
   out += ol;
   *outlen = ol;

   EVP_CipherFinal(ct[mode], UC out, &ol);
   *outlen += ol;

   len = *outlen;
   return (len);
}
   

