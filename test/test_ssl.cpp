#include "CwxAes.h"
#include "CwxSha.h"
#include "CwxRsa.h"

CWINUX_USING_NAMESPACE
// ---- rsa非对称加解密 ---- //    
#define KEY_LENGTH  2048               // 密钥长度  
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径  
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径  

// 函数方法生成密钥对   
void generateRSAKey(std::string strKey[2])
{
  // 公私密钥对    
  size_t pri_len;
  size_t pub_len;
  char *pri_key = NULL;
  char *pub_key = NULL;

  // 生成密钥对    
  RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

  BIO *pri = BIO_new(BIO_s_mem());
  BIO *pub = BIO_new(BIO_s_mem());

  PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
  PEM_write_bio_RSAPublicKey(pub, keypair);

  // 获取长度    
  pri_len = BIO_pending(pri);
  pub_len = BIO_pending(pub);

  // 密钥对读取到字符串    
  pri_key = (char *)malloc(pri_len + 1);
  pub_key = (char *)malloc(pub_len + 1);

  BIO_read(pri, pri_key, pri_len);
  BIO_read(pub, pub_key, pub_len);

  pri_key[pri_len] = '\0';
  pub_key[pub_len] = '\0';

  // 存储密钥对    
  strKey[0] = pub_key;
  strKey[1] = pri_key;
  // 内存释放  
  RSA_free(keypair);
  BIO_free_all(pub);
  BIO_free_all(pri);

  free(pri_key);
  free(pub_key);
}

int main(int, char**) {
  unsigned char digest[SHA512_DIGEST_LENGTH];
  char  hex_digest[SHA512_DIGEST_LENGTH * 2 + 1];
  uint32_t dest_len = SHA512_DIGEST_LENGTH * 2 + 1;
  string keys[2];
  generateRSAKey(keys);
  string pubkey = keys[0];
  string prikey = keys[1];
  printf("public key:\n%s\n", pubkey.c_str());
  printf("private key:\n%s\n", prikey.c_str());
  CwxSha512 sha512;
  string sign = "abcdefedsfsdfsdfsdfl";
  sha512.update((unsigned char const*)sign.c_str(), sign.length());
  sha512.final(digest);
  printf("public key sha512 sign(len:%d):\n\t%s\n\t%s\n", SHA512_DIGEST_LENGTH,
    sha512.to_hex(),
    CwxCommon::toHex(digest, SHA512_DIGEST_LENGTH, hex_digest, dest_len));
  CwxRsaPri rsa_pri;
  CwxRsaPub rsa_pub;
  if (!rsa_pri.init(prikey.c_str(), prikey.length())) {
    printf("Failed to init CwxRsaPri.err:%s\n", rsa_pri.errmsg());
    exit(1);
  }
  if (!rsa_pub.init(pubkey.c_str(), pubkey.length())) {
    printf("Failed to init rsa_pub. err:%s\n", rsa_pub.errmsg());
    exit(1);
  }
  string en_str, de_str;
  printf("encrypt by private key, decrypt by public key:\n");
  if (!rsa_pri.encrypt(digest, SHA512_DIGEST_LENGTH, en_str)) {
    printf("Failed to invokde CwxRsaPri.encrypt:%s\n", rsa_pri.errmsg());
    exit(1);
  }
  if (!rsa_pub.decrypt((unsigned char*)en_str.c_str(), en_str.length(), de_str)) {
    printf("Failed to invokde CwxRsaPub.decrypt:%s\n", rsa_pub.errmsg());
    exit(1);
  }
  dest_len = SHA512_DIGEST_LENGTH * 2 + 1;
  printf("src:%s\n", CwxCommon::toHex(digest, SHA512_DIGEST_LENGTH, hex_digest, dest_len));
  dest_len = SHA512_DIGEST_LENGTH * 2 + 1;
  printf("encryp:%s\n", CwxCommon::toHex((unsigned char*)en_str.c_str(), en_str.length(), hex_digest, dest_len));
  dest_len = SHA512_DIGEST_LENGTH * 2 + 1;
  printf("decrypt:%s\n", CwxCommon::toHex((unsigned char*)de_str.c_str(), de_str.length(), hex_digest, dest_len));
  printf("encrypt by public key, decrypt by private key:\n");
  if (!rsa_pub.encrypt(digest, SHA512_DIGEST_LENGTH, en_str)) {
    printf("Failed to invokde CwxRsaPub.encrypt:%s\n", rsa_pub.errmsg());
    exit(1);
  }
  if (!rsa_pri.decrypt((unsigned char*)en_str.c_str(), en_str.length(), de_str)) {
    printf("Failed to invokde CwxRsaPri.decrypt:%s\n", rsa_pri.errmsg());
    exit(1);
  }
  dest_len = SHA512_DIGEST_LENGTH * 2 + 1;
  printf("src:%s\n", CwxCommon::toHex(digest, SHA512_DIGEST_LENGTH, hex_digest, dest_len));
  dest_len = SHA512_DIGEST_LENGTH * 2 + 1;
  printf("encryp:%s\n", CwxCommon::toHex((unsigned char*)en_str.c_str(), en_str.length(), hex_digest, dest_len));
  dest_len = SHA512_DIGEST_LENGTH * 2 + 1;
  printf("decrypt:%s\n", CwxCommon::toHex((unsigned char*)de_str.c_str(), de_str.length(), hex_digest, dest_len));

  printf("Ase encryp/decrypt..\n");
  //pubkey = "int aes_len = aes.padding_size(pubkey.length()) + pubkey.length();";
  CwxAesEncrypt  aes_enc;
  CwxAesDecrypt  aes_dec;
  if (!aes_enc.init(digest, digest + 32, 256)) {
    printf("Failed to invokde CwxAes.init:%s\n", aes_enc.errmsg());
    exit(1);
  }
  if (!aes_dec.init(digest, digest + 32, 256)) {
    printf("Failed to invokde CwxAes.init:%s\n", aes_dec.errmsg());
    exit(1);
  }
  int aes_len = aes_enc.padding_size(pubkey.length()) + pubkey.length();
  unsigned char* aes_src = (unsigned char*)malloc(aes_len);
  unsigned char* aes_dest = (unsigned char*)malloc(aes_len);
  char* aes_hex = (char*)malloc(aes_len * 2 + 1);
  memset(aes_src, 0x00, aes_len);
  memcpy(aes_src, pubkey.c_str(), pubkey.length());
  dest_len = aes_len * 2 + 1;
  printf("key:%s\n", CwxCommon::toHex(digest, 32, aes_hex, dest_len));
  printf("iv:%s\n", CwxCommon::toHex(digest+32, 32, aes_hex, dest_len));
  if (!aes_enc.encrypt(aes_src, aes_dest, aes_len)) {
    printf("Failed to invokde CwxAes.encrypt:%s\n", aes_enc.errmsg());
    exit(1);
  }
  dest_len = aes_len * 2 + 1;
  printf("src:\n%s\n", CwxCommon::toHex(aes_src, aes_len, aes_hex, dest_len));
  dest_len = aes_len * 2 + 1;
  printf("encryp:\n%s\n", CwxCommon::toHex(aes_dest, aes_len, aes_hex, dest_len));
  dest_len = aes_len * 2 + 1;
  printf("key:%s\n", CwxCommon::toHex(digest, 32, aes_hex, dest_len));
  printf("iv:%s\n", CwxCommon::toHex(digest+32, 32, aes_hex, dest_len));
  if (!aes_dec.decrypt(aes_dest, aes_src, aes_len)) {
    printf("Failed to invokde CwxAes.decrypt:%s\n", aes_dec.errmsg());
    exit(1);
  }
  dest_len = aes_len * 2 + 1;
  printf("src:\n%s\n", CwxCommon::toHex(aes_dest, aes_len, aes_hex, dest_len));
  dest_len = aes_len * 2 + 1;
  printf("dest:\n%s\n", CwxCommon::toHex(aes_src, aes_len, aes_hex, dest_len));
  return 0;
}
