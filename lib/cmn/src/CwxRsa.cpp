
#include "CwxRsa.h"

CWINUX_BEGIN_NAMESPACE
// 初始化。
bool CwxRsaPri::init(char const* key, int len) {
  if (rsa_) RSA_free(rsa_);
  rsa_ = RSA_new();
  BIO *keybio = BIO_new_mem_buf((void*)key, len);
  rsa_ = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
  BIO_free_all(keybio);
  if (!rsa_) {
    memset(err_buf_, 0x00, 1024);
    ERR_error_string_n(ERR_get_error(), err_buf_, 1023);
    err_ = string("Failed to invoke:PEM_read_bio_RSAPrivateKey(), err:") + err_buf_;
    return false;
  }
  return true;
}
// encrypt
bool CwxRsaPri::encrypt(unsigned char *from, int len, string& to) {
  if (!rsa_) {
    err_ = "Not init.";
    return false;
  }
  if (len > max_encrypt_size()) {
    snprintf(err_buf_, 1023, "encrypted string's size[%d] is too long, max:[%d].", len, max_encrypt_size());
    err_ = err_buf_;
    return false;
  }
  memset(buf_, 0x00, 1024);
  int ret = RSA_private_encrypt(len, from, buf_, rsa_, RSA_PKCS1_PADDING);
  if (-1 == ret) {
    memset(err_buf_, 0x00, 1024);
    ERR_error_string_n(ERR_get_error(), err_buf_, 1023);
    err_ = string("Failed to invoke:RSA_private_encrypt(), err:") + err_buf_;
    return false;
  }
  to.assign((char*)buf_, ret);
  return true;
}
// decrypt。false
bool CwxRsaPri::decrypt(unsigned char *from, int len, string& to) {
  if (!rsa_) {
    err_ = "Not init.";
    return false;
  }
  memset(buf_, 0x00, 1024);
  int ret = RSA_private_decrypt(len, from, buf_, rsa_, RSA_PKCS1_PADDING);
  if (-1 == ret) {
    memset(err_buf_, 0x00, 1024);
    ERR_error_string_n(ERR_get_error(), err_buf_, 1023);
    err_ = string("Failed to invoke:RSA_private_decrypt(), err:") + err_buf_;
    return false;
  }
  to.assign((char*)buf_, ret);
  return true;
}

// 形成密钥
void CwxRsaPri::generate_rsa(string& pri, string& pub, uint32_t len) {
  // 公私密钥对
  size_t pri_len;
  size_t pub_len;
  char *pri_key = NULL;
  char *pub_key = NULL;
  // 生成密钥对
  RSA *keypair = RSA_generate_key(len, RSA_3, NULL, NULL);
  BIO *pri_bio = BIO_new(BIO_s_mem());
  BIO *pub_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPrivateKey(pri_bio, keypair, NULL, NULL, 0, NULL, NULL);
  PEM_write_bio_RSAPublicKey(pub_bio, keypair);
  // 获取长度
  pri_len = BIO_pending(pri_bio);
  pub_len = BIO_pending(pub_bio);
  // 密钥对读取到字符串
  pri_key = (char *)malloc(pri_len);
  pub_key = (char *)malloc(pub_len);
  BIO_read(pri_bio, pri_key, pri_len);
  BIO_read(pub_bio, pub_key, pub_len);
  pub.assign(pub_key, pub_len);
  pri.assign(pri_key, pri_len);
  RSA_free(keypair);
  BIO_free_all(pub_bio);
  BIO_free_all(pri_bio);
}

// 初始化。
bool CwxRsaPub::init(char const* key, int len) {
  if (rsa_) RSA_free(rsa_);
  rsa_ = RSA_new();
  BIO *keybio = BIO_new_mem_buf((void*)key, len);
  rsa_ = PEM_read_bio_RSAPublicKey(keybio, NULL, NULL, NULL);
  BIO_free_all(keybio);
  if (!rsa_) {
    memset(err_buf_, 0x00, 1024);
    ERR_error_string_n(ERR_get_error(), err_buf_, 1023);
    err_ = string("Failed to invoke:PEM_read_bio_RSAPrivateKey(), err:") + err_buf_;
    return false;
  }
  return true;
}
// encrypt
bool CwxRsaPub::encrypt(unsigned char *from, int len, string& to) {
  if (!rsa_) {
    err_ = "Not init.";
    return false;
  }
  if (len > max_encrypt_size()) {
    snprintf(err_buf_, 1023, "encrypted string's size[%d] is too long, max:[%d].", len, max_encrypt_size());
    err_ = err_buf_;
    return false;
  }
  memset(buf_, 0x00, 1024);
  int ret = RSA_public_encrypt(len, from, buf_, rsa_, RSA_PKCS1_PADDING);
  if (-1 == ret) {
    memset(err_buf_, 0x00, 1024);
    ERR_error_string_n(ERR_get_error(), err_buf_, 1023);
    err_ = string("Failed to invoke:RSA_private_encrypt(), err:") + err_buf_;
    return false;
  }
  to.assign((char*)buf_, ret);
  return true;
}
// decrypt。false
bool CwxRsaPub::decrypt(unsigned char *from, int len, string& to) {
  if (!rsa_) {
    err_ = "Not init.";
    return false;
  }
  memset(buf_, 0x00, 1024);
  int ret = RSA_public_decrypt(len, from, buf_, rsa_, RSA_PKCS1_PADDING);
  if (-1 == ret) {
    memset(err_buf_, 0x00, 1024);
    ERR_error_string_n(ERR_get_error(), err_buf_, 1023);
    err_ = string("Failed to invoke:RSA_private_decrypt(), err:") + err_buf_;
    return false;
  }
  to.assign((char*)buf_, ret);
  return true;
}

CWINUX_END_NAMESPACE

