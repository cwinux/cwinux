#ifndef __CWX_MD5_H__
#define __CWX_MD5_H__
/*
版权声明：
    本软件遵循GNU LGPL (Lesser General Public License)（http://www.gnu.org/licenses/gpl.html），
    联系方式：email:cwinux@gmail.com；微博:http://weibo.com/cwinux
*/

/**
*@file  CwxMd5.h
*@author cwinux@gmail.com
*@version 0.1
*@date    2009-11-28
*@warning 无
*@bug   
*/

#include "CwxPre.h"
#include "CwxGlobalMacro.h"
#include "CwxType.h"
#include <iostream>
#include <string>
#include <string.h>
#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/des.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "CwxCommon.h"
CWINUX_BEGIN_NAMESPACE
/**
*@class  CwxMd5
*@brief  Md5的签名对象。此对象多线程不安全，在多线程环境下，
        每个线程需要自己的一个对象实例。
*/
class CwxMd5
{
public:
    ///构造函数
    CwxMd5() {
      MD5_Init(&ctx_);
      memset(digest_, 0x00, 16);
      memset(hex_, 0x00, 33);
    }
    ///析构函数
    ~CwxMd5() {}
public:
    /**
    *@brief  根据buf的内容，对MD5签名进行更新
    *@param [in] szBuf 签名的内容.
    *@param [in] uiLen 内容的长度.
    *@return void.
    */
    void update(unsigned char const *szBuf, uint32_t uiLen);
    /**
    *@brief  输出16字节的签名内容
    *@param [out] digest 输出内容的签名.
    *@return void.
    */
    void final(unsigned char digest[16]);
    /**
    *@brief  输出签名的HEX
    *@param [out] digest 输出内容的签名HEX.
    *@return void.
    **/
    char const* to_hex();
    /**
    ** HEX 长度
    **/
    uint32_t hex_len() const { return 32; }
private:
    unsigned char          digest_[16];
    char                   hex_[33];
    MD5_CTX                ctx_;
};

CWINUX_END_NAMESPACE

#include "CwxPost.h"

#endif
