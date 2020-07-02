/*
AES_GCM的输入三要素：plaintext（必选）、tag（可选）、iv（必选）
AES_GCM的输出三要素：ciphertext（必选）、tag（必选）

GCM(Galois/Counter Mode)的意思是对称加密采用Counter模式,并带有GMAC消息认证码
 */

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <tommath.h>
#include <tomcrypt.h>

void encrypt(unsigned char *key, unsigned char *plain_text, int pt_len, unsigned char *cipher_text, unsigned char *iv,
             int iv_len, unsigned char *tag, unsigned long tag_len)
{
    int key_len = 32; // 256-bit key
    register_cipher(&aes_desc);
    int err = gcm_memory(find_cipher("aes"), (const unsigned char *) key, key_len, (const unsigned char *) iv, iv_len,
                         NULL, NULL, plain_text, pt_len, cipher_text, tag, &tag_len, GCM_ENCRYPT);
}

int decrypt(unsigned char *key, unsigned char *plain_text, int ct_len, unsigned char *cipher_text, unsigned char *iv,
            int iv_len, unsigned char *tag, unsigned long tag_len)
{
    int key_len = 32; // 256-bit key
    register_cipher(&aes_desc);
    int err = gcm_memory(find_cipher("aes"), (const unsigned char *) key, key_len, (const unsigned char *) iv, iv_len,
                         NULL, NULL, plain_text, ct_len, cipher_text, tag, &tag_len, GCM_DECRYPT);
}

/*
// 加密
void encrypt(unsigned char *cipher_text, unsigned char *plain_text, int pt_len, unsigned char *key, unsigned char *iv, unsigned char *tag, unsigned char *tag)
{
    int outlen;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    // 设置GCM算法模式
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    // 设置iv大小，缺省96bit(12byte)
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_ivLEN, 12, NULL);
    // 设置key和iv
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    // 添加tag，第二个参数为NULL时，加密函数默认第4个参数是tag待加密数据
    EVP_EncryptUpdate(ctx, NULL, &outlen, tag, 16);
    // 对明文加密
    EVP_EncryptUpdate(ctx, cipher_text, &outlen, plain_text, pt_len);
    // 这里没什么意义，不会输出
    EVP_EncryptFinal_ex(ctx, cipher_text, &outlen);
    // 获取tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    //memcpy(tag,cipher_text,16);
    EVP_CIPHER_CTX_free(ctx);
}

// 解密
void decrypt(unsigned char *plain_text, unsigned char *cipher_text, int ct_len, unsigned char *key, unsigned char *iv, unsigned char *tag, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, rv;
    ctx = EVP_CIPHER_CTX_new();
    // 设置GCM算法模式
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    // 设置iv长度，缺省96bit(12byte)
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_ivLEN, 12, NULL);
    // 设置iv、key
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    // 设置tag
    EVP_DecryptUpdate(ctx, NULL, &outlen, tag, 16);
    // 解密
    EVP_DecryptUpdate(ctx, plain_text, &outlen, cipher_text, ct_len);
    // 设置预期tag值
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *) tag);
    rv = EVP_DecryptFinal_ex(ctx, plain_text, &outlen);
    // 输出解密结果，根据tag判断是否可信
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    EVP_CIPHER_CTX_free(ctx);
}
*/