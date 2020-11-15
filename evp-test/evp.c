#include <string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

int main()
{
    int ret, which = 1;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher;
    unsigned char key[24], iv[8];
    unsigned char in[100], out[108], de[100];
    int i, len, inl, outl, total = 0;

    for (i = 0; i < 24; i++) {
        memset(&key[i], i, 1);
    }

    for (i = 0; i < 8; i++) {
        memset(&iv[i], i , 1);
    }

    for (i = 0; i < 100; i++) {
        memset(&in[i], i, 1);
    }
    
    EVP_CIPHER_CTX_init(ctx);
    printf("please select:\n");
    printf("1: EVP_des_ede3_ofb\n");
    printf("2: EVP_des_ede3_cbc\n");
    scanf("%d", &which);
    if (which == 1)
        cipher = EVP_des_ede3_ofb();
    else
        cipher = EVP_des_ede3_cbc();

    ret = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    if (ret != 1) {
        printf("EVP_EncrypInit_ex err!\n");
        return -1;
    }

    inl = 50;
    len = 0;
    EVP_EncryptUpdate(ctx, out+len, &outl, in, inl);
    len += outl;
    EVP_EncryptUpdate(ctx, out+len, &outl, in+50, inl);
    len += outl;
    EVP_EncryptFinal_ex(ctx, out+len, &outl);
    len += outl;
    printf("Length of encrypt: %d\n", len);

    /* decrypt */
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_init(ctx);
    ret = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    if (ret != 1) {
        printf("EVP_DecryptInit_ex err !\n");
        return -1;
    }

    total = 0;
    EVP_DecryptUpdate(ctx, de+total, &outl, out, 44);
    total += outl;
    EVP_DecryptUpdate(ctx, de+total, &outl, out+44, len-44);
    total += outl;

    ret = EVP_DecryptFinal_ex(ctx, de+total, &outl);
    total += outl;
    if (ret != 1) {
        EVP_CIPHER_CTX_cleanup(ctx);
        printf("EVP_DecryptFinal_ex err\n");
        return -1;
    }

    if ((total != 100) || (memcmp(de, in, 100))) {
        printf("err!\n");
        return -1;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    printf("test ok!\n");

    return 0;

}
