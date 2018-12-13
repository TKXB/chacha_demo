//
// Created by tk on 8/21/18.
//
#include <string.h>
#include <stdio.h>
#include "prtypes.h"
#include "chacha20.h"
#include "poly1305-donna.h"

int main(void){
    unsigned char hmackey[32];   //KEY
    unsigned char mac_header[16];   //假设为header的mac值
    unsigned char mac_body[16];   //假设为body的mac值
    unsigned char mac_all[16];   //假设为poly1305(KEY, poly1305(KEY, header)+ poly1305(KEY, body))的值
    unsigned char msg[73];  //要被hmac的信息
    unsigned char msg2[88];  //要被hmac的信息
    unsigned char macbuf[32];  //poly1305(KEY, header)+ poly1305(KEY, body)

    size_t i;
    int success = poly1305_power_on_self_test();   //自测
    printf("poly1305 self test: %s\n", success ? "successful" : "failed");
    if (!success)
        return 1;
    memset(msg,65, sizeof(msg));
    memset(msg2,66, sizeof(msg2));

    unsigned char in[32] = {0};  //设为0，用于计算hmackey
    unsigned char key[32] = "0123456bbb012345678901234aaa8901";   //masterkey,ecdh阶段生成
    unsigned char nonce[8] = "12345678";  //初始向量，客户端服务端保持一致

    uint64_t counter = 0; //dataid ,counter使用dataid作为计数器
    ChaCha20XOR(hmackey, in, sizeof(in), key, nonce, counter); //生成用于计算的KEY
    for (int i = 0; i < 32; ++i) {
        printf("%02x", hmackey[i]);
    }
    printf("\n");

    poly1305_auth(mac_header, msg, sizeof(msg), hmackey);  //poly1305(KEY, header)
    for (i = 0; i < sizeof(mac_header); i++)
        printf("%02x", mac_header[i]);

    printf("\n");
    poly1305_auth(mac_body, msg2, sizeof(msg2), hmackey);  //poly1305(KEY, body)
    for (i = 0; i < sizeof(mac_body); i++)
        printf("%02x", mac_body[i]);

    printf("\n");

    memcpy(macbuf, mac_header, sizeof(mac_header));
    memcpy(&macbuf[16], mac_body, sizeof(mac_body));

    poly1305_auth(mac_all, macbuf, sizeof(macbuf), hmackey); //poly1305(KEY, poly1305(KEY, header)+ poly1305(KEY, body))
    for (i = 0; i < sizeof(mac_all); i++)
        printf("%02x", mac_all[i]);


}
