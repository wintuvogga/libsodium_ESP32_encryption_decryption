
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdint.h>
#include "esp_log.h"
#include <sodium.h>
#include "cJSON.h"

#define TAG "Main"

unsigned char secret_key[32] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
char *payload = "This is the payload. This is the payload. This is the payload. This is the payload. This is the payload. This is the payload. This is the payload. This is the payload. This is the payload. This is the payload.";

void app_main(void)
{
  ESP_LOGI(TAG, "Initializing...");

  if (sodium_init() == -1)
  {
    ESP_LOGE(TAG, "Sodium init failed");
  }
  else
  {
    ESP_LOGI(TAG, "Sodium init success");
  }

  /////////////////////////// at transmitter side //////////////////////////////////////
  // create nonce
  unsigned char nonce[crypto_secretbox_NONCEBYTES] = {};
  randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
  ESP_LOGI(TAG, "Nonce binary:");
  ESP_LOG_BUFFER_HEX(TAG, nonce, crypto_secretbox_NONCEBYTES);

  // create base64 encoded string for that nonce
  uint16_t templen = sodium_base64_ENCODED_LEN(crypto_secretbox_NONCEBYTES, sodium_base64_VARIANT_ORIGINAL);
  char *base64Nonce = malloc(templen);
  memset(base64Nonce, 0, templen);
  sodium_bin2base64(base64Nonce, templen, nonce, crypto_secretbox_NONCEBYTES, sodium_base64_VARIANT_ORIGINAL);
  ESP_LOGI(TAG, "Nonce base64: %s", base64Nonce);

  // encrypt the payload
  size_t cipherTextLength = crypto_secretbox_MACBYTES + strlen(payload);
  char *ciphertext = malloc(cipherTextLength);
  crypto_secretbox_easy((unsigned char *)ciphertext, (unsigned char *)payload, strlen(payload), nonce, secret_key);
  ESP_LOGI(TAG, "Cipher binary:");
  ESP_LOG_BUFFER_HEX(TAG, ciphertext, cipherTextLength);

  // create base64 encoded string for the payload
  templen = sodium_base64_ENCODED_LEN(cipherTextLength, sodium_base64_VARIANT_ORIGINAL);
  char *base64payload = malloc(templen);
  sodium_bin2base64(base64payload, templen, (unsigned char *)ciphertext, cipherTextLength, sodium_base64_VARIANT_ORIGINAL);
  ESP_LOGI(TAG, "Cipher base64: %s", base64payload);

  // prepare json message for transmission through MQTT or any other medium
  char *mqtt_msg_payload = malloc(4000);
  memset(mqtt_msg_payload, 0, 4000);
  cJSON *json = cJSON_CreateObject();
  cJSON_AddItemToObject(json, "nounce", cJSON_CreateString(base64Nonce));
  cJSON_AddItemToObject(json, "payload", cJSON_CreateString(base64payload));
  cJSON_PrintPreallocated(json, mqtt_msg_payload, 4000, false);
  cJSON_Delete(json);
  json = NULL;
  free(base64Nonce);
  free(base64payload);
  free(ciphertext);

  ESP_LOGI(TAG, "Final Payload to Transmit: %s", mqtt_msg_payload);

  /////////////////////////// at receiver side //////////////////////////////////////
  // first parse the received message
  cJSON *root = cJSON_Parse(mqtt_msg_payload);
  cJSON *elem = cJSON_GetObjectItem(root, "nounce");
  char *base64StringNonce = malloc(512);
  strcpy(base64StringNonce, elem->valuestring);
  elem = cJSON_GetObjectItem(root, "payload");
  char *base64StringPayload = malloc(512);
  strcpy(base64StringPayload, elem->valuestring);
  cJSON_Delete(root);
  free(mqtt_msg_payload);

  ESP_LOGI(TAG, "Parsed nounce base64: %s", base64StringNonce);
  ESP_LOGI(TAG, "Parsed payload base64: %s", base64StringPayload);

  // convert base64 to binary
  uint8_t *nonceBinary = malloc(512);
  memset(nonceBinary, 0, 512);
  size_t nonceBinaryActualLen = 0;
  sodium_base642bin(nonceBinary, 512, base64StringNonce, strlen(base64StringNonce), NULL, &nonceBinaryActualLen, NULL, sodium_base64_VARIANT_ORIGINAL);
  ESP_LOGI(TAG, "nonce binary at rx:");
  ESP_LOG_BUFFER_HEX(TAG, nonceBinary, nonceBinaryActualLen);

  uint8_t *payloadBinary = malloc(1024);
  size_t payloadBinaryActualLen = 0;
  sodium_base642bin(payloadBinary, 1024, base64StringPayload, strlen(base64StringPayload), NULL, &payloadBinaryActualLen, NULL, sodium_base64_VARIANT_ORIGINAL);
  ESP_LOGI(TAG, "payload binary at rx:");
  ESP_LOG_BUFFER_HEX(TAG, payloadBinary, payloadBinaryActualLen);

  unsigned char *decrypted = malloc(512);
  memset(decrypted, 0, 512);
  if (crypto_secretbox_open_easy(decrypted, payloadBinary, payloadBinaryActualLen, nonceBinary, secret_key) != 0)
  {
    ESP_LOGI(TAG, "Decryption failed");
  }
  else
  {
    ESP_LOGI(TAG, "payload decrypted: %s", decrypted);
  }
  free(nonceBinary);
  free(payloadBinary);
  free(decrypted);

  while (1)
  {
    vTaskDelay(1000);
  }
}
