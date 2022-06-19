#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"

static const char *NVS_PK_KEY = "NVS_PK_KEY";
static const char *NVS_SK_KEY = "NVS_SK_KEY";

unsigned char pk[crypto_sign_PUBLICKEYBYTES];
unsigned char sk[crypto_sign_SECRETKEYBYTES];

char persisted_pk[crypto_sign_PUBLICKEYBYTES + 1]; // last byte is null since value must be a zero terminated string
char persisted_sk[crypto_sign_SECRETKEYBYTES + 1];

void print_key (char *key) {
	for (int i = 0; i < 32; ++i) {
		printf("%x", key[i]);
	}
	printf("\n");
}

void initialize_nvs () {
	esp_err_t err = nvs_flash_init();
	if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		err = nvs_flash_init();
	}
	ESP_ERROR_CHECK(err);
}

esp_err_t read_pk () {
	nvs_handle_t my_handle;
	esp_err_t err = nvs_open(NVS_PK_KEY, NVS_READWRITE, &my_handle);
	size_t size = crypto_sign_PUBLICKEYBYTES + 1; 
	err = nvs_get_str(my_handle, NVS_PK_KEY, persisted_pk, &size);
	nvs_close(my_handle);
	return err;
}

esp_err_t read_sk () {
	nvs_handle_t my_handle;
	esp_err_t err = nvs_open(NVS_SK_KEY, NVS_READWRITE, &my_handle);
	size_t size = crypto_sign_SECRETKEYBYTES + 1; 
	err = nvs_get_str(my_handle, NVS_SK_KEY, persisted_sk, &size);
	nvs_close(my_handle);
	return err;
}

void persist_pk () {
	nvs_handle_t my_handle;
	esp_err_t err = nvs_open(NVS_PK_KEY, NVS_READWRITE, &my_handle);
	strncpy(persisted_pk, (char *) pk,  32);
	persisted_pk[32] = '\0'; // convert to zero terminated string
	err = nvs_set_str(my_handle, NVS_PK_KEY, persisted_pk);
        printf((err != ESP_OK) ? "Pk persist failed.\n" : "Pk persist done.\n");
	nvs_close(my_handle);
}

void persist_sk () {
	nvs_handle_t my_handle;
	esp_err_t err = nvs_open(NVS_SK_KEY, NVS_READWRITE, &my_handle);
	strncpy(persisted_sk, (char *) sk,  32);
	persisted_sk[32] = '\0'; // convert to zero terminated string
	err = nvs_set_str(my_handle, NVS_SK_KEY, persisted_sk);
        printf((err != ESP_OK) ? "Sk persist failed.\n" : "Sk persist done.\n");
	nvs_close(my_handle);
}

void app_main (void) {
	// Initialize sodium lib
	if (sodium_init() < 0) {
		printf("Sodium couldn't be initialized!\n");
	}

	initialize_nvs();
	esp_err_t err = read_pk();

	if (err == ESP_ERR_NVS_NOT_FOUND) {
		printf("Public key not found, generating and persisting new key pair...\n");
		crypto_sign_keypair(pk, sk);
		persist_pk();
		persist_sk();
	} else if (err == ESP_OK) {
		read_sk(); // assumes that if public key was found, private key is also generated
		printf("Public key found...\n");
	}

	printf("Public key: ");
	print_key(persisted_pk);
	print_key(persisted_sk);
}

