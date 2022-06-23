#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/uart.h"

#define TXD 1
#define RXD 3
#define UART_PORT_NUM 0
#define ECHO_UART_BAUD_RATE 115200
#define REQUEST_TASK_STACK_SIZE (8192)
#define RTS (UART_PIN_NO_CHANGE)
#define CTS (UART_PIN_NO_CHANGE)
#define BUF_SIZE (1024)

#define PK_HEADER_LEN 14
#define SCALARMULT_HEADER_LEN 14

static const char *NVS_PK_KEY = "NVS_PK_KEY";
static const char *NVS_SK_KEY = "NVS_SK_KEY";

unsigned char pk[crypto_sign_PUBLICKEYBYTES];
unsigned char sk[crypto_sign_SECRETKEYBYTES];

char persisted_pk[crypto_sign_PUBLICKEYBYTES + 1]; // last byte is null since value must be a zero terminated string
char persisted_sk[crypto_sign_SECRETKEYBYTES + 1];

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
	nvs_close(my_handle);
}

void persist_sk () {
	nvs_handle_t my_handle;
	nvs_open(NVS_SK_KEY, NVS_READWRITE, &my_handle);
	strncpy(persisted_sk, (char *) sk,  64);
	persisted_sk[64] = '\0'; // convert to zero terminated string
	nvs_set_str(my_handle, NVS_SK_KEY, persisted_sk);
	nvs_close(my_handle);
}

void sign_message (unsigned char* message, unsigned char* signature, int message_length) {
	crypto_sign_detached(signature, NULL, message, message_length, sk);
}

static void request_task (void *arg) {
	uart_config_t uart_config = {
		.baud_rate = ECHO_UART_BAUD_RATE,
		.data_bits = UART_DATA_8_BITS,
		.parity    = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
		.source_clk = UART_SCLK_DEFAULT,
	};

	int intr_alloc_flags = 0;
	ESP_ERROR_CHECK(uart_driver_install(UART_PORT_NUM, BUF_SIZE * 2, 0, 0, NULL, intr_alloc_flags));
	ESP_ERROR_CHECK(uart_param_config(UART_PORT_NUM, &uart_config));
	ESP_ERROR_CHECK(uart_set_pin(UART_PORT_NUM, TXD, RXD, RTS, CTS));

	// Configure a temporary buffer for the incoming data
	uint8_t *data = (uint8_t *) malloc(BUF_SIZE);

	while (1) {
		int length = uart_read_bytes(UART_PORT_NUM, data, (BUF_SIZE - 1), 20 / portTICK_PERIOD_MS);
		if (length) {

			if(strncmp((char *) data, "__public_key__", PK_HEADER_LEN) == 0) { // compare first (PK_HEADER_LEN) chars of data
				uart_write_bytes(UART_PORT_NUM, (const char *) pk, 32);
			}else if (strncmp((char *) data, "__scalarmult__", SCALARMULT_HEADER_LEN) == 0) {
				unsigned char k [crypto_scalarmult_SCALARBYTES];
				unsigned char output [crypto_scalarmult_SCALARBYTES];
				unsigned char sub_sk[32];
				strncpy((char *) k ,((char *) data) + SCALARMULT_HEADER_LEN, 32); // strncpy with offset of (SCALARMULT_HEADER_LER)
				strncpy((char *) sub_sk, (char *) sk, 32);
				crypto_scalarmult(output, sub_sk, pk);
				uart_write_bytes(UART_PORT_NUM, output, crypto_scalarmult_SCALARBYTES);
			} else {
				unsigned char signature [crypto_sign_BYTES];
				sign_message((unsigned char *) data, signature, length);
				uart_write_bytes(UART_PORT_NUM, signature, 64);
			}
		}
	}
}

void app_main (void) {
	sodium_init();
	initialize_nvs();
	esp_err_t err = read_pk();

	if (err == ESP_ERR_NVS_NOT_FOUND) {
		crypto_sign_keypair(pk, sk);
		persist_pk();
		persist_sk();
	} else if (err == ESP_OK) {
		read_sk(); // assumes that if public key was found, private key is also generated
		strncpy((char *) sk, persisted_sk,  64);
		strncpy((char *) pk, persisted_pk,  32);
	}

	xTaskCreate(request_task, "request_task", REQUEST_TASK_STACK_SIZE, NULL, 10, NULL);
}

