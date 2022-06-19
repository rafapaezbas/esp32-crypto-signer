# Esp32 Crypto Signer

Esp32 Crypto Signer is a public key signature esp32 firmware base on the framework [esp-idf](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/) and the cryptographic library [libsodium](https://doc.libsodium.org/).

## Setup

- In order to flash this to an esp32 microcontroller first thing to do is the setup of esp-idf. [Check this step by step tutorial](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/linux-macos-setup.html).
- Check also the documentation for [start a new project](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html#start-a-new-project).
- Install the [libsodium component](https://components.espressif.com/component/espressif/libsodium)

``` bash
idf.py add-dependency espressif/libsodium==1.0.20
```

- Copy main.c into the main folder of the project. Then:

``` bash
 idf.py build && idf.py -p /dev/ttyUSB0 flash
```

## Signature

After the flash, the esp32 will sign data sent via [UART](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver-transmitter) protocol through the USB port. 

``` bash
stty -F /dev/ttyUSB0 115200 raw -echo
cat -v /dev/ttyUSB0 &
echo -n "message" > /dev/ttyUSB0
# e738d2b53926ff6e19bc2d69366b25f3f49ca5b4869c28a806274de6f224864
```

## Key pair

The esp32 microcontroller has a memory partition for [non volatile storage](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/nvs_flash.html?highlight=nvs). This works as a key valye store. 
On every run, the program checks if a key pair has been stored in the keys __NVS_PK_KEY__ and __NVS_SK_KEY__, in case that the register is empty, it generates a new key pair and stores it. This means that under normal conditions, the key pair is genrated only once on the first run after the flash.

## Getting the public key

``` bash
stty -F /dev/ttyUSB0 115200 raw -echo
cat -v /dev/ttyUSB0 &
echo -n "__public_key__" > /dev/ttyUSB0
# 76c9558f59fe5d898729c8d083275581cd6f2f4b4394baa066cfcc578889d1
```
