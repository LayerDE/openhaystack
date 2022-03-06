/**
 *  OpenHaystack – Tracking personal Bluetooth devices via Apple's Find My network
 *
 *  Copyright © 2021 Secure Mobile Networking Lab (SEEMOO)
 *  Copyright © 2021 The Open Wireless Link Project
 *
 *  SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <string.h>

#include <blessed/bdaddr.h>
#include <blessed/evtloop.h>

#include "ll.h"

#include "SHA_sha256.h"
#include "uECC-handle.hpp"

static uint8_t private_key[28];
static uint8_t public_key[28];
static uint8_t private_key_init[28] = ":)";

uECC cryptohandler;

#define ADV_INTERVAL			2000000	/* 2 s */

static bdaddr_t addr = {
	{ 0xFF, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
	BDADDR_TYPE_RANDOM
};

static uint8_t offline_finding_adv_template[] = {
	0x1e, /* Length (30) */
	0xff, /* Manufacturer Specific Data (type 0xff) */
	0x4c, 0x00, /* Company ID (Apple) */
	0x12, 0x19, /* Offline Finding type and length */
	0x00, /* State */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, /* First two bits */
	0x00, /* Hint (0x00) */
};

void set_addr_from_key() {
	/* copy first 6 bytes */
	/* BLESSED seems to reorder address bytes, so we copy them in reverse order */
	addr.addr[5] = public_key[0] | 0b11000000;
	addr.addr[4] = public_key[1];
	addr.addr[3] = public_key[2];
	addr.addr[2] = public_key[3];
	addr.addr[1] = public_key[4];
	addr.addr[0] = public_key[5];
}

void fill_adv_template_from_key() {
	/* copy last 22 bytes */
	memcpy(&offline_finding_adv_template[7], &public_key[6], 22);
	/* append two bits of public key */
	offline_finding_adv_template[29] = public_key[0] >> 6;
}

int RNG(uint8_t* dest, unsigned int size){
	for(unsigned int x = 0; x < size; x++)
		dest[x] = 0;
	return 0;
}

void init(){
	memcpy(private_key, private_key_init, 28);
	cryptohandler = uECC(RNG);
	cryptohandler.compute_public_key(private_key, public_key);
}

void uart_mode(){
	while(1){

	}
}

void generate_next_key(const uint8_t* in, uint8_t* private_key, uint8_t* public_key){
	uint8_t hash[HASH_LENGTH];
	createHash(in,28,hash);
	memcpy(private_key,hash,28);
	cryptohandler.compute_public_key(private_key, public_key);
}

int main(void) {
	init();
	uint8_t empty[28];
	memset(empty,0,28);
	if(!memcmp(private_key_init,empty,28))
		uart_mode();
	set_addr_from_key();
	fill_adv_template_from_key();

	ll_init(&addr);
	ll_set_advertising_data(offline_finding_adv_template, sizeof(offline_finding_adv_template));
	ll_advertise_start(LL_PDU_ADV_NONCONN_IND, ADV_INTERVAL, LL_ADV_CH_ALL);

	evt_loop_run();

	return 0;
}
