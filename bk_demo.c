/*
 * Copyright 2021 Intrinsic ID B.V.  All rights reserved.
 *
 * Usage of this software is permitted under a valid written license agreement
 * between you and Intrinsic ID B.V.
 */

/*!
 * \file    bk_demo.c
 * \brief   BK-Demo entry point.
 */

#include <string.h>
#include <windows.h>
#include<stdio.h>
#include "winsock2.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "iid_target.h"
#include "iid_bk.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/


#define ID = 1;
uint8_t KEY = 0;
uint8_t KEY2 = 0;

/*! \brief Compute x divided by y, rounded up to the nearest integer value.
 */
#define CEILDIV(x,y)				(((x)+(y)-1)/(y))

/*! \brief Compute the smallest multiple of y equal or larger than x.
 */
#define INTEGERMULTIPLE(x,y)		((y)*CEILDIV((x),(y)))


/*! \brief Value indicating BK is in enrolled state.
 */
#define BK_STATUS_ENROLLED			1


/*! \brief   The BK persistent data padding size in bytes.
 *
 *  \details The padding data size of the BK persistent data. This value is calculated
 *           by calculating the difference between the smallest multiple of the nvm storage
 *           bytes larger than the activation code and status byte minus the activation code
 *           and status byte. This ensures we always write a multiple of the required write
 *           size of the nvm driver.
 *
 *  \note    If the nvm is flash, this should be multiple of the smallest amount of data
 *           that can be written to flash.
 */
#define BK_PERS_PAD_SIZE_BYTES		(INTEGERMULTIPLE((BK_AC_SIZE_BYTES + 1), IID_TARGET_NVM_WRITE_BYTES) \
									 - (BK_AC_SIZE_BYTES + 1))

/*******************************************************************************
 * Types
 ******************************************************************************/
/*!
 * \brief   Persistent data structure for BK-Demo data
 *
 * \details This structure contains the persistent data required by the BK-Demo application only.
 *          This structure includes the mandatory activation code and additional data to ensure
 *          the demo will work correctly.
 *
 * \note    BK requires only the storage of the activation code. Additional data is only added
 *          to ensure the correct working of this demo.
 *
 * \note    The size of the padding depends on the flash geometry. It is calculated compile time
 *          assuming the define #IID_TARGET_NVM_WRITE_BYTES has been filed appropriately.
 */
typedef struct bk_persistent_data_u {
	PRE_ALIGN uint8_t activation_code[BK_AC_SIZE_BYTES] POST_ALIGN;
	uint8_t status;
	uint8_t padding[BK_PERS_PAD_SIZE_BYTES];
} bk_persistent_data_t;


/*******************************************************************************
 * Variables
 ******************************************************************************/
/*! \brief   The linker script defined symbol identifying the PUF SRAM.
 *
 *  \details The start of the PUF used SRAM defined as a symbol in the linker script.
 *           By using a symbol defined in the linker script, we remove the responsibility
 *           of the developer to maintain the correct address in this source file.
 */
extern uint8_t __base_PUF;

/*! \brief   Variable pointing to the PUF SRAM.
 *
 *  \details This variable contains the start address of the PUF SRAM. It's value
 *           is the address of the linker script defined __base_PUF symbol, which
 *           is located at the start of the PUF SRAM.
 */
static uint8_t * PUF = (uint8_t *)&__base_PUF;

/*!
 * \brief   BK-Demo data persistent data
 *
 * \details Instance of the persistent data required for the BK-Demo. This instance must
 *          be read immediately after start before calling bK-enroll or bk_start.
 *
 * \note    The structure must be aligned according to the NVM alignment requirements
 *          as defined by #IID_TARGET_NVM_DATA_ALIGNMENT
 */
bk_persistent_data_t nvm_bk_data __attribute__ ((aligned IID_TARGET_NVM_DATA_ALIGNMENT)) = { 0 };



/* external or "other" public key used in examples */
const uint8_t external_public_key[] = {
		0x04,
		0xbc, 0x67, 0xfd, 0x60, 0x0f, 0x5e, 0x3a, 0x3d,
		0xc6, 0x9b, 0x8f, 0x98, 0xf8, 0xc0, 0x89, 0x64,
		0x2c, 0x12, 0x46, 0x4c, 0x72, 0x54, 0xd1, 0x03,
		0x6c, 0x0a, 0xcf, 0x09, 0x2e, 0x4e, 0x5b, 0x10,
		0x0f, 0x51, 0xed, 0x98, 0xe5, 0x7b, 0x46, 0xe7,
		0x49, 0xf5, 0xcd, 0x17, 0x75, 0x21, 0xc5, 0x4b,
		0x0e, 0xc4, 0x7d, 0xfd, 0x14, 0x28, 0x71, 0xcf,
		0xf9, 0xff, 0xd7, 0x59, 0xf2, 0x69, 0x50, 0x3c };

static const char b64_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
		'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
		'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
		'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
		'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static void b64_encode3bytes(uint8_t *result, uint8_t *buf, uint8_t bytes_to_encode) {
	if (bytes_to_encode == 3) {
		result[0] = b64_table[(buf[0] & 0xfc) >> 2];
		result[1] = b64_table[((buf[0] & 0x03) << 4) + ((buf[1] & 0xf0) >> 4)];
		result[2] = b64_table[((buf[1] & 0x0f) << 2) + ((buf[2] & 0xc0) >> 6)];
		result[3] = b64_table[buf[2] & 0x3f];
	} else if (bytes_to_encode == 2) {
		result[0] = b64_table[(buf[0] & 0xfc) >> 2];
		result[1] = b64_table[((buf[0] & 0x03) << 4) + ((buf[1] & 0xf0) >> 4)];
		result[2] = b64_table[((buf[1] & 0x0f) << 2)];
		result[3] = '=';
	} else if (bytes_to_encode == 1) {
		result[0] = b64_table[(buf[0] & 0xfc) >> 2];
		result[1] = b64_table[((buf[0] & 0x03) << 4)];
		result[2] = '=';
		result[3] = '=';
	} else {
		PRINTF("b64_encode3bytes(): invalid bytes_to_encode %d, should be 0 < b < 4", bytes_to_encode);
	}
}


/* print BK enrollment status */
static void status(void) {
	if (nvm_bk_data.status == BK_STATUS_ENROLLED) {
		PRINTF("This device is enrolled\r\n\r\n");
		target_led_control(led_green, true);
		target_led_control(led_red, false);
	} else {
		PRINTF("This device is not enrolled\r\n\r\n");
		target_led_control(led_green, false);
		target_led_control(led_red, true);
	}
}

/* wipe the flash and clear the internal administration */
static void wipe_device(void) {
	target_nvm_clear();

	memset(&nvm_bk_data, 0, sizeof(nvm_bk_data));

	status();

	PRINTF("Please re-power the device. BK can be enrolled only once during its life cycle.\r\n");
}

/* enroll BK and store activation code in flash */
static void enroll(void) {
	iid_return_t iid_retval;

	iid_retval = bk_enroll(nvm_bk_data.activation_code);

	PRINTF("bk_enroll() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS != iid_retval) {
		if (IID_NOT_ALLOWED == iid_retval) {
			PRINTF("Please wipe and re-power the device. BK can be enrolled only once during its life cycle.\r\n");
		}
		return;
	}

	nvm_bk_data.status = BK_STATUS_ENROLLED;
	target_nvm_write((uint32_t *)&nvm_bk_data, sizeof(bk_persistent_data_t));
	status();
}

static void start(void) {
	iid_return_t iid_retval;

	iid_retval = bk_start(nvm_bk_data.activation_code);

	PRINTF("bk_start() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		target_led_control(led_blue, true);
	}
}

static void stop(void) {
	iid_return_t iid_retval;

	iid_retval = bk_stop();

	PRINTF("bk_stop() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		target_led_control(led_blue, false);
	}
}

/* helper functions to prepare device for demos */

static void require_clean_device(void) {
	if (nvm_bk_data.status == BK_STATUS_ENROLLED) {
		stop();
		wipe_device();
		status();
		PRINTF("This demo requires a clean device. \r\n");
		PRINTF("Please restart the debug session and make the same menu selections after device reset\r\n");
		PRINTF("Resetting device...\r\n");
		target_nvic_reset();
	}
}

static void require_enrolled_device(void) {
	if (nvm_bk_data.status != BK_STATUS_ENROLLED) {
		enroll();
		stop();
	}
}

/* Use cases from  BK_API_Example_Codes_V1.1 document*/

/* 2.2 Get product info and 2.3 Get version string */

static void demo_GetVersionInfo(void) {
	PRINTF("executing function %s\r\n", __func__);

	iid_return_t iid_retval;

	uint8_t product_id;
	uint8_t major;
	uint8_t minor;
	uint8_t patch;
	uint8_t build_number;

	iid_retval = bk_get_product_info(&product_id, &major, &minor, &patch, &build_number);

	PRINTF("bk_get_product_info() returned %02X\r\n\r\n", iid_retval);

	PRINTF("Product ID: %c version %d.%d.%d.%d\r\n\r\n", product_id, major, minor, patch, build_number);

	PRINTF("bk_get_version_string():\r\n");
	PRINTF("\t%s\r\n\r\n", bk_get_version_string());

}

/* 2.5 Enroll and Stop*/

static void demo_EnrollAndStop(void) {
	PRINTF("executing function %s\r\n", __func__);

	/* For bk_enroll() please take a look at the enroll() function of this program */
	enroll();

	/* For bk_stop() please take a look at the stop() function of this program */
	stop();
}

/* 2.6 Start and Stop*/

static void demo_StartAndStop(void) {
	PRINTF("executing function %s\r\n", __func__);

	/* For bk_start() please take a look at the start() function of this program */
	start();

	/* For bk_stop() please take a look at the stop() function of this program */
	stop();
}

/* 2.7 Get Key*/

static void demo_GetKey(void) {
	PRINTF("executing function %s\r\n", __func__);
	iid_return_t iid_retval;

	int i;

	uint8_t key_type = BK_SYM_KEY_TYPE_256;
	uint8_t key_index = 0;
	uint8_t key[32];

	start();

	iid_retval = bk_get_key(key_type, key_index, key);

	PRINTF("bk_get_key() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		PRINTF("get key result:\r\n");
		for (i = 0; i < sizeof(key); i += 4) {
			PRINTF("\t%02X %02X %02X %02X\r\n", key[i], key[i + 1], key[i + 2], key[i + 3]);
		}
		PRINTF("\r\n");
	}

	strcpy(KEY, key);

	stop();
}

/* 2.8 Generate Random*/

static void demo_GenerateRandom(void) {
	PRINTF("executing function %s\r\n", __func__);
	iid_return_t iid_retval;

	int i;
	uint8_t random[8];

	start();

	iid_retval = bk_generate_random(sizeof(random), random);

	PRINTF("bk_generate_random() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		PRINTF("result:\r\n");
		for (i = 0; i < sizeof(random); i += 4) {
			PRINTF("\t%02X %02X %02X %02X\r\n", random[i], random[i + 1], random[i + 2], random[i + 3]);
		}
		PRINTF("\r\n");
	}

	stop();
}

/* 2.9 Get Private Key */

static void demo_GetPrivateKey(void) {
	PRINTF("executing function %s\r\n", __func__);
	iid_return_t iid_retval;

	int i;

	PRE_ALIGN uint8_t key[BK_ECC_CURVE_SECP256R1_PRIVATE_KEY_BYTES] POST_ALIGN;

	start();

	iid_retval = bk_get_private_key(BK_ECC_CURVE_NIST_P256, NULL, 0, BK_ECC_KEY_SOURCE_PUF_DERIVED, key);

	PRINTF("bk_get_private_key() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		PRINTF("private key result:\r\n");
		for (i = 0; i < sizeof(key); i += 4) {
			PRINTF("\t%02X %02X %02X %02X\r\n", key[i], key[i + 1], key[i + 2], key[i + 3]);
		}
		PRINTF("\r\n");
	}
	strcpy(KEY2, key);


	stop();
}

/* 2.10 Wrap and Unwrap*/

static void demo_WrapAndUnwrap(void) {
	PRINTF("executing function %s\r\n", __func__);

	iid_return_t iid_retval;

	int i;

	/* key contains a key or other data that need to be protected by BK */
	PRE_ALIGN uint8_t key[32] POST_ALIGN;
	/* key_code will contain the protected key or data from the "key"-buffer */
	PRE_ALIGN uint8_t key_code[BK_USER_KEY_CODE_NONKEY_BYTES + sizeof(key)] POST_ALIGN;
	uint8_t key_index = 0;

	/* key_unwrapped will contain the key or data after unwrapping */
	PRE_ALIGN uint8_t key_unwrapped[32] POST_ALIGN;
	uint16_t key_unwrapped_length;
	uint8_t key_index_unwrapped;

	/* set the key to something human readable */
	const char keydata[] = "this is a key or data";
	memcpy(key, keydata, sizeof(keydata));

	PRINTF("going to wrap the following data: [%s]\r\n", key);

	start();

	iid_retval = bk_wrap(key_index, key, sizeof(key), key_code);

	PRINTF("bk_wrap() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		PRINTF("key code (wrapped data):\r\n");
		for (i = 0; i < sizeof(key); i += 4) {
			PRINTF("\t%02X %02X %02X %02X\r\n", key[i], key[i + 1], key[i + 2], key[i + 3]);
		}
		PRINTF("\r\n");
	} else {
		return;
	}

	stop();

	PRINTF("Unwrap key code:\r\n");

	start();

	iid_retval = bk_unwrap(key_code, key_unwrapped, &key_unwrapped_length, &key_index_unwrapped);

	PRINTF("bk_unwrap() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		PRINTF("unwrapped key:\r\n");
		PRINTF("\t[%s]\r\n", key_unwrapped);
		PRINTF("\r\n");
	}

	stop();

}

/* 2.11 Derive public key */

static void demo_DerivePublicKey(void) {
	PRINTF("executing function %s\r\n", __func__);
	iid_return_t iid_retval;

	PRE_ALIGN uint8_t private_key[BK_ECC_CURVE_SECP256R1_PRIVATE_KEY_BYTES] POST_ALIGN;

	PRE_ALIGN uint8_t public_key[BK_ECC_CURVE_SECP256R1_PUBLIC_KEY_BYTES] POST_ALIGN;

	int i;

	start();

	iid_retval = bk_get_private_key(BK_ECC_CURVE_NIST_P256, NULL, 0, BK_ECC_KEY_SOURCE_PUF_DERIVED, private_key);

	PRINTF("bk_get_private_key() returned %02X\r\n\r\n", iid_retval);

	iid_retval = bk_derive_public_key(false, BK_ECC_CURVE_NIST_P256,private_key, public_key);

	PRINTF("bk_derive_public_key() returned %02X\r\n\r\n", iid_retval);

	if (IID_SUCCESS == iid_retval) {
		PRINTF("public key:\r\n");
		PRINTF("\t%02X\r\n", public_key[0]);
		for (i = 1; i < sizeof(public_key); i += 4) {
			PRINTF("\t%02X %02X %02X %02X\r\n", public_key[i], public_key[i + 1],  public_key[i + 2], public_key[i + 3]);
		}
		PRINTF("\r\n");
	}

	stop();
}

/* 2.12 Private and public Key reconstruction*/

static void demo_ReconstructKeyPair(void) {
	PRINTF("executing function %s\r\n", __func__);

	/* for bk_create_private_key */
	PRE_ALIGN bk_ecc_private_key_code_t private_key_code POST_ALIGN;
	uint8_t usage_context[] = "My Usage Context";

	/* for bk_compute_public_from_private_key */
	PRE_ALIGN bk_ecc_public_key_code_t public_key_code POST_ALIGN;

	/* for bk_export_public_key */
	uint8_t public_key[BK_ECC_CURVE_SECP256R1_PUBLIC_KEY_BYTES];
	bk_ecc_curve_t curve_out;
	bk_ecc_key_purpose_t key_purpose_out;

	/* common */
	iid_return_t iid_retval;
	int i;

	start();

	/* create (protected) private key code */
	iid_retval = bk_create_private_key(BK_ECC_CURVE_NIST_P256,
	BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA, usage_context, sizeof(usage_context),
	BK_ECC_KEY_SOURCE_PUF_DERIVED,
	NULL, &private_key_code);

	PRINTF("bk_create_private_key() returned %02X\r\n\r\n", iid_retval);

	/* create (protected) public key */
	iid_retval = bk_compute_public_from_private_key(&private_key_code, &public_key_code);
	PRINTF("bk_compute_public_from_private_key() returned %02X\r\n\r\n", iid_retval);

	iid_retval = bk_export_public_key(
	false, /* point compression is disabled */
	&public_key_code, (uint8_t*) &public_key, &curve_out, &key_purpose_out);

	/* export (un-protect) public key */
	PRINTF("bk_export_public_key() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		PRINTF("Exported curve:       0x%02X\r\n", curve_out);
		PRINTF("Exported key_purpose: 0x%02X\r\n", key_purpose_out);
		PRINTF("Exported public key:\r\n");
		PRINTF("\t%02X\r\n", public_key[0]);
		for (i = 1; i < sizeof(public_key); i += 4) {
			PRINTF("\t%02X %02X %02X %02X\r\n", public_key[i], public_key[i + 1], public_key[i + 2], public_key[i + 3]);
		}
		PRINTF("\r\n");
	}

	stop();

	/* For demo purposes we assume the device has been power cycled at this point of the code */
	/* We now continue with re-creating the same private key */

	start();

	/* re-create (protected) private key code */
	iid_retval = bk_create_private_key(
			BK_ECC_CURVE_NIST_P256,
			BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA,
			usage_context,
			sizeof(usage_context),
			BK_ECC_KEY_SOURCE_PUF_DERIVED,
			NULL,
			&private_key_code);

	PRINTF("bk_create_private_key() returned %02X\r\n\r\n", iid_retval);

	stop();
}

/* 2.13 Import public key*/

static void demo_ImportPublicKey(void) {
	PRINTF("executing function %s\r\n", __func__);

	/* input for bk_import_public_key */
	uint8_t *public_key = (uint8_t*) external_public_key;
	bk_ecc_curve_t curve = BK_ECC_CURVE_NIST_P256;
	bk_ecc_key_purpose_t key_purpose = BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA;

	/* output */
	PRE_ALIGN bk_ecc_public_key_code_t public_key_code POST_ALIGN;

	iid_return_t iid_retval;

	start();

	/* import public key */
	iid_retval = bk_import_public_key(curve, key_purpose, (uint8_t*) public_key, &public_key_code);

	PRINTF("bk_import_public_key() returned %02X\r\n\r\n", iid_retval);

	stop();
}

/* 2.14 Sign and Verify*/

static void demo_SignAndVerify(void) {
	PRINTF("executing function %s\r\n", __func__);

	/* for bk_create_private_key */
	PRE_ALIGN bk_ecc_private_key_code_t private_key_code POST_ALIGN;
	uint8_t usage_context[] = "My Usage Context";

	/* for bk_compute_public_from_private_key */
	PRE_ALIGN bk_ecc_public_key_code_t public_key_code POST_ALIGN;

	/* for bk_ecdsa_sign and bk_ecdsa_verify */
	uint8_t message[] = "Message to sign";
	uint8_t signature[BK_ECC_CURVE_SECP256R1_SIGNATURE_BYTES];
	uint16_t signature_length = sizeof(signature);

	/* common */
	iid_return_t iid_retval;

	start();

	/** Recreate the key pair from 2.12 **/

	/* create (protected) private key code */
	iid_retval = bk_create_private_key(
			BK_ECC_CURVE_NIST_P256,
			BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA,
			usage_context,
			sizeof(usage_context),
			BK_ECC_KEY_SOURCE_PUF_DERIVED,
			NULL,
			&private_key_code);

	PRINTF("bk_create_private_key() returned %02X\r\n\r\n", iid_retval);

	/* create (protected) public key */
	iid_retval = bk_compute_public_from_private_key(&private_key_code, &public_key_code);
	PRINTF("bk_compute_public_from_private_key() returned %02X\r\n\r\n", iid_retval);

	/** sign message with private key **/

	iid_retval = bk_ecdsa_sign(
			&private_key_code,
			false, /* non-deterministic signing algorithm */
			message,
			sizeof(message),
			false, /* message is not hashed */
			signature,
			&signature_length); /* signature_length is both input and output */

	PRINTF("bk_ecdsa_sign() returned %02X\r\n\r\n", iid_retval);

	/** verify signature with public key **/

	iid_retval = bk_ecdsa_verify(
			&public_key_code,
			message,
			sizeof(message),
			false, /* message is not hashed */
			signature,
			signature_length);

	PRINTF("bk_ecdsa_verify() returned %02X\r\n\r\n", iid_retval);

	PRINTF("Change message...\r\n");
	message[1] ^= message[1];

	iid_retval = bk_ecdsa_verify(
			&public_key_code,
			message,
			sizeof(message),
			false, /* message is not hashed */
			signature,
			signature_length);

	PRINTF("bk_ecdsa_verify() should now fail (!0)\r\n");
	PRINTF("bk_ecdsa_verify() returned %02X\r\n\r\n", iid_retval);

	stop();
}

/* 2.15 ECDH Shared Secret*/

static void demo_ECDHSharedSecret(void) {
	PRINTF("executing function %s\r\n", __func__);

	/* re-using private key from 2.12 */
	PRE_ALIGN bk_ecc_private_key_code_t private_key_code POST_ALIGN;
	uint8_t usage_context[] = "My Usage Context";

	/* Re-using external public key from 1.13 */
	uint8_t *public_key = (uint8_t*) external_public_key;
	bk_ecc_curve_t curve = BK_ECC_CURVE_NIST_P256;
	bk_ecc_key_purpose_t key_purpose = BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA;
	PRE_ALIGN bk_ecc_public_key_code_t public_key_code POST_ALIGN;

	/* The shared secret */
	uint8_t shared_secret[BK_ECC_CURVE_SECP256R1_SHARED_SECRET_BYTES];

	/* common */
	iid_return_t iid_retval;
	int i;

	start();

	/* create (protected) private key code */
	iid_retval = bk_create_private_key(
			BK_ECC_CURVE_NIST_P256,
			BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA,
			usage_context,
			sizeof(usage_context),
			BK_ECC_KEY_SOURCE_PUF_DERIVED,
			NULL,
			&private_key_code);

	PRINTF("bk_create_private_key() returned %02X\r\n\r\n", iid_retval);

	/* import external public key */
	iid_retval = bk_import_public_key(curve, key_purpose, (uint8_t*) public_key, &public_key_code);

	PRINTF("bk_import_public_key() returned %02X\r\n\r\n", iid_retval);

	/* calculate shared secret */
	iid_retval = bk_ecdh_shared_secret(&private_key_code, &public_key_code, shared_secret);

	PRINTF("bk_ecdh_shared_secret() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		PRINTF("Shared secret:\r\n");
		for (i = 0; i < sizeof(shared_secret); i += 4) {
			PRINTF("\t%02X %02X %02X %02X\r\n", shared_secret[i], shared_secret[i + 1], shared_secret[i + 2], shared_secret[i + 3]);
		}
		PRINTF("\r\n");
	}

	stop();
}

/* 2.16 Generate and Process cryptogram */
/* Comments in this method assume a remote service sends an encrypted message to this device */
static void demo_GenerateAndProcessCryptogram(void) {
	PRINTF("executing function %s\r\n", __func__);

	/* local key pair */
	PRE_ALIGN bk_ecc_private_key_code_t receiver_private_key_code POST_ALIGN;
	PRE_ALIGN bk_ecc_public_key_code_t receiver_public_key_code POST_ALIGN;
	uint8_t receiver_usage_context[] = "My Usage Context";

	/* remote key pair - remote key pair should normally be used on a different device or service */
	PRE_ALIGN bk_ecc_private_key_code_t sender_private_key_code POST_ALIGN;
	uint8_t sender_usage_context[] = "I live on a server, not this device";

	/* Sender cryptogram variables */
	/* Requirement: sizeof(plaintext) % 4 == 0 */
	PRE_ALIGN uint8_t sender_plaintext[8] POST_ALIGN = { 1, 2, 3, 4, 5, 6, 7, 8 };
	PRE_ALIGN uint8_t cryptogram[BK_ECC_CRYPTOGRAM_HEADER_SIZE_BYTES + (2 * BK_ECC_CURVE_SECP256R1_PRIVATE_KEY_BYTES) + sizeof(sender_plaintext)] POST_ALIGN;
	uint32_t cryptogram_length = sizeof(cryptogram);
	PRE_ALIGN uint8_t sender_message_counter[8] POST_ALIGN = { 0 }; /* this counter should be read from and written to NVM in order to prevent replay attacks*/

	/* Receiver cryptogram variables */
	PRE_ALIGN uint8_t receiver_plaintext[sizeof(cryptogram) - (2 * BK_ECC_CURVE_SECP256R1_PRIVATE_KEY_BYTES) + BK_ECC_CRYPTOGRAM_HEADER_SIZE_BYTES] POST_ALIGN;
	uint32_t receiver_plaintext_length = sizeof(receiver_plaintext);
	/* re-use cryptogram*/
	/* re-use cryptogram_length*/
	PRE_ALIGN uint8_t receiver_message_counter[8] POST_ALIGN = { 0 }; /* this counter should be read from NVM */
	bk_ecc_std_public_key_t received_sender_public_key;
	PRE_ALIGN bk_ecc_public_key_code_t received_sender_public_key_code POST_ALIGN;
	bk_ecc_cryptogram_type_t cryptogram_type;
	iid_return_t iid_retval;

	/* Prepare the keys */
	start();

	/* sender private key code (should normally not be on this device) */
	iid_retval = bk_create_private_key(
			BK_ECC_CURVE_NIST_P256,
			BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA,
			sender_usage_context,
			sizeof(sender_usage_context),
			BK_ECC_KEY_SOURCE_RANDOM,
			NULL,
			&sender_private_key_code);
	PRINTF("bk_create_private_key() returned %02X\r\n\r\n", iid_retval);

	/* receiver private key code */
	iid_retval = bk_create_private_key(
			BK_ECC_CURVE_NIST_P256,
			BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA,
			receiver_usage_context,
			sizeof(receiver_usage_context),
			BK_ECC_KEY_SOURCE_PUF_DERIVED,
			NULL,
			&receiver_private_key_code);
	PRINTF("bk_create_private_key() returned %02X\r\n\r\n", iid_retval);

	/* receiver public key code, normally the sender would get access to this through the export_public_key method on beforehand*/
	iid_retval = bk_compute_public_from_private_key(&receiver_private_key_code,&receiver_public_key_code);
	PRINTF("bk_compute_public_from_private_key() returned %02X\r\n\r\n",iid_retval);

	stop();

	/* Generate cryptogram (imagine this happens off-device using the IID cryptogram tool)*/
	start();

	PRINTF( "encrypting %d bytes [%d...%d] expected cryptogram length: %d\r\n",
			sizeof(sender_plaintext),
			sender_plaintext[0],
			sender_plaintext[7],
			cryptogram_length);

	iid_retval = bk_generate_cryptogram(
			&receiver_public_key_code,
			&sender_private_key_code,
			BK_ECC_CRYPTOGRAM_TYPE_ECDH_STATIC,
			sender_message_counter,
			sender_plaintext,
			sizeof(sender_plaintext),
			cryptogram,
			&cryptogram_length);

	PRINTF("bk_generate_cryptogram() returned %02X\r\n\r\n", iid_retval);

	/* save sending_message_counter to NVM for it has been updated by bk_generate_cryptogram */

	stop();

	/* Now process (decrypt) the cryptogram */
	start();

	iid_retval = bk_get_public_key_from_cryptogram(
			false,
			BK_ECC_CURVE_NIST_P256,
			cryptogram,
			cryptogram_length,
			received_sender_public_key);

	PRINTF("bk_get_public_key_from_cryptogram() returned %02X\r\n\r\n", iid_retval);

	iid_retval = bk_import_public_key(
			BK_ECC_CURVE_NIST_P256,
			BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA,
			received_sender_public_key,
			&received_sender_public_key_code);

	PRINTF("bk_import_public_key() returned %02X\r\n\r\n", iid_retval);

	iid_retval = bk_process_cryptogram(
			&receiver_private_key_code,
			&received_sender_public_key_code,
			&cryptogram_type,
			receiver_message_counter,
			cryptogram,
			cryptogram_length,
			receiver_plaintext,
			&receiver_plaintext_length);

	PRINTF("bk_process_cryptogram() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS == iid_retval) {
		PRINTF("\t plaintext: [%d...%d]\r\n\r\n", receiver_plaintext[0], receiver_plaintext[7]);
	}

	/* receiver_message_counter should now be stored to NVM to prevent replay attacks */
	/* if the previously stored value of receiver_message_counter were equal or larger than the one
	 * found inside the cryptogram, the operation would have failed. */

	stop();

}

/* 2.18 Create Certificate Signing Request */

static void demo_CreateCSR(void) {
	PRINTF("executing function %s\r\n", __func__);

	/* for bk_create_private_key */
	PRE_ALIGN bk_ecc_private_key_code_t private_key_code POST_ALIGN;
	uint8_t usage_context[] = "My Usage Context";

	/* input for csr */
	bk_certificate_subject_t subject_public_key_info;

	subject_public_key_info.subject_c = "US";
	subject_public_key_info.subject_cn = "ACME SECURITY";
	subject_public_key_info.subject_o = "ACME SECURITY LLC";
	subject_public_key_info.subject_sn = "123456";

	/*create a sufficiently long buffer to hold the csr */
	uint8_t csr[1024];
	uint16_t csr_length;

	/* boilerplate */
	iid_return_t iid_retval;
	uint32_t chunk, i;
	uint8_t tmp[5] = { 0 };

	start();

	/*  create (or reconstruct) private key code */
	iid_retval = bk_create_private_key(
			BK_ECC_CURVE_NIST_P256,
			BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA,
			usage_context,
			sizeof(usage_context),
			BK_ECC_KEY_SOURCE_PUF_DERIVED,
			NULL,
			&private_key_code);

	PRINTF("bk_create_private_key() returned %02X\r\n\r\n", iid_retval);

	/* check if csr buffer is large enough */
	iid_retval = bk_maxsizeof_csr(&private_key_code, false, &subject_public_key_info, &csr_length);

	PRINTF("bk_maxsizeof_csr() returned %02X\r\n\r\n", iid_retval);
	if (IID_SUCCESS != iid_retval) {
		PRINTF("exiting...\r\n");
		stop();
		return;
	}

	if (sizeof(csr) < csr_length) {
		PRINTF("CSR buffer (%d) insufficient, require %d. Exiting... \r\n\r\n", sizeof(csr), csr_length);
		stop();
		return;
	}

	iid_retval = bk_create_csr(&private_key_code, false, &subject_public_key_info, csr, &csr_length);

	PRINTF("bk_create_csr() returned %02X\r\n\r\n", iid_retval);

	/* print csr */
	PRINTF("-----BEGIN CERTIFICATE REQUEST-----\r\n");
	i = 0;
	while (i < csr_length) {
		chunk = csr_length - i > 3 ? 3 : csr_length - i;

		b64_encode3bytes(tmp, &csr[i], chunk);
		i += chunk;

		PRINTF("%s", tmp);

		if (i != 0 && i % 48 == 0) {
			PRINTF("\r\n");
		}
	}
	PRINTF("\r\n-----END CERTIFICATE REQUEST-----\r\n");

	stop();

}

/* 2.19 Create Self signed certificate */
static void demo_CreateSSC(void) {
	PRINTF("executing function %s\r\n", __func__);

	/* for bk_create_private_key */
	PRE_ALIGN bk_ecc_private_key_code_t private_key_code POST_ALIGN;
	uint8_t usage_context[] = "My Usage Context";

	/* for Certificate */
	bk_certificate_subject_t subject_public_key_info;

	subject_public_key_info.subject_c = "US";
	subject_public_key_info.subject_cn = "ACME SECURITY";
	subject_public_key_info.subject_o = "ACME SECURITY LLC";
	subject_public_key_info.subject_sn = "123456";

	uint8_t serial[5];

	char *valid_start = "20200901000000";
	char *valid_end = "20300831235959";

	uint8_t certificate[1024];
	uint16_t certificate_length;

	/* boilerplate */
	iid_return_t iid_retval;
	uint32_t i, chunk;
	uint8_t tmp[5] = { 0 };

	start();

	/* create (protected) private key code */
	iid_retval = bk_create_private_key(
			BK_ECC_CURVE_NIST_P256,
			BK_ECC_KEY_PURPOSE_ECDH_AND_ECDSA,
			usage_context,
			sizeof(usage_context),
			BK_ECC_KEY_SOURCE_PUF_DERIVED,
			NULL,
			&private_key_code);

	PRINTF("bk_create_private_key() returned %02X\r\n\r\n", iid_retval);

	iid_retval = bk_maxsizeof_selfsigned_certificate(
			&private_key_code,
			false,
			serial,
			sizeof(serial),
			&subject_public_key_info,
			&certificate_length);

	PRINTF("bk_maxsizeof_selfsigned_certificate() returned %02X\r\n\r\n",iid_retval);
	if (IID_SUCCESS != iid_retval) {
		PRINTF("exiting...\r\n");
		stop();
		return;
	}

	if (sizeof(certificate) < certificate_length) {
		PRINTF( "Certificate buffer (%d) insufficient, require %d. Exiting... \r\n\r\n", sizeof(certificate), certificate_length);
		stop();
		return;
	}

	iid_retval = bk_create_selfsigned_certificate(
			&private_key_code,
			false,
			serial,
			sizeof(serial),
			valid_start,
			valid_end,
			&subject_public_key_info,
			certificate,
			&certificate_length);

	PRINTF("bk_create_selfsigned_certificate() returned %02Xr\n\r\n", iid_retval);

	/* print certificate */
	PRINTF("-----BEGIN CERTIFICATE -----\r\n");
	i = 0;
	while (i < certificate_length) {
		/* chunk =  min(certificate_length - i, 3) */
		chunk = certificate_length - i > 3 ? 3 : certificate_length - i;

		b64_encode3bytes(tmp, &certificate[i], chunk);
		i += chunk;

		PRINTF("%s", tmp);

		if (i != 0 && i % 48 == 0) {
			PRINTF("\r\n");
		}
	}
	PRINTF("\r\n-----END CERTIFICATE -----\r\n");

	stop();

}

unsigned char *mx_hmac_sha256(const void *key, int keylen,
                              const unsigned char *data, int datalen,
                              unsigned char *result, unsigned int *resultlen) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}


void handleHMAC(SOCKET sockfd, int step){

	unsigned char *result = NULL;
	unsigned int resultlen = -1;
	int Id = 19;


	//THIS IS FOR FIRST ITERATION

			if(step == 1){
				const unsigned char *data = (const unsigned char *)strdup(Id); //ID
				int datalen = strlen((char *)data);
				int keylen = strlen(KEY);
				result = mx_hmac_sha256((const void *)KEY, keylen, data, datalen, result, &resultlen);

							sendHmac(sockfd, result);
			}

			if(step == 2){
				const unsigned char *data = (const unsigned char *)strdup(KEY2); //ID
				int datalen = strlen((char *)data);
				int keylen = strlen(KEY);
				result = mx_hmac_sha256((const void *)KEY, keylen, data, datalen, result, &resultlen);

				sendHmac(sockfd, result);
			}

}

void sendHMAC(SOCKET sockfd, unsigned char *result){

		if( send(sockfd , result , strlen(result) , 0) < 0){
				puts("Send failed");
				return 1;
		}
			puts("Data Sent\n");
	}



void handleData(SOCKET sockfd){
	char server_reply[2000];
	int recv_size;



	//Send Commands to bk_demo
	if(iteration == 1){
		handleHMAC(sockfd, 1); //SENDS FIRST HMAC WITH ID
		bzero(buff, sizeof(buff));
			if((recv_size = recv(sockfd, server_reply, 2000, 0)) == SOCKET_ERROR);//Waits for Server Response
			{
				puts("recv failed");
			}
			puts("Reply received\n");
			server_reply[recv_size] = '\0';
			if(authenticate(sockfd, server_reply, 1)){
				iteration++;
			}else{
				printf("Error in first iteration");
			}
	}//Repeat for other iterations

	if(iteration == 2){
			handleHMAC(sockfd, 2); //SENDS FIRST HMAC WITH ID
			bzero(buff, sizeof(buff));
				if((recv_size = recv(sockfd, server_reply, 2000, 0)) == SOCKET_ERROR);//Waits for Server Response
				{
					puts("recv failed");
				}
				puts("Reply received\n");
				server_reply[recv_size] = '\0';
				if(authenticate(sockfd, server_reply, 2)){
					iteration++;
				}else{
					printf("Error in first iteration");
				}
		}
	//handle the received data and store vars in global ones to be called in authenticate
	//SAVE HMAC IN GLOBAL VAR
	//SAVE COMPONENTS OF HMAC IN GLOBAL VARIABLES


	//Return Array of Commands
	return null;
}




boolean authenticate(int sockfd, char *otherHmac, int try){
	unsigned char *result = NULL;
	unsigned int resultlen = -1;
	int Challenge = 1234567;
	if(try == 1){ //SERVER SENDS HMAC, MESSAGE IS CHALLENGE AND KEY IS KEY1   O CHALLENGE EU VOU POR UMA MERDA HARDCODED
			const unsigned char *data = (const unsigned char *)strdup(Challenge); //ID
			int datalen = strlen((char *)data);
			char *key = strdup(KEY);
			int keylen = strlen(key);
			result = mx_hmac_sha256((const void *)key, keylen, data, datalen, result, &resultlen);
			//COMPARE WITH PREVIOUSLY SAVED ONE
			if(strcmp(result, otherHmac) == 1){
				return true;
			}
			return false;
	}
	if(try == 2){//TRY 2 VAI SERVIR PARA A RESPOSTA QUE TRAZ M(A CHAVE ENCRIPTADA) PORTANTO ISTO SERA PARA DESENCRIPTAR A CHAVE QUE VEM NA MENSAGEM 2-1 A TRY 3 SERA PARA A MENSAGEM HMAC 2-2 PARA VERIFICAR SE A INTEGRIDADE DA CHAVE NAO SE FUDEU
		char *plainText = NULL; //ESTA DEVIA SER GLOBAL
		strcpy(plainText, encryptOrDecrypt(otherHmac, false));



	}





	return true;

}


char *encryptOrDecrypt(char *message, boolean encrypt){
	//encrypt = false means decrypt
	//AINDA NAO SEI ISTO
}

void ficarAMandarMsgsEncriptadas(char *message, boolean encrypt){
	//encrypt = false means decrypt
	//AINDA NAO SEI ISTO
}


/*!
 * \brief   Application entry point.
 */
int bk_demo(SOCKET sockfd) {
	char cmd;
	target_nvm_read((uint32_t *)&nvm_bk_data, sizeof(bk_persistent_data_t));

	iid_return_t retval = bk_init(PUF, BK_SRAM_PUF_SIZE_BYTES);
	PRINTF("bk_init() returned %02X\r\n\r\n", retval);

	status();

	// command loop
	while (1) {

		PRINTF("Please select application mode\r\n");
		PRINTF("Make sure to use UPPERCASE characters, lowercase characters interfere with communication.\r\n");
		PRINTF("\tPress D for demo mode and code examples.\r\n");
		PRINTF("\tPress S for Settings.\r\n\r\n");

		cmd = target_get_upper_case_char(); //CMD VAI TER OS VALORES DO HANDLE DATA

		if ('D' == cmd) {

			while (1) {
				PRINTF("Demo mode and code examples\r\n");
				PRINTF("Make sure to use UPPERCASE characters, lowercase characters interfere with communication.\r\n");
				PRINTF("\tX: Exit\r\n");
				PRINTF("\tV: Get Product info (example 2.2) and Get version string (example 2.3) \r\n");
				PRINTF("\tE: Enroll and stop (example 2.5)\r\n");
				PRINTF("\tS: Start and stop (example 2.6)\r\n");
				PRINTF("\tK: Get Key (example 2.7)\r\n");
				PRINTF("\tR: Generate Random (example 2.8) \r\n");
				PRINTF("\tP: Get private key (example 2.9) \r\n");
				PRINTF("\tW: Wrap and Unwrap (example 2.10) \r\n");
				PRINTF("\tD: Derive Public Key(example 2.11) \r\n");
				PRINTF("\tU: Private and public key reconstruction (example 2.12) \r\n");
				PRINTF("\tI: Import public key (example 2.13) \r\n");
				PRINTF("\tZ: ECDSA Sign and Verify (example 2.14) \r\n");
				PRINTF("\tH: ECDH Shared Secret (example 2.15) \r\n");
				PRINTF("\tY: Generate and Process Cryptogram (example 2.16) \r\n");
				PRINTF("\tQ: Create Certificate Signing Request (CSR) (example 2.18) \r\n");
				PRINTF("\tC: Create Self-Signed Certificate (example 2.19) \r\n");

				cmd = target_get_upper_case_char();

				if ('X' == cmd) {//EACH RETURN IS STORED IN GLOBAL VARIABLE em cada funcao vou guardar o que quero numa global para nao usar returns
					cmd = 0;
					break;
				} else if ('E' == cmd) {
					PRINTF("CMD: Enroll and stop\r\n");
					require_clean_device();
					demo_EnrollAndStop();
				} else if ('S' == cmd) {
					PRINTF("CMD: Start and stop\r\n");
					require_enrolled_device();
					demo_StartAndStop();
				} else if ('K' == cmd) {
					PRINTF("CMD: Get Key\r\n");
					require_enrolled_device();
					demo_GetKey();
				} else if ('V' == cmd) {
					PRINTF("CMD: Get product info and get version string\r\n");
					demo_GetVersionInfo();
				} else if ('R' == cmd) {
					PRINTF("CMD: Generate random\r\n");
					require_enrolled_device();
					demo_GenerateRandom();
				} else if ('P' == cmd) {
					PRINTF("CMD: Get private key\r\n");
					require_enrolled_device();
					demo_GetPrivateKey();
				} else if ('W' == cmd) {
					PRINTF("CMD: Wrap and Unwrap\r\n");
					require_enrolled_device();
					demo_WrapAndUnwrap();
				} else if ('D' == cmd) {
					PRINTF("CMD: Derive public key\r\n");
					require_enrolled_device();
					demo_DerivePublicKey();
				} else if ('U' == cmd) {
					PRINTF("CMD: Key pair reconstruction\r\n");
					require_enrolled_device();
					demo_ReconstructKeyPair();
				} else if ('I' == cmd) {
					PRINTF("CMD: Import public key\r\n");
					require_enrolled_device();
					demo_ImportPublicKey();
				} else if ('Z' == cmd) {
					PRINTF("CMD: ECDSA Sign and Verify\r\n");
					require_enrolled_device();
					demo_SignAndVerify();
				} else if ('H' == cmd) {
					PRINTF("CMD: ECDH Shared Secret\r\n");
					require_enrolled_device();
					demo_ECDHSharedSecret();
				} else if ('Y' == cmd) {
					PRINTF("CMD: Generate and Process Cryptogram\r\n");
					require_enrolled_device();
					demo_GenerateAndProcessCryptogram();
				} else if ('Q' == cmd) {
					PRINTF("CMD: Create Certificate Signing Request (CSR)\r\n");
					require_enrolled_device();
					demo_CreateCSR();
				} else if ('C' == cmd) {
					PRINTF("CMD: Create Self-Signed Certificate \r\n");
					require_enrolled_device();
					demo_CreateSSC();
				}

			}
		} else if ('S' == cmd) {
			while (1) {
				PRINTF("Settings\r\n");
				PRINTF("Make sure to use UPPERCASE characters, lowercase characters interfere with communication.\r\n");
				PRINTF("\tX: exit\r\n");
				PRINTF("\tE: enroll\r\n");
				PRINTF("\tW: wipe device\r\n");
				PRINTF("\tT: status\r\n");
				PRINTF("\tR: reset\r\n");

				cmd = target_get_upper_case_char();

				if ('X' == cmd) {
					cmd = 0;
					break;
				} else if ('E' == cmd) {
					PRINTF("CMD: enroll\r\n");
					enroll();
				} else if ('W' == cmd) {
					PRINTF("CMD: wipe device\r\n");
					wipe_device();
				} else if ('S' == cmd) {
					PRINTF("CMD: status\r\n");
					status();
				} else if ('A' == cmd) {
					PRINTF("CMD: start\r\n");
					start();
				} else if ('T' == cmd) {
					PRINTF("CMD: status\r\n");
					status();
				} else if ('R' == cmd) {
					PRINTF("CMD: reset\r\n");
					NVIC_SystemReset();
				}
			}
		}
	}
	return 0;
}
