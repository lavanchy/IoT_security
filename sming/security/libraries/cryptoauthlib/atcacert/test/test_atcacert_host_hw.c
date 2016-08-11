
#include "atcacert/atcacert_host_hw.h"
#include "test/unity.h"
#include "test/unity_fixture.h"
#include "basic/atca_basic.h"
#include <string.h>

static const uint8_t g_signer_ca_public_key[64] = {
    0x44, 0xCE, 0xAE, 0x5E, 0x80, 0x2E, 0xE7, 0x16, 0x9D, 0x77, 0xDB, 0x0A, 0x55, 0x5A, 0x38, 0xED,
    0xB2, 0x88, 0xAC, 0x73, 0x61, 0x56, 0xCA, 0x5B, 0x20, 0x0B, 0x57, 0x94, 0x7A, 0x48, 0x63, 0x50,
    0xE9, 0x72, 0xC4, 0x11, 0x3D, 0x71, 0x9A, 0xAF, 0x83, 0x72, 0x0E, 0xEF, 0x94, 0x3B, 0xDA, 0x69,
    0xD8, 0x39, 0x20, 0xD5, 0x23, 0xB8, 0x1C, 0x96, 0x49, 0x7C, 0x26, 0x62, 0x00, 0x3B, 0x7C, 0x01 };

static const uint8_t g_signer_cert_def_cert_template[] = {
	0x30, 0x82, 0x01, 0xB1, 0x30, 0x82, 0x01, 0x57, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x40,
	0x01, 0x02, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x36,
	0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x45, 0x78, 0x61, 0x6D, 0x70,
	0x6C, 0x65, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x19, 0x45, 0x78, 0x61,
	0x6D, 0x70, 0x6C, 0x65, 0x20, 0x41, 0x54, 0x45, 0x43, 0x43, 0x35, 0x30, 0x38, 0x41, 0x20, 0x52,
	0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 0x30, 0x37, 0x33, 0x31,
	0x30, 0x30, 0x31, 0x32, 0x31, 0x35, 0x5A, 0x17, 0x0D, 0x33, 0x35, 0x30, 0x37, 0x33, 0x31, 0x30,
	0x30, 0x31, 0x32, 0x31, 0x35, 0x5A, 0x30, 0x3A, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04,
	0x0A, 0x0C, 0x07, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03,
	0x55, 0x04, 0x03, 0x0C, 0x1D, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x41, 0x54, 0x45,
	0x43, 0x43, 0x35, 0x30, 0x38, 0x41, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x65, 0x72, 0x20, 0x58, 0x58,
	0x58, 0x58, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
	0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xF8, 0x0D, 0x8B,
	0x65, 0xE8, 0xBC, 0xCE, 0x14, 0x76, 0xE1, 0x8D, 0x05, 0xE2, 0x01, 0x69, 0x3B, 0xA2, 0xA6, 0x59,
	0xCF, 0xB9, 0xFD, 0x95, 0xE7, 0xBA, 0xD0, 0x21, 0x77, 0xF1, 0x38, 0x76, 0x1B, 0x34, 0xF1, 0xB3,
	0x58, 0x95, 0xA1, 0x35, 0x0D, 0x94, 0x82, 0x47, 0xE5, 0x23, 0x6F, 0xB3, 0x92, 0x01, 0x51, 0xD1,
	0x3A, 0x6F, 0x01, 0x23, 0xD6, 0x70, 0xB5, 0xE5, 0x0C, 0xE0, 0xFF, 0x49, 0x31, 0xA3, 0x50, 0x30,
	0x4E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30,
	0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x1F, 0xAF, 0x8F, 0x90, 0x86, 0x5F,
	0x7D, 0xD2, 0x26, 0xB0, 0x6F, 0xE3, 0x20, 0x4E, 0x48, 0xA5, 0xD2, 0x94, 0x65, 0xE2, 0x30, 0x1F,
	0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x77, 0x23, 0xA2, 0xC4, 0x32,
	0xA6, 0x94, 0x1D, 0x81, 0x32, 0xCB, 0x76, 0x04, 0xC3, 0x80, 0x1D, 0xD2, 0xBE, 0x95, 0x5D, 0x30,
	0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45,
	0x02, 0x20, 0x43, 0x90, 0xCD, 0x89, 0xE0, 0x75, 0xD0, 0x45, 0x93, 0x7B, 0x37, 0x3F, 0x52, 0x6F,
	0xF6, 0x5C, 0x4B, 0x4C, 0xCA, 0x7C, 0x61, 0x3C, 0x5F, 0x9C, 0xF2, 0xF4, 0xC9, 0xE7, 0xCE, 0xDF,
	0x24, 0xAA, 0x02, 0x21, 0x00, 0x89, 0x52, 0x36, 0xF3, 0xC3, 0x7C, 0xD7, 0x9D, 0x5C, 0x43, 0xF4,
	0xA9, 0x1B, 0xB3, 0xB1, 0xC7, 0x3E, 0xB2, 0x66, 0x74, 0x6C, 0x20, 0x53, 0x0A, 0x3B, 0x90, 0x77,
	0x6C, 0xA9, 0xC7, 0x79, 0x0D
};

static const uint8_t g_device_cert_def_cert_template[] = {
	0x30, 0x82, 0x01, 0x8A, 0x30, 0x82, 0x01, 0x30, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0A, 0x40,
	0x01, 0x23, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xEE, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
	0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x3A, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A,
	0x0C, 0x07, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55,
	0x04, 0x03, 0x0C, 0x1D, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x41, 0x54, 0x45, 0x43,
	0x43, 0x35, 0x30, 0x38, 0x41, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x65, 0x72, 0x20, 0x58, 0x58, 0x58,
	0x58, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 0x30, 0x37, 0x33, 0x31, 0x30, 0x30, 0x31, 0x32, 0x31,
	0x36, 0x5A, 0x17, 0x0D, 0x33, 0x35, 0x30, 0x37, 0x33, 0x31, 0x30, 0x30, 0x31, 0x32, 0x31, 0x36,
	0x5A, 0x30, 0x35, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x45, 0x78,
	0x61, 0x6D, 0x70, 0x6C, 0x65, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x18,
	0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x41, 0x54, 0x45, 0x43, 0x43, 0x35, 0x30, 0x38,
	0x41, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
	0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
	0x42, 0x00, 0x04, 0xC3, 0xDC, 0x86, 0xE9, 0xCC, 0x59, 0xA1, 0xFA, 0xF8, 0xE6, 0x02, 0xB3, 0x44,
	0x89, 0xD1, 0x70, 0x4A, 0x3B, 0x44, 0x04, 0x52, 0xAA, 0x11, 0x93, 0x35, 0xA9, 0xBE, 0x6F, 0x68,
	0x32, 0xDC, 0x59, 0xCE, 0x5E, 0x74, 0x73, 0xB8, 0x44, 0xBD, 0x08, 0x4D, 0x5D, 0x3D, 0xE5, 0xDE,
	0x21, 0xC3, 0x4F, 0x8D, 0xC1, 0x61, 0x4F, 0x17, 0x27, 0xAF, 0x6D, 0xC4, 0x9C, 0x42, 0x83, 0xEE,
	0x36, 0xE2, 0x31, 0xA3, 0x23, 0x30, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18,
	0x30, 0x16, 0x80, 0x14, 0x1F, 0xAF, 0x8F, 0x90, 0x86, 0x5F, 0x7D, 0xD2, 0x26, 0xB0, 0x6F, 0xE3,
	0x20, 0x4E, 0x48, 0xA5, 0xD2, 0x94, 0x65, 0xE2, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
	0x3D, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x5E, 0x13, 0x59, 0x05, 0x08,
	0xDA, 0x03, 0xFD, 0x94, 0x1B, 0xAF, 0xEF, 0x8A, 0x3D, 0xC8, 0x24, 0xE5, 0x49, 0x07, 0xB8, 0xA2,
	0xBD, 0x36, 0x60, 0x26, 0x14, 0x75, 0x27, 0x36, 0x66, 0xE1, 0xAA, 0x02, 0x21, 0x00, 0x96, 0xFF,
	0x2B, 0xDF, 0x34, 0x54, 0x9B, 0x7C, 0x56, 0x8F, 0x54, 0x44, 0x4F, 0xE6, 0xAD, 0x3B, 0xFE, 0x63,
	0xBD, 0xD2, 0x93, 0x65, 0xF2, 0x65, 0x59, 0x22, 0xC6, 0x25, 0x90, 0x7A, 0xEC, 0x19
};

static const atcacert_def_t g_signer_cert_def = {
	.type = CERTTYPE_X509,
	.template_id = 1,
	.chain_id = 0,
	.private_key_slot = 0,
	.sn_source = SNSRC_SIGNER_ID,
	.cert_sn_dev_loc = {
		.zone = DEVZONE_NONE,
		.slot = 0,
		.is_genkey = 0,
		.offset = 0,
		.count = 0
	},
	.issue_date_format = DATEFMT_RFC5280_UTC,
	.expire_date_format = DATEFMT_RFC5280_UTC,
	.tbs_cert_loc = {
		.offset = 4,
		.count = 347
	},
	.expire_years = 20,
	.public_key_dev_loc = {
		.zone = DEVZONE_DATA,
		.slot = 11,
		.is_genkey = 0,
		.offset = 0,
		.count = 72
	},
	.comp_cert_dev_loc = {
		.zone = DEVZONE_DATA,
		.slot = 12,
		.is_genkey = 0,
		.offset = 0,
		.count = 72
	},
	.std_cert_elements = {
		{ // STDCERT_PUBLIC_KEY
			.offset = 205,
			.count = 64
		},
		{ // STDCERT_SIGNATURE
			.offset = 363,
			.count = 73
		},
		{ // STDCERT_ISSUE_DATE
			.offset = 90,
			.count = 13
		},
		{ // STDCERT_EXPIRE_DATE
			.offset = 105,
			.count = 13
		},
		{ // STDCERT_SIGNER_ID
			.offset = 174,
			.count = 4
		},
		{ // STDCERT_CERT_SN
			.offset = 15,
			.count = 3
		},
		{ // STDCERT_AUTH_KEY_ID
			.offset = 331,
			.count = 20
		},
		{ // STDCERT_SUBJ_KEY_ID
			.offset = 298,
			.count = 20
		}
	},
	.cert_elements = NULL,
	.cert_elements_count = 0,
	.cert_template = g_signer_cert_def_cert_template,
	.cert_template_size = sizeof(g_signer_cert_def_cert_template)
};

static const atcacert_def_t g_device_cert_def = {
	.type = CERTTYPE_X509,
	.template_id = 0,
	.chain_id = 0,
	.private_key_slot = 0,
	.sn_source = SNSRC_DEVICE_SN,
	.cert_sn_dev_loc = {
		.zone = DEVZONE_NONE,
		.slot = 0,
		.is_genkey = 0,
		.offset = 0,
		.count = 0
	},
	.issue_date_format = DATEFMT_RFC5280_UTC,
	.expire_date_format = DATEFMT_RFC5280_UTC,
	.tbs_cert_loc = {
		.offset = 4,
		.count = 308
	},
	.expire_years = 20,
	.public_key_dev_loc = {
		.zone = DEVZONE_DATA,
		.slot = 0,
		.is_genkey = 1,
		.offset = 0,
		.count = 64
	},
	.comp_cert_dev_loc = {
		.zone = DEVZONE_DATA,
		.slot = 10,
		.is_genkey = 0,
		.offset = 0,
		.count = 72
	},
	.std_cert_elements = {
		{ // STDCERT_PUBLIC_KEY
			.offset = 211,
			.count = 64
		},
		{ // STDCERT_SIGNATURE
			.offset = 324,
			.count = 73
		},
		{ // STDCERT_ISSUE_DATE
			.offset = 101,
			.count = 13
		},
		{ // STDCERT_EXPIRE_DATE
			.offset = 116,
			.count = 13
		},
		{ // STDCERT_SIGNER_ID
			.offset = 93,
			.count = 4
		},
		{ // STDCERT_CERT_SN
			.offset = 15,
			.count = 10
		},
		{ // STDCERT_AUTH_KEY_ID
			.offset = 292,
			.count = 20
		},
		{ // STDCERT_SUBJ_KEY_ID
			.offset = 0,
			.count = 0
		}
	},
	.cert_elements = NULL,
	.cert_elements_count = 0,
	.cert_template = g_device_cert_def_cert_template,
	.cert_template_size = sizeof(g_device_cert_def_cert_template)
};

static const uint8_t g_signer_cert[] = {
    0x30, 0x82, 0x01, 0xB0, 0x30, 0x82, 0x01, 0x57, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x40,
    0xC4, 0x8B, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x36,
    0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x45, 0x78, 0x61, 0x6D, 0x70,
    0x6C, 0x65, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x19, 0x45, 0x78, 0x61,
    0x6D, 0x70, 0x6C, 0x65, 0x20, 0x41, 0x54, 0x45, 0x43, 0x43, 0x35, 0x30, 0x38, 0x41, 0x20, 0x52,
    0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x34, 0x30, 0x38, 0x30, 0x32,
    0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x34, 0x30, 0x38, 0x30, 0x32, 0x32,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x3A, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04,
    0x0A, 0x0C, 0x07, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0C, 0x1D, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x41, 0x54, 0x45,
    0x43, 0x43, 0x35, 0x30, 0x38, 0x41, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x65, 0x72, 0x20, 0x43, 0x34,
    0x38, 0x42, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
    0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x8B, 0x59, 0x97,
    0xE6, 0x3A, 0xD2, 0x18, 0xBF, 0xE6, 0x19, 0xD7, 0x42, 0x17, 0xD8, 0xA7, 0x79, 0x7E, 0xD4, 0x41,
    0xA8, 0x9C, 0x5E, 0x7E, 0x13, 0xAD, 0x7D, 0xA1, 0xBF, 0xA7, 0x71, 0x31, 0x6F, 0xD4, 0xFE, 0x6A,
    0x6A, 0xCD, 0x1D, 0x94, 0x3A, 0x07, 0xCD, 0x3D, 0x7D, 0xD2, 0x0C, 0xCF, 0xF6, 0xCA, 0x04, 0xFC,
    0xBC, 0x15, 0xE8, 0x6C, 0x26, 0x39, 0xE0, 0x1F, 0xAA, 0x6C, 0xA0, 0x4A, 0x12, 0xA3, 0x50, 0x30,
    0x4E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30,
    0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xD9, 0x69, 0xCE, 0x9C, 0xE4, 0x33,
    0xEF, 0x2A, 0xEF, 0xCC, 0xD8, 0x62, 0x72, 0x4A, 0x49, 0xA2, 0x1B, 0x17, 0xE5, 0xD3, 0x30, 0x1F,
    0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xFB, 0x17, 0xB4, 0x6A, 0x07,
    0xCC, 0xCE, 0x70, 0xF5, 0xF7, 0xC2, 0xD7, 0x8D, 0xDD, 0x62, 0x1A, 0x12, 0xF0, 0x9C, 0xD3, 0x30,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44,
    0x02, 0x20, 0x29, 0x09, 0xF2, 0xE2, 0xE5, 0xB1, 0xF0, 0xF1, 0xE5, 0x37, 0x90, 0x9A, 0x4D, 0x0D,
    0xCB, 0x38, 0x23, 0x0E, 0xE8, 0x5D, 0xC8, 0xF8, 0xAC, 0x07, 0x65, 0x22, 0x9E, 0x11, 0xC3, 0x95,
    0xD7, 0x96, 0x02, 0x20, 0x13, 0xBC, 0x35, 0x0A, 0x93, 0x95, 0xE8, 0xFF, 0x08, 0xFD, 0xEC, 0x51,
    0x11, 0x8D, 0xD0, 0x5F, 0xBD, 0x95, 0xE9, 0x81, 0x92, 0xB3, 0x76, 0x5D, 0xC2, 0xD4, 0xF4, 0x40,
    0xEB, 0x81, 0xE7, 0xF5 };
    
static const uint8_t g_device_cert[] = {
    0x30, 0x82, 0x01, 0x8A, 0x30, 0x82, 0x01, 0x30, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0A, 0x40,
    0x01, 0x23, 0x83, 0x32, 0xD9, 0x2C, 0xA5, 0x71, 0xEE, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x3A, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A,
    0x0C, 0x07, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0C, 0x1D, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x41, 0x54, 0x45, 0x43,
    0x43, 0x35, 0x30, 0x38, 0x41, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x65, 0x72, 0x20, 0x43, 0x34, 0x38,
    0x42, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 0x30, 0x39, 0x30, 0x33, 0x32, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x5A, 0x17, 0x0D, 0x33, 0x35, 0x30, 0x39, 0x30, 0x33, 0x32, 0x31, 0x30, 0x30, 0x30, 0x30,
    0x5A, 0x30, 0x35, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x45, 0x78,
    0x61, 0x6D, 0x70, 0x6C, 0x65, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x18,
    0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x41, 0x54, 0x45, 0x43, 0x43, 0x35, 0x30, 0x38,
    0x41, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xC7, 0x94, 0x94, 0x6A, 0x0C, 0xCB, 0x54, 0x1E, 0xFE, 0x50, 0x56, 0xA2, 0x93,
    0xC8, 0xC4, 0xC0, 0xC2, 0x41, 0xC1, 0x35, 0x78, 0xDE, 0x98, 0x19, 0x2C, 0x86, 0x11, 0x5F, 0x4E,
    0x98, 0x10, 0x38, 0xF1, 0x93, 0xCB, 0xA4, 0x81, 0x6A, 0xD8, 0x67, 0x04, 0x4E, 0x98, 0x36, 0x95,
    0x7F, 0xD6, 0xF0, 0x03, 0xA9, 0x82, 0x05, 0x3A, 0xD5, 0x5D, 0x99, 0x2A, 0xD0, 0x00, 0x2F, 0x3D,
    0xFB, 0x8B, 0xCE, 0xA3, 0x23, 0x30, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0xD9, 0x69, 0xCE, 0x9C, 0xE4, 0x33, 0xEF, 0x2A, 0xEF, 0xCC, 0xD8, 0x62,
    0x72, 0x4A, 0x49, 0xA2, 0x1B, 0x17, 0xE5, 0xD3, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x5B, 0xD0, 0xAE, 0xF5, 0x47,
    0x34, 0x5B, 0x0D, 0x6C, 0xC2, 0x2A, 0xB3, 0x67, 0x5C, 0x80, 0xC9, 0x41, 0x0D, 0x35, 0x07, 0x92,
    0xF3, 0x50, 0x12, 0x15, 0xAC, 0x33, 0xEB, 0x2B, 0x8E, 0xBB, 0x72, 0x02, 0x21, 0x00, 0x8C, 0x81,
    0xB8, 0x27, 0x09, 0x40, 0x91, 0x18, 0xF2, 0xC5, 0x15, 0x73, 0x23, 0x60, 0x42, 0x81, 0xE3, 0x61,
    0x01, 0xE4, 0x58, 0x67, 0x0A, 0x33, 0xF5, 0xDC, 0xB4, 0x0E, 0xC1, 0x60, 0x83, 0x87 };

TEST_GROUP(atcacert_host_hw);

TEST_SETUP(atcacert_host_hw)
{
    #ifdef ATCA_HAL_I2C
	atcab_init( &cfg_ateccx08a_i2c_default );
	#elif ATCA_HAL_SWI
	atcab_init( &cfg_ateccx08a_swi_default );
	#endif
}

TEST_TEAR_DOWN(atcacert_host_hw)
{
	atcab_release();
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_cert_hw)
{
    int ret = 0;
    uint8_t signer_public_key[64];
    
    // Validate signer cert against its certificate authority (CA) public key
    ret = atcacert_verify_cert_hw(&g_signer_cert_def,  g_signer_cert, sizeof(g_signer_cert), g_signer_ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    
    // Get the signer's public key from its certificate
    ret = atcacert_get_subj_public_key(&g_signer_cert_def, g_signer_cert, sizeof(g_signer_cert), signer_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    
    // Validate the device cert against its certificate authority (CA) which is the signer
    ret = atcacert_verify_cert_hw(&g_device_cert_def, g_device_cert, sizeof(g_device_cert), signer_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_cert_hw_verify_failed)
{
    int ret = 0;
    uint8_t bad_cert[sizeof(g_signer_cert)];
    size_t public_key_offset = g_signer_cert_def.std_cert_elements[STDCERT_PUBLIC_KEY].offset;
    
    memcpy(bad_cert, g_signer_cert, sizeof(bad_cert));
    
    // Change the cert public key to make the verify fail.
    bad_cert[public_key_offset]++;
    
    // Validate signer cert against its certificate authority (CA) public key
    ret = atcacert_verify_cert_hw(&g_signer_cert_def, bad_cert, sizeof(bad_cert), g_signer_ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_VERIFY_FAILED, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_cert_hw_short_cert)
{
    // Cert size is shortened so the TBS will run past the end of the cert
    int ret = atcacert_verify_cert_hw(&g_signer_cert_def,  g_signer_cert, sizeof(g_signer_cert)-100, g_signer_ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_CERT, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_cert_hw_bad_sig)
{
    int ret = 0;
    uint8_t bad_cert[sizeof(g_signer_cert)];
    
    memcpy(bad_cert, g_signer_cert, sizeof(bad_cert));
    
    // Change the signature so it doesn't decode
    bad_cert[g_signer_cert_def.std_cert_elements[STDCERT_SIGNATURE].offset]++;
    
    // Validate signer cert against its certificate authority (CA) public key
    ret = atcacert_verify_cert_hw(&g_signer_cert_def,  bad_cert, sizeof(bad_cert), g_signer_ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_DECODING_ERROR, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_cert_hw_bad_params)
{
    int ret = 0;
    
    ret = atcacert_verify_cert_hw(NULL,  g_signer_cert, sizeof(g_signer_cert), g_signer_ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_cert_hw(&g_signer_cert_def,  NULL, sizeof(g_signer_cert), g_signer_ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_cert_hw(NULL,  NULL, sizeof(g_signer_cert), g_signer_ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_cert_hw(&g_signer_cert_def,  g_signer_cert, sizeof(g_signer_cert), NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_cert_hw(NULL,  g_signer_cert, sizeof(g_signer_cert), NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_cert_hw(&g_signer_cert_def,  NULL, sizeof(g_signer_cert), NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_cert_hw(NULL,  NULL, sizeof(g_signer_cert), NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_gen_challenge_hw)
{
    int ret = 0;
    uint8_t init[32];
    uint8_t challenge1[32];
    uint8_t challenge2[32];
    
    memset(init, 0, sizeof(init));
    memcpy(challenge1, init, sizeof(challenge1));
    memcpy(challenge2, init, sizeof(challenge2));
    
    ret = atcacert_gen_challenge_hw(challenge1);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(memcmp(init, challenge1, sizeof(init)) != 0);
    
    ret = atcacert_gen_challenge_hw(challenge2);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(memcmp(init, challenge2, sizeof(init)) != 0);
    
    TEST_ASSERT(memcmp(challenge1, challenge2, sizeof(challenge1)) != 0);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_gen_challenge_hw_bad_params)
{
    int ret = atcacert_gen_challenge_hw(NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_response_hw)
{
    int ret = 0;
    const uint8_t challenge[32] = {
        0x0c, 0xa6, 0x34, 0xc8, 0x37, 0x2f, 0x87, 0x99, 0x99, 0x7e, 0x9e, 0xe9, 0xd5, 0xbc, 0x72, 0x71,
        0x84, 0xd1, 0x97, 0x0a, 0xea, 0xfe, 0xac, 0x60, 0x7e, 0xd1, 0x3e, 0x12, 0xb7, 0x32, 0x25, 0xf1 };
    const uint8_t response[64] = {  
        0x2F, 0xA2, 0x13, 0x49, 0x31, 0x26, 0x4D, 0x68, 0x7C, 0x64, 0xA7, 0xC7, 0xE3, 0x82, 0x99, 0x5C,
        0xBD, 0xE9, 0x91, 0xBD, 0x8C, 0x0E, 0xB4, 0xFA, 0x36, 0x60, 0x06, 0x01, 0xBA, 0x04, 0x75, 0x7D,
        0x3B, 0xFA, 0xA0, 0x64, 0x0B, 0x27, 0xA3, 0x45, 0xD1, 0xC9, 0x07, 0xFE, 0x12, 0xFD, 0x9A, 0xF6,
        0xFF, 0x6E, 0x38, 0x64, 0xBE, 0xCA, 0x57, 0x60, 0xE1, 0x78, 0x95, 0x59, 0x73, 0x97, 0x03, 0x44 };
    const uint8_t public_key[64] = {
        0xCC, 0x20, 0xE3, 0xCC, 0x5E, 0xD8, 0x41, 0x19, 0x63, 0xC4, 0x5C, 0x72, 0x89, 0x6C, 0xC0, 0x53,
        0x21, 0x94, 0x6A, 0x2C, 0x3D, 0x45, 0x41, 0x6F, 0x5F, 0x2B, 0x1F, 0xC3, 0xD4, 0xB2, 0x0C, 0x26,
        0x96, 0xE9, 0x18, 0x4D, 0xB7, 0x0D, 0x23, 0xFB, 0xE6, 0x11, 0xEC, 0x5B, 0xFA, 0xFC, 0x29, 0x49,
        0xA8, 0x1E, 0x64, 0x61, 0xDE, 0x07, 0xA9, 0xBE, 0x0E, 0xF9, 0x2C, 0x30, 0x89, 0x24, 0x1E, 0x34 };
    
    ret = atcacert_verify_response_hw(public_key, challenge, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_response_hw_bad_challenge)
{
    int ret = 0;
    const uint8_t challenge[32] = {
        0x0d, 0xa6, 0x34, 0xc8, 0x37, 0x2f, 0x87, 0x99, 0x99, 0x7e, 0x9e, 0xe9, 0xd5, 0xbc, 0x72, 0x71,
        0x84, 0xd1, 0x97, 0x0a, 0xea, 0xfe, 0xac, 0x60, 0x7e, 0xd1, 0x3e, 0x12, 0xb7, 0x32, 0x25, 0xf1 };
    const uint8_t response[64] = {
        0x2F, 0xA2, 0x13, 0x49, 0x31, 0x26, 0x4D, 0x68, 0x7C, 0x64, 0xA7, 0xC7, 0xE3, 0x82, 0x99, 0x5C,
        0xBD, 0xE9, 0x91, 0xBD, 0x8C, 0x0E, 0xB4, 0xFA, 0x36, 0x60, 0x06, 0x01, 0xBA, 0x04, 0x75, 0x7D,
        0x3B, 0xFA, 0xA0, 0x64, 0x0B, 0x27, 0xA3, 0x45, 0xD1, 0xC9, 0x07, 0xFE, 0x12, 0xFD, 0x9A, 0xF6,
        0xFF, 0x6E, 0x38, 0x64, 0xBE, 0xCA, 0x57, 0x60, 0xE1, 0x78, 0x95, 0x59, 0x73, 0x97, 0x03, 0x44 };
    const uint8_t public_key[64] = {
        0xCC, 0x20, 0xE3, 0xCC, 0x5E, 0xD8, 0x41, 0x19, 0x63, 0xC4, 0x5C, 0x72, 0x89, 0x6C, 0xC0, 0x53,
        0x21, 0x94, 0x6A, 0x2C, 0x3D, 0x45, 0x41, 0x6F, 0x5F, 0x2B, 0x1F, 0xC3, 0xD4, 0xB2, 0x0C, 0x26,
        0x96, 0xE9, 0x18, 0x4D, 0xB7, 0x0D, 0x23, 0xFB, 0xE6, 0x11, 0xEC, 0x5B, 0xFA, 0xFC, 0x29, 0x49,
        0xA8, 0x1E, 0x64, 0x61, 0xDE, 0x07, 0xA9, 0xBE, 0x0E, 0xF9, 0x2C, 0x30, 0x89, 0x24, 0x1E, 0x34 };
    
    ret = atcacert_verify_response_hw(public_key, challenge, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_VERIFY_FAILED, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_response_hw_bad_response)
{
    int ret = 0;
    const uint8_t challenge[32] = {
        0x0c, 0xa6, 0x34, 0xc8, 0x37, 0x2f, 0x87, 0x99, 0x99, 0x7e, 0x9e, 0xe9, 0xd5, 0xbc, 0x72, 0x71,
        0x84, 0xd1, 0x97, 0x0a, 0xea, 0xfe, 0xac, 0x60, 0x7e, 0xd1, 0x3e, 0x12, 0xb7, 0x32, 0x25, 0xf1 };
    const uint8_t response[64] = {
        0x30, 0xA2, 0x13, 0x49, 0x31, 0x26, 0x4D, 0x68, 0x7C, 0x64, 0xA7, 0xC7, 0xE3, 0x82, 0x99, 0x5C,
        0xBD, 0xE9, 0x91, 0xBD, 0x8C, 0x0E, 0xB4, 0xFA, 0x36, 0x60, 0x06, 0x01, 0xBA, 0x04, 0x75, 0x7D,
        0x3B, 0xFA, 0xA0, 0x64, 0x0B, 0x27, 0xA3, 0x45, 0xD1, 0xC9, 0x07, 0xFE, 0x12, 0xFD, 0x9A, 0xF6,
        0xFF, 0x6E, 0x38, 0x64, 0xBE, 0xCA, 0x57, 0x60, 0xE1, 0x78, 0x95, 0x59, 0x73, 0x97, 0x03, 0x44 };
    const uint8_t public_key[64] = {
        0xCC, 0x20, 0xE3, 0xCC, 0x5E, 0xD8, 0x41, 0x19, 0x63, 0xC4, 0x5C, 0x72, 0x89, 0x6C, 0xC0, 0x53,
        0x21, 0x94, 0x6A, 0x2C, 0x3D, 0x45, 0x41, 0x6F, 0x5F, 0x2B, 0x1F, 0xC3, 0xD4, 0xB2, 0x0C, 0x26,
        0x96, 0xE9, 0x18, 0x4D, 0xB7, 0x0D, 0x23, 0xFB, 0xE6, 0x11, 0xEC, 0x5B, 0xFA, 0xFC, 0x29, 0x49,
        0xA8, 0x1E, 0x64, 0x61, 0xDE, 0x07, 0xA9, 0xBE, 0x0E, 0xF9, 0x2C, 0x30, 0x89, 0x24, 0x1E, 0x34 };
    
    ret = atcacert_verify_response_hw(public_key, challenge, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_VERIFY_FAILED, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_response_hw_bad_public_key)
{
    int ret = 0;
    const uint8_t challenge[32] = {
        0x0c, 0xa6, 0x34, 0xc8, 0x37, 0x2f, 0x87, 0x99, 0x99, 0x7e, 0x9e, 0xe9, 0xd5, 0xbc, 0x72, 0x71,
        0x84, 0xd1, 0x97, 0x0a, 0xea, 0xfe, 0xac, 0x60, 0x7e, 0xd1, 0x3e, 0x12, 0xb7, 0x32, 0x25, 0xf1 };
    const uint8_t response[64] = {
        0x2F, 0xA2, 0x13, 0x49, 0x31, 0x26, 0x4D, 0x68, 0x7C, 0x64, 0xA7, 0xC7, 0xE3, 0x82, 0x99, 0x5C,
        0xBD, 0xE9, 0x91, 0xBD, 0x8C, 0x0E, 0xB4, 0xFA, 0x36, 0x60, 0x06, 0x01, 0xBA, 0x04, 0x75, 0x7D,
        0x3B, 0xFA, 0xA0, 0x64, 0x0B, 0x27, 0xA3, 0x45, 0xD1, 0xC9, 0x07, 0xFE, 0x12, 0xFD, 0x9A, 0xF6,
        0xFF, 0x6E, 0x38, 0x64, 0xBE, 0xCA, 0x57, 0x60, 0xE1, 0x78, 0x95, 0x59, 0x73, 0x97, 0x03, 0x44 };
    const uint8_t public_key[64] = {
        0x2F, 0xF3, 0xFD, 0x63, 0x14, 0x91, 0x8D, 0xAC, 0xA7, 0x47, 0x63, 0xC8, 0x63, 0x62, 0xA5, 0x8B,
        0x76, 0xAD, 0xCA, 0x5C, 0x6E, 0xDB, 0xB0, 0x93, 0x76, 0x0B, 0x0B, 0x83, 0xA6, 0x3A, 0x99, 0x8F,
        0x61, 0x10, 0xF8, 0x74, 0x34, 0x95, 0xCF, 0x33, 0x6F, 0xA4, 0xF1, 0xAB, 0xBD, 0xDE, 0x11, 0xB1,
        0xE2, 0x9E, 0x82, 0x8E, 0x8E, 0x78, 0x55, 0x32, 0x1D, 0x8D, 0x8C, 0xFA, 0x02, 0xDC, 0xCB, 0xD8 };
    
    ret = atcacert_verify_response_hw(public_key, challenge, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_VERIFY_FAILED, ret);
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_response_hw_malformed_public_key)
{
    int ret = 0;
    const uint8_t challenge[32] = {
        0x0c, 0xa6, 0x34, 0xc8, 0x37, 0x2f, 0x87, 0x99, 0x99, 0x7e, 0x9e, 0xe9, 0xd5, 0xbc, 0x72, 0x71,
        0x84, 0xd1, 0x97, 0x0a, 0xea, 0xfe, 0xac, 0x60, 0x7e, 0xd1, 0x3e, 0x12, 0xb7, 0x32, 0x25, 0xf1 };
    const uint8_t response[64] = {
        0x2F, 0xA2, 0x13, 0x49, 0x31, 0x26, 0x4D, 0x68, 0x7C, 0x64, 0xA7, 0xC7, 0xE3, 0x82, 0x99, 0x5C,
        0xBD, 0xE9, 0x91, 0xBD, 0x8C, 0x0E, 0xB4, 0xFA, 0x36, 0x60, 0x06, 0x01, 0xBA, 0x04, 0x75, 0x7D,
        0x3B, 0xFA, 0xA0, 0x64, 0x0B, 0x27, 0xA3, 0x45, 0xD1, 0xC9, 0x07, 0xFE, 0x12, 0xFD, 0x9A, 0xF6,
        0xFF, 0x6E, 0x38, 0x64, 0xBE, 0xCA, 0x57, 0x60, 0xE1, 0x78, 0x95, 0x59, 0x73, 0x97, 0x03, 0x44 };
    const uint8_t public_key[64] = {
        0xCD, 0x20, 0xE3, 0xCC, 0x5E, 0xD8, 0x41, 0x19, 0x63, 0xC4, 0x5C, 0x72, 0x89, 0x6C, 0xC0, 0x53,
        0x21, 0x94, 0x6A, 0x2C, 0x3D, 0x45, 0x41, 0x6F, 0x5F, 0x2B, 0x1F, 0xC3, 0xD4, 0xB2, 0x0C, 0x26,
        0x96, 0xE9, 0x18, 0x4D, 0xB7, 0x0D, 0x23, 0xFB, 0xE6, 0x11, 0xEC, 0x5B, 0xFA, 0xFC, 0x29, 0x49,
        0xA8, 0x1E, 0x64, 0x61, 0xDE, 0x07, 0xA9, 0xBE, 0x0E, 0xF9, 0x2C, 0x30, 0x89, 0x24, 0x1E, 0x34 };
    
    ret = atcacert_verify_response_hw(public_key, challenge, response);
    TEST_ASSERT_EQUAL(ATCA_EXECUTION_ERROR, ret); // Malformed public key results in an execution failure on the verify command
}

TEST(atcacert_host_hw, atcacert_host_hw__atcacert_verify_response_hw_bad_params)
{
    int ret = 0;
    const uint8_t challenge[32] = {
        0x0c, 0xa6, 0x34, 0xc8, 0x37, 0x2f, 0x87, 0x99, 0x99, 0x7e, 0x9e, 0xe9, 0xd5, 0xbc, 0x72, 0x71,
        0x84, 0xd1, 0x97, 0x0a, 0xea, 0xfe, 0xac, 0x60, 0x7e, 0xd1, 0x3e, 0x12, 0xb7, 0x32, 0x25, 0xf1 };
    const uint8_t response[64] = {
        0x2F, 0xA2, 0x13, 0x49, 0x31, 0x26, 0x4D, 0x68, 0x7C, 0x64, 0xA7, 0xC7, 0xE3, 0x82, 0x99, 0x5C,
        0xBD, 0xE9, 0x91, 0xBD, 0x8C, 0x0E, 0xB4, 0xFA, 0x36, 0x60, 0x06, 0x01, 0xBA, 0x04, 0x75, 0x7D,
        0x3B, 0xFA, 0xA0, 0x64, 0x0B, 0x27, 0xA3, 0x45, 0xD1, 0xC9, 0x07, 0xFE, 0x12, 0xFD, 0x9A, 0xF6,
        0xFF, 0x6E, 0x38, 0x64, 0xBE, 0xCA, 0x57, 0x60, 0xE1, 0x78, 0x95, 0x59, 0x73, 0x97, 0x03, 0x44 };
    const uint8_t public_key[64] = {
        0xCC, 0x20, 0xE3, 0xCC, 0x5E, 0xD8, 0x41, 0x19, 0x63, 0xC4, 0x5C, 0x72, 0x89, 0x6C, 0xC0, 0x53,
        0x21, 0x94, 0x6A, 0x2C, 0x3D, 0x45, 0x41, 0x6F, 0x5F, 0x2B, 0x1F, 0xC3, 0xD4, 0xB2, 0x0C, 0x26,
        0x96, 0xE9, 0x18, 0x4D, 0xB7, 0x0D, 0x23, 0xFB, 0xE6, 0x11, 0xEC, 0x5B, 0xFA, 0xFC, 0x29, 0x49,
        0xA8, 0x1E, 0x64, 0x61, 0xDE, 0x07, 0xA9, 0xBE, 0x0E, 0xF9, 0x2C, 0x30, 0x89, 0x24, 0x1E, 0x34 };
    
    ret = atcacert_verify_response_hw(NULL, challenge, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_response_hw(public_key, NULL, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_response_hw(NULL, NULL, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_response_hw(public_key, challenge, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_response_hw(NULL, challenge, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_response_hw(public_key, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
    
    ret = atcacert_verify_response_hw(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
}