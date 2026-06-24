#pragma once
#include <utils/types.h>
#include "crypto.h"

typedef struct {
    u8 master_kek[SE_KEY_128_SIZE];
    u8 master_key[SE_KEY_128_SIZE];
    u8 package2_key[SE_KEY_128_SIZE];
    u8 titlekek[SE_KEY_128_SIZE];
    u8 key_area_key_application[SE_KEY_128_SIZE];
    u8 key_area_key_ocean[SE_KEY_128_SIZE];
    u8 key_area_key_system[SE_KEY_128_SIZE];
    u8 tsec_root_key_00[SE_KEY_128_SIZE];
    u8 tsec_root_key_01[SE_KEY_128_SIZE];
} new_gen_keys_t;

// Mounts BIS, scans for NCA 0100000000000816, and — if its master_key_revision
// exceeds CURRENT_KEY_GENERATION — extracts package1 and derives new keys.
// Returns master_key_revision (positive) on success, 0 if up to date, -1 on error.
// out_mkr is set to the new master_key_revision on success, 0 otherwise.
int extract_new_gen_keys(key_storage_t *keys, new_gen_keys_t *out, int *out_mkr);
