/*
 * Copyright (c) 2019-2022 shchmue
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "nca_extract.h"
#include "nca.h"
#include "fs_crypto.h"
#include "../gfx/gfx.h"
#include "../storage/emummc.h"
#include "../storage/nx_emmc.h"
#include "../storage/nx_emmc_bis.h"
#include <libs/fatfs/ff.h>
#include <mem/heap.h>
#include <sec/se.h>
#include <sec/se_t210.h>
#include <utils/list.h>
#include <utils/sprintf.h>
#include <utils/types.h>
#include <string.h>

#include "key_sources.inl"

// 0100000000000816 — system version title; its key_generation tells us the running firmware revision.
static const u8 _nca_ver_title_id[8] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x16
};
// 0100000000000819 — BootImagePackage; always key_gen=0, contains nx/package1 in its RomFS.
static const u8 _nca_pkg1_title_id[8] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x19
};

// Parsed info from NCA sectors 1 + 2 needed for CTR section reads.
typedef struct {
    u32 media_start;           // section start in 0x200-byte blocks
    u64 ivfc_content_off;      // byte offset from section start to RomFS content
    u64 ivfc_content_size;
    u8  ctr_base[16];          // AES-CTR counter value at NCA file offset 0
    u8  section_ctr_key[16];   // decrypted key area entry 2 (used for CTR)
} NcaSect0Info;

// package1_key_08 = AES_ECB_ENCRYPT(tsec_auth_signature_02, AES_ECB_DECRYPT("HOVI_ENC_KEY_PRD", hovi_kek))
static void _derive_package1_key_08(u8 *out) {
    u8 pkg1_kek[SE_KEY_128_SIZE];
    load_aes_key(KS_AES_ECB, pkg1_kek, hovi_kek, package1_kek_source_hovi);
    se_aes_key_set(KS_AES_ECB, pkg1_kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out, tsec_auth_signature_02);
}

// tsec_root_key_00/01 derived from hovi_kek for prod.keys output.
static void _derive_tsec_root_keys_sw(u8 *out_00, u8 *out_01) {
    u8 kek[SE_KEY_128_SIZE];
    se_aes_key_set(KS_AES_ECB, hovi_kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, kek, tsec_root_kek_source);
    se_aes_key_set(KS_AES_ECB, kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_00, tsec_auth_signature_00);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_01, tsec_auth_signature_01);
}

// Read and XTS-decrypt sectors 1 and 2 of the NCA at path.
// Decrypted sector 1 = NCA metadata (section table, encrypted key area).
// Decrypted sector 2 = FsHeader 0 (IVFC offsets, CTR fields).
// kak = key_area_key[0][mkr] — used to decrypt key area entry 2 for CTR.
static int _parse_nca_sect0_info(const char *path, const u8 *header_key,
                                  const u8 *kak, NcaSect0Info *out) {
    FIL fp;
    if (f_open(&fp, path, FA_READ | FA_OPEN_EXISTING) != FR_OK)
        return -1;

    // Layout: [0x000:0x200] raw sector 1, [0x200:0x400] decrypted sector 1,
    //         [0x400:0x600] raw sector 2, [0x600:0x800] decrypted sector 2.
    u8 *buf = (u8 *)malloc(0x800);
    if (!buf) { f_close(&fp); return -1; }

    UINT br;
    // Read sectors 1+2 (file bytes 0x200–0x5FF) into the raw halves.
    if (f_lseek(&fp, 0x200) != FR_OK ||
        f_read(&fp, buf, 0x400, &br) != FR_OK || br != 0x400) {
        f_close(&fp); free(buf); return -1;
    }
    f_close(&fp);

    // buf[0x000:0x200] = raw sector 1; raw sector 2 sits at buf[0x200:0x400].
    // Decrypt sector 1 → buf[0x400:0x600], sector 2 → buf[0x600:0x800].
    se_aes_key_set(KS_NCA_HDR_CRYPT, header_key,        SE_KEY_128_SIZE);
    se_aes_key_set(KS_NCA_HDR_TWEAK, header_key + 0x10, SE_KEY_128_SIZE);
    se_aes_xts_crypt(KS_NCA_HDR_TWEAK, KS_NCA_HDR_CRYPT, DECRYPT, 1, buf + 0x400, buf + 0x000, 0x200, 1);
    se_aes_xts_crypt(KS_NCA_HDR_TWEAK, KS_NCA_HDR_CRYPT, DECRYPT, 2, buf + 0x600, buf + 0x200, 0x200, 1);
    se_aes_key_clear(KS_NCA_HDR_CRYPT);
    se_aes_key_clear(KS_NCA_HDR_TWEAK);

    u8 *nca_meta = buf + 0x400; // decrypted sector 1
    u8 *fs_hdr   = buf + 0x600; // decrypted FsHeader 0

    // Section 0 media_start from the first section table entry (offset 0x040 in sector 1).
    out->media_start = *(u32 *)(nca_meta + 0x040);

    // Decrypt key area entry 2 (offset 0x120 in sector 1: 0x100 + 2*16).
    load_aes_key(KS_AES_ECB, out->section_ctr_key, kak, nca_meta + 0x120);

    // Build AES-CTR base from FsHeader 0 generation[0x140] and secureValue[0x144].
    // Python: bytearray((8 zeros) + generation + secureValue)[::-1]
    // → ctr[0..3] = secureValue BE, ctr[4..7] = generation BE, ctr[8..15] = 0.
    u8 *gen = fs_hdr + 0x140;
    u8 *sv  = fs_hdr + 0x144;
    out->ctr_base[0] = sv[3];  out->ctr_base[1] = sv[2];
    out->ctr_base[2] = sv[1];  out->ctr_base[3] = sv[0];
    out->ctr_base[4] = gen[3]; out->ctr_base[5] = gen[2];
    out->ctr_base[6] = gen[1]; out->ctr_base[7] = gen[0];
    memset(out->ctr_base + 8, 0, 8);

    // IVFC content level: max_layers at fs_hdr[0x014], levels start at fs_hdr[0x018].
    // Content level is index (max_layers-1), stored at (max_layers-2)*0x18 into the array.
    u32 max_layers = *(u32 *)(fs_hdr + 0x014);
    if (max_layers < 2) { free(buf); return -1; }
    u8 *content_level = fs_hdr + 0x018 + (max_layers - 2) * 0x18;
    out->ivfc_content_off  = *(u64 *)(content_level + 0x000);
    out->ivfc_content_size = *(u64 *)(content_level + 0x008);

    free(buf);
    return 0;
}

// Compute the AES-CTR counter for a given absolute NCA file offset.
static void _nca_ctr_at_off(u8 *ctr, const u8 *base_ctr, u64 abs_nca_off) {
    memcpy(ctr, base_ctr, 16);
    u64 block = abs_nca_off >> 4;
    for (int i = 15; i >= 8; i--, block >>= 8)
        ctr[i] = (u8)(block & 0xFF);
}

// Read and AES-CTR decrypt exactly `size` bytes (must be a multiple of 16) from
// a NCA section at byte offset `section_off` from the section's media_start.
static int _nca_ctr_read(FIL *fp, const NcaSect0Info *s,
                          u64 section_off, u32 size, u8 *out) {
    UINT br;
    u64 abs = (u64)s->media_start * 0x200 + section_off;
    if (f_lseek(fp, abs) != FR_OK) return -1;
    if (f_read(fp, out, size, &br) != FR_OK || br != size) return -1;
    u8 ctr[16];
    _nca_ctr_at_off(ctr, s->ctr_base, abs);
    se_aes_key_set(KS_AES_CTR, s->section_ctr_key, SE_KEY_128_SIZE);
    se_aes_crypt_ctr(KS_AES_CTR, out, size, out, size, ctr);
    return 0;
}

// Walk the RomFS dir/file metadata tables to locate "nx/package1".
// dir_meta / file_meta are already CTR-decrypted buffers.
// data_off is the absolute section-relative offset to the RomFS file data area.
// On success: *out_off = absolute section offset of package1 data, *out_size = file size.
static int _romfs_find_package1(const u8 *dir_meta,  u32 dir_sz,
                                 const u8 *file_meta, u32 file_sz,
                                 u64 data_off,
                                 u64 *out_off, u32 *out_size) {
    // Root dir entry is at offset 0. Its child-dir pointer is at +0x08.
    u32 child = *(u32 *)(dir_meta + 0x08);
    u32 nx_off = 0xFFFFFFFF;
    while (child != 0xFFFFFFFF) {
        if (child + 0x18 > dir_sz) break;
        u32 ns = *(u32 *)(dir_meta + child + 0x14);
        if (ns == 2 && memcmp(dir_meta + child + 0x18, "nx", 2) == 0) {
            nx_off = child;
            break;
        }
        child = *(u32 *)(dir_meta + child + 0x04); // sibling
    }
    if (nx_off == 0xFFFFFFFF) return -1;

    // Walk file list of the "nx" dir. First-file pointer is at +0x0C in dir entry.
    u32 fe = *(u32 *)(dir_meta + nx_off + 0x0C);
    while (fe != 0xFFFFFFFF) {
        if (fe + 0x20 > file_sz) break;
        u32 ns = *(u32 *)(file_meta + fe + 0x1C);
        if (ns == 8 && memcmp(file_meta + fe + 0x20, "package1", 8) == 0) {
            u64 foff = *(u64 *)(file_meta + fe + 0x08);
            *out_off  = data_off + foff;
            *out_size = (u32)(*(u64 *)(file_meta + fe + 0x10));
            return 0;
        }
        fe = *(u32 *)(file_meta + fe + 0x04); // sibling
    }
    return -1;
}

// AES-CBC decrypt the encrypted body of package1 in place.
// pkg1[0x154] = bl_size, pkg1[0x170] = IV (16 bytes), pkg1[0x180] = encrypted data.
// After decryption, pkg1[0x180..] holds: dec_data[0x10..] (first 0x10 bytes discarded).
static int _decrypt_package1_cbc(u8 *pkg1, u32 total_size, const u8 *pk08) {
    if (total_size < 0x190) return -1;
    u32 bl_size = *(u32 *)(pkg1 + 0x154);
    if (bl_size == 0 || bl_size + 0x180u > total_size) return -1;

    u8 *iv  = pkg1 + 0x170;
    u8 *enc = pkg1 + 0x180;

    u8 *dec = (u8 *)malloc(bl_size);
    if (!dec) return -1;

    se_aes_key_set(KS_AES_ECB, pk08, SE_KEY_128_SIZE);
    se_aes_iv_set(KS_AES_ECB, iv);
    se_aes_crypt_cbc(KS_AES_ECB, DECRYPT, dec, bl_size, enc, bl_size);

    // Python: package1_dec = header + decrypted_data[0x10:]
    // We skip the first 0x10 bytes of the decrypted block.
    memcpy(pkg1 + 0x180, dec + 0x10, bl_size - 0x10);
    free(dec);
    return 0;
}

// Scan the decrypted package1 for the OYASUMI magic and extract master_kek_source.
// master_kek_source is 16 bytes at (magic_end + 0x42).
static int _find_master_kek_source(const u8 *pkg1, u32 size, u8 *out) {
    static const u8 oyasumi[7] = {0x4F, 0x59, 0x41, 0x53, 0x55, 0x4D, 0x49};
    for (u32 i = 0; i + 7 + 0x42 + SE_KEY_128_SIZE <= size; i++) {
        if (memcmp(pkg1 + i, oyasumi, 7) == 0) {
            memcpy(out, pkg1 + i + 7 + 0x42, SE_KEY_128_SIZE);
            return 0;
        }
    }
    return -1;
}

// Derive all new-generation keys from master_kek_source + tsec_root_key (= tsec_root_key_02).
// Implements single_keygen_master_kek from crypto.py.
static void _derive_new_gen_keys_from_src(const u8 *new_mkek_src,
                                           const u8 *tsec_root_key,
                                           new_gen_keys_t *out) {
    // master_kek = DECRYPT(new_mkek_src, tsec_root_key)
    load_aes_key(KS_AES_ECB, out->master_kek, tsec_root_key, new_mkek_src);
    // master_key = DECRYPT(master_key_source, master_kek)
    load_aes_key(KS_AES_ECB, out->master_key, out->master_kek, master_key_source);
    // package2_key, titlekek
    load_aes_key(KS_AES_ECB, out->package2_key, out->master_key, package2_key_source);
    load_aes_key(KS_AES_ECB, out->titlekek,     out->master_key, titlekek_source);

    // key_area_key_* via generateKek chain:
    //   kek     = DECRYPT(aes_kek_generation_source, master_key)
    //   src_kek = DECRYPT(key_area_key_sources[t], kek)
    //   result  = DECRYPT(aes_key_generation_source, src_kek)
    u8 kek[SE_KEY_128_SIZE], src_kek[SE_KEY_128_SIZE];
    u8 *targets[3] = {
        out->key_area_key_application,
        out->key_area_key_ocean,
        out->key_area_key_system
    };
    for (int t = 0; t < 3; t++) {
        load_aes_key(KS_AES_ECB, kek,       out->master_key, aes_kek_generation_source);
        load_aes_key(KS_AES_ECB, src_kek,   kek,             key_area_key_sources[t]);
        load_aes_key(KS_AES_ECB, targets[t], src_kek,        aes_key_generation_source);
    }
}

// Scan bis:/Contents/registered/ for an NCA matching target_tid.
// Optionally saves its path to path_out. Returns effective master_key_revision, -1 if not found.
static int _scan_registered_find_nca(const u8 *header_key, const u8 *target_tid,
                                      char *path_out, u32 path_len) {
    DIR      dir;
    FILINFO  fno;
    NcaHeader hdr;
    char     path[128];
    int      result = -1;

    if (f_findfirst(&dir, &fno, "bis:/Contents/registered", "*") != FR_OK)
        return -1;

    while (fno.fname[0] != '\0') {
        if (fno.fattrib & AM_DIR)
            s_printf(path, "bis:/Contents/registered/%s/00", fno.fname);
        else
            s_printf(path, "bis:/Contents/registered/%s", fno.fname);

        if (ReadNcaHeader(path, header_key, &hdr) == 0 &&
            memcmp(hdr.title_id, target_tid, 8) == 0)
        {
            u8 key_gen = MAX(hdr.key_generation, hdr.crypto_type);
            result = (key_gen > 0) ? (int)(key_gen - 1) : 0;
            if (path_out && path_len > 0)
                s_printf(path_out, "%s", path);
            break;
        }

        if (f_findnext(&dir, &fno) != FR_OK)
            break;
    }

    f_closedir(&dir);
    return result;
}

int extract_new_gen_keys(key_storage_t *keys, new_gen_keys_t *out, int *out_mkr) {
    *out_mkr = 0;

    if (!emmc_storage.initialized ||
        !key_exists(keys->bis_key[2]) ||
        !key_exists(keys->header_key))
        return -1;

    if (!emummc_storage_set_mmc_partition(EMMC_GPP)) {
        EPRINTF("Unable to set partition.");
        return -1;
    }

    LIST_INIT(gpt);
    nx_emmc_gpt_parse(&gpt, &emmc_storage);

    emmc_part_t *system_part = nx_emmc_part_find(&gpt, "SYSTEM");
    if (!system_part) {
        EPRINTF("Unable to locate System partition.");
        nx_emmc_gpt_free(&gpt);
        return -1;
    }

    nx_emmc_bis_init(system_part);

    if (f_mount(&emmc_fs, "bis:", 1)) {
        EPRINTF("Unable to mount system partition.");
        nx_emmc_gpt_free(&gpt);
        return -1;
    }

    // Step 1: get firmware revision from 0100000000000816 (no path needed).
    int mkr = _scan_registered_find_nca(keys->header_key, _nca_ver_title_id, NULL, 0);

    if (mkr < 0 || mkr <= CURRENT_KEY_GENERATION) {
        f_mount(NULL, "bis:", 1);
        nx_emmc_gpt_free(&gpt);
        return (mkr < 0) ? -1 : 0;
    }
    *out_mkr = mkr;

    // Step 2: find 0100000000000819 (BootImagePackage) — always key_gen=0.
    char pkg1_nca_path[128] = {0};
    if (_scan_registered_find_nca(keys->header_key, _nca_pkg1_title_id,
                                   pkg1_nca_path, sizeof(pkg1_nca_path)) < 0) {
        EPRINTF("BootImagePackage NCA (0100000000000819) not found.");
        f_mount(NULL, "bis:", 1);
        nx_emmc_gpt_free(&gpt);
        return -1;
    }

    int result = -1;
    u8 *meta_buf = NULL;
    u8 *pkg1_buf = NULL;
    FIL nca_fp;
    bool nca_open = false;

    // Parse pkg1 NCA header — it is always encrypted with key_area_key[0][0].
    NcaSect0Info sect0;
    if (_parse_nca_sect0_info(pkg1_nca_path, keys->header_key,
                               keys->key_area_key[0][0], &sect0) < 0) {
        EPRINTF("Failed to parse NCA section 0.");
        goto done;
    }

    if (f_open(&nca_fp, pkg1_nca_path, FA_READ | FA_OPEN_EXISTING) != FR_OK) {
        EPRINTF("Failed to open NCA for streaming.");
        goto done;
    }
    nca_open = true;

    // Read and decrypt RomFS header (0x50 bytes, rounded to 0x60 for AES alignment).
    u8 romfs_hdr[0x60];
    if (_nca_ctr_read(&nca_fp, &sect0, sect0.ivfc_content_off, sizeof(romfs_hdr), romfs_hdr) < 0) {
        EPRINTF("Failed to read RomFS header.");
        goto done;
    }

    u64 dir_meta_off  = *(u64 *)(romfs_hdr + 0x18);
    u64 dir_meta_size = *(u64 *)(romfs_hdr + 0x20);
    u64 file_meta_off = *(u64 *)(romfs_hdr + 0x38);
    u64 file_meta_size= *(u64 *)(romfs_hdr + 0x40);
    u64 data_off      = *(u64 *)(romfs_hdr + 0x48);

    if (dir_meta_size == 0 || file_meta_size == 0) {
        EPRINTF("RomFS metadata tables are empty.");
        goto done;
    }

    u32 dir_sz  = ((u32)dir_meta_size  + 15) & ~15u;
    u32 file_sz = ((u32)file_meta_size + 15) & ~15u;

    meta_buf = (u8 *)malloc(dir_sz + file_sz);
    if (!meta_buf) goto done;

    if (_nca_ctr_read(&nca_fp, &sect0,
                       sect0.ivfc_content_off + dir_meta_off,
                       dir_sz, meta_buf) < 0) {
        EPRINTF("Failed to read RomFS dir metadata.");
        goto done;
    }
    if (_nca_ctr_read(&nca_fp, &sect0,
                       sect0.ivfc_content_off + file_meta_off,
                       file_sz, meta_buf + dir_sz) < 0) {
        EPRINTF("Failed to read RomFS file metadata.");
        goto done;
    }

    u64 pkg1_off;
    u32 pkg1_size;
    if (_romfs_find_package1(meta_buf, dir_sz,
                              meta_buf + dir_sz, file_sz,
                              sect0.ivfc_content_off + data_off,
                              &pkg1_off, &pkg1_size) < 0) {
        EPRINTF("nx/package1 not found in RomFS.");
        goto done;
    }

    u32 pkg1_padded = (pkg1_size + 15) & ~15u;
    pkg1_buf = (u8 *)malloc(pkg1_padded);
    if (!pkg1_buf) goto done;
    memset(pkg1_buf, 0, pkg1_padded);

    if (_nca_ctr_read(&nca_fp, &sect0, pkg1_off, pkg1_padded, pkg1_buf) < 0) {
        EPRINTF("Failed to read package1.");
        goto done;
    }

    u8 pkg1_key[SE_KEY_128_SIZE];
    _derive_package1_key_08(pkg1_key);

    if (_decrypt_package1_cbc(pkg1_buf, pkg1_padded, pkg1_key) < 0) {
        EPRINTF("Failed to decrypt package1.");
        goto done;
    }

    u8 new_mkek_src[SE_KEY_128_SIZE];
    if (_find_master_kek_source(pkg1_buf, pkg1_padded, new_mkek_src) < 0) {
        EPRINTF("OYASUMI magic not found in package1.");
        goto done;
    }

    _derive_new_gen_keys_from_src(new_mkek_src, keys->tsec_root_key, out);
    _derive_tsec_root_keys_sw(out->tsec_root_key_00, out->tsec_root_key_01);
    result = mkr;

done:
    if (pkg1_buf) free(pkg1_buf);
    if (meta_buf) free(meta_buf);
    if (nca_open) f_close(&nca_fp);
    f_mount(NULL, "bis:", 1);
    nx_emmc_gpt_free(&gpt);
    return result;
}
