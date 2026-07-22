#ifndef PCSC_COMMON_H
#define PCSC_COMMON_H

/* ================================================================
 *  Cross-platform PCSC abstraction
 *
 *  macOS   : native PCSC.framework  (#include <PCSC/winscard.h>)
 *  Linux   : pcsclite               (#include <PCSC/winscard.h>)
 *  Windows : WinSCard               (#include <winscard.h>)
 * ================================================================ */

#ifdef _WIN32
  #include <windows.h>
  #include <winscard.h>
  #define SLEEP_MS(ms)  Sleep((DWORD)(ms))
#else
  #include <stdio.h>
  #include <stdlib.h>
  #include <signal.h>
  #include <poll.h>
  #include <PCSC/winscard.h>
  #include <PCSC/wintypes.h>
  /* poll() provides a millisecond sleep without relying on obsolete usleep(). */
  #define SLEEP_MS(ms)  ((void)poll(NULL, 0, (int)(ms)))
#endif

/* ================================================================
 *  MIFARE Classic 1K  layout
 * ================================================================ */
#define MF1K_SECTORS              16
#define MF1K_BLOCKS_PER_SECTOR    4
#define MF1K_TOTAL_BLOCKS         (MF1K_SECTORS * MF1K_BLOCKS_PER_SECTOR)
#define MF1K_BLOCK_SIZE           16
#define MF1K_TOTAL_BYTES          (MF1K_TOTAL_BLOCKS * MF1K_BLOCK_SIZE)

#define MF1K_BLOCK_MFR            0       /* manufacturer block */
#define MF1K_SECTOR_TRAILER       3       /* trailer offset in sector */

/* ---------- sector trailer offsets ---------- */
#define TRAILER_KEY_A_OFF         0
#define TRAILER_ACCESS_BITS_OFF   6
#define TRAILER_KEY_B_OFF         10
#define ACCESS_BITS_LEN           4

/* ---------- MIFARE Crypto-1 key types ---------- */
#define MIFARE_KEY_A              0x60
#define MIFARE_KEY_B              0x61
#define MIFARE_KEY_LEN            6

/* ---------- ACR122U APDU for MIFARE Classic ---------- */
#define APDU_CLA                  0xFF
#define APDU_INS_LOAD_KEY         0x82
#define APDU_INS_AUTH             0x86
#define APDU_INS_GET_DATA         0xCA
#define APDU_INS_READ_BIN         0xB0
#define APDU_INS_UPDATE_BIN       0xD6
#define APDU_INS_VALUE_OP         0xD7

#define APDU_LOAD_KEY_SLOT_A      0x00
#define APDU_LOAD_KEY_SLOT_B      0x01
#define APDU_AUTH_KEY_NO          0x00

/* ---------- value block format ---------- */
typedef struct {
    BYTE value[4];
    BYTE valueInv[4];
    BYTE valueDup[4];
    BYTE addr;
    BYTE addrInv;
    BYTE addrDup;
    BYTE addrInvDup;
} mf1k_value_block_t;

/* ---------- access bits decoded ---------- */
typedef struct {
    BYTE raw[ACCESS_BITS_LEN];
    BYTE access_block0;   /* bits 2-0  */
    BYTE access_block1;   /* bits 6-4  */
    BYTE access_block2;   /* bits 10-8 */
    BYTE access_trailer;  /* bits 14-12 */
    BYTE user_data;       /* bit 15     */
} mf1k_access_bits_t;

/* ---------- sector trailer ---------- */
typedef struct {
    BYTE keyA[MIFARE_KEY_LEN];
    BYTE accessBits[ACCESS_BITS_LEN];
    BYTE keyB[MIFARE_KEY_LEN];
} mf1k_trailer_t;

/* ---------- door lock credential (block 4) ---------- */
#define CRED_MAGIC          "LOCK"
#define CRED_MAGIC_LEN      4
#define CRED_SECTOR         1
#define CRED_BLOCK_HDR      0
#define CRED_BLOCK_KEY      1
#define CRED_BLOCK_META     2

typedef struct {
    BYTE magic[CRED_MAGIC_LEN];     /* "LOCK" */
    BYTE cardSerial[4];
    BYTE accessLevel[2];
    BYTE reserved[6];
} cred_header_t;

typedef struct {
    BYTE credKey[8];
    BYTE reserved[8];
} cred_key_t;

typedef struct {
    BYTE issueDate[4];
    BYTE expiryDate[4];
    BYTE reserved[8];
} cred_meta_t;

/* ---------- reader / config ---------- */
#define ACR122U_VENDOR_NAME     "ACS ACR122U"
#define ACR122U_MAX_READERS     8

#define DEFAULT_KEYFILE         "keys.txt"
#define MAX_WHITELIST_KEYS      64
#define CRED_KEY_LEN            8

/* ---------- default key ---------- */
#define MF1K_DEFAULT_KEY_A      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define MF1K_DEFAULT_KEY_B      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

/* ---------- timeouts (ms) ---------- */
#define POLL_INTERVAL           200
#define CARD_REMOVAL_WAIT       2000
#define RECONNECT_WAIT          5000

/* ---------- APDU buffers ---------- */
#define APDU_MAX_LEN            255
#define APDU_RESP_MAX_LEN       (APDU_MAX_LEN + 2)

/* ---------- SCard ---------- */
#define PROTOCOL_FLAGS          (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)

/* ---------- return codes ---------- */
typedef enum {
    AUTH_SUCCESS          =  0,
    AUTH_FAIL_SIGNATURE   = -1,
    AUTH_FAIL_KEY         = -2,
    AUTH_FAIL_READ        = -3,
    AUTH_FAIL_CARD        = -4,
    AUTH_FAIL_WRITE       = -5,
    AUTH_FAIL_INVALID_BLK = -6,
    AUTH_FAIL_ACCESS      = -7,
    AUTH_FAIL_EXPIRED     = -8,
    AUTH_FAIL_MAGIC       = -9,
    AUTH_FAIL_FORMAT      = -10,
    AUTH_FAIL_NOT_IN_LIST = -11,
    AUTH_FAIL_CONFIG      = -12,
    AUTH_FAIL_UID         = -13
} auth_result_t;

#endif /* PCSC_COMMON_H */
