#include "kernel.h"

int fs_server_task_id = -1;
int fs_server_listen_ep_idx = -1;

static int storage_format_sealed(struct block_device *bd, const char *password, size_t plen);
int storage_mount(struct block_device *bd);
int storage_unlock(const char *password, size_t plen);
int storage_read_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, void *buf);
int storage_write_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, const void *buf);
struct mounted_fs *storage_get_mounted_fs(void);

static void my_memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = dst; const uint8_t *s = src;
    while (n--) *d++ = *s++;
}

static void my_memset(void *dst, int val, size_t n) {
    uint8_t *d = dst; while (n--) *d++ = (uint8_t)val;
}

static size_t my_strlen(const char *s) {
    size_t len = 0; while (s[len]) len++; return len;
}

static int my_strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

static void my_strncpy(char *dst, const char *src, size_t n) {
    while (n-- && (*dst++ = *src++));
}

#define STORAGE_MAGIC   0x48534653
#define STORAGE_VERSION 5   /* v5: adds the write-ahead redo log (journal region) */

static struct virtual_disk g_vdisk;
/* Unused when STORAGE_ATA selects the ATA backend instead of the RAM vdisk. */
static uint8_t g_vdisk_buffer[BLOCKS_PER_DISK * BLOCK_SIZE] __attribute__((unused));

/* Deferred-format state: storage_init() sets this when no valid disk is found,
 * then storage_unlock() (called at first login) formats+seals with the user's
 * password so disk_key is never committed to disk without a KEK. */
static int                  g_needs_format    = 0;
static struct block_device *g_needs_format_bd = NULL;

static int vdisk_read(struct block_device *bd, uint64_t block, void *buf) {
    struct virtual_disk *vd = (struct virtual_disk *)bd->private;
    if (block >= bd->total_blocks) return -1;

    uint8_t *src = vd->data + (block * BLOCK_SIZE);
    uint8_t *d = buf;
    for (size_t i = 0; i < BLOCK_SIZE; i++) d[i] = src[i];
    return 0;
}

static int vdisk_write(struct block_device *bd, uint64_t block, const void *buf) {
    struct virtual_disk *vd = (struct virtual_disk *)bd->private;
    if (block >= bd->total_blocks) return -1;

    uint8_t *dst = vd->data + (block * BLOCK_SIZE);
    const uint8_t *s = buf;
    for (size_t i = 0; i < BLOCK_SIZE; i++) dst[i] = s[i];
    return 0;
}

static struct block_device g_vdisk_bd = {
    .name = "vdisk0",
    .total_blocks = BLOCKS_PER_DISK,
    .read_block = vdisk_read,
    .write_block = vdisk_write,
    .private = &g_vdisk,
};

static struct block_device *current_bd = &g_vdisk_bd;

#define INTENT_LOG_SLOTS 8
static struct {
    uint32_t kind;   
    uint64_t arg0;
    uint64_t arg1;
    uint32_t gen;
} intent_log[INTENT_LOG_SLOTS];
static int intent_head = 0;

static void intent_append(uint32_t kind, uint64_t a0, uint64_t a1, uint32_t gen) {
    
    intent_log[intent_head].kind = kind;
    intent_log[intent_head].arg0 = a0;
    intent_log[intent_head].arg1 = a1;
    intent_log[intent_head].gen  = gen;
    intent_head = (intent_head + 1) % INTENT_LOG_SLOTS;
}

/* Per-physical-block AEAD metadata: nonce (12), tag (16), present flag (1),
 * and 3 bytes of padding to reach exactly META_ENTRY_SIZE=32 bytes.  Packing
 * to 32 bytes lets META_ENTRIES_PER_BLOCK=16 entries fit one 512-byte sector
 * cleanly, making the on-disk metadata region exactly META_BLOCKS_COUNT=64
 * sectors.  The region is written to disk on every encrypt/free so it survives
 * across reboots; a missing or corrupt entry causes AEAD to fail closed
 * (buffer zeroed, -1 returned) rather than ever decrypting wrongly. */
struct block_crypto_meta {
    uint8_t nonce[AEAD_NONCE_LEN];   /* 12 */
    uint8_t tag[AEAD_TAG_LEN];       /* 16 */
    uint8_t present;                  /*  1 */
    uint8_t _pad[3];                  /*  3 → total 32 = META_ENTRY_SIZE */
};
_Static_assert(sizeof(struct block_crypto_meta) == META_ENTRY_SIZE,
               "block_crypto_meta must be META_ENTRY_SIZE bytes");
static struct block_crypto_meta g_block_meta[BLOCKS_PER_DISK];

/* forward declarations — defined after do_block_read/do_block_write */
static void flush_meta_block(uint64_t phys);
static void load_meta_region(struct mounted_fs *mfs);
static void update_meta_hmac(void);
static int  derive_kek(const char *password, size_t plen,
                       const uint8_t *kek_salt, uint8_t *kek32);
static void storage_fsck_pass(struct mounted_fs *mfs);

/* Per-block subkeys = HKDF-SHA256(ikm = volume_key, salt = disk_key,
 * info = "horus-block-aead-v3" || ino || block) -> enc_key(32) || mac_key(32).
 *
 * Salt changed from kernel_pepper (per-boot ephemeral) to disk_key (per-format
 * stable).  The old v2 derivation made every block undecryptable after reboot
 * because kernel_pepper changes on every boot.  disk_key is stored in the
 * superblock and survives reboots, making ATA-backed files persistent.
 *
 * Security property: keys are unknown to anyone who cannot read disk_key from
 * the superblock.  For passphrase-gated unwrapping (so disk_key itself stays
 * secret without the passphrase), wrap it with a KEK — future work. */
int storage_derive_block_keys(uint64_t ino, uint64_t block,
                              const uint8_t *vol_key, size_t vol_key_len,
                              uint8_t *enc_key32, uint8_t *mac_key32)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || !mfs->unlocked) return -1;

    uint8_t info[19 + 8 + 8];
    const char *label = "horus-block-aead-v3";
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    for (int i = 0; i < 8; i++) info[p++] = (uint8_t)(ino   >> (i * 8));
    for (int i = 0; i < 8; i++) info[p++] = (uint8_t)(block >> (i * 8));

    uint8_t okm[64];
    if (rust_hkdf_sha256(vol_key, vol_key_len,
                         mfs->disk_key, sizeof(mfs->disk_key),
                         info, p, okm, sizeof(okm)) != 0) {
        return -1;
    }
    for (int i = 0; i < 32; i++) {
        enc_key32[i] = okm[i];
        mac_key32[i] = okm[32 + i];
    }
    secure_zero(okm, sizeof(okm));
    return 0;
}

/* AAD = ino(8 LE) || block(8 LE): authenticates each block's logical location
 * so an authentic block cannot be replayed at a different (ino, block). */
static size_t storage_block_aad(uint64_t ino, uint64_t block, uint8_t *aad16)
{
    for (int i = 0; i < 8; i++) aad16[i]     = (uint8_t)(ino   >> (i * 8));
    for (int i = 0; i < 8; i++) aad16[8 + i] = (uint8_t)(block >> (i * 8));
    return 16;
}

/* Encrypt `buf` (full BLOCK_SIZE) in place with the ChaCha20 + HMAC-SHA256
 * AEAD, drawing a FRESH random nonce per write (so rewriting a block can never
 * reuse a keystream -- the two-time-pad flaw the old deterministic-nonce CTR
 * mode had), and recording (nonce,tag) in the metadata table keyed by physical
 * block. */
int storage_encrypt_block(uint64_t phys, uint64_t ino, uint64_t block, void *buf)
{
    if (phys >= BLOCKS_PER_DISK) return -1;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || !mfs->unlocked) return -1;

    uint8_t enc_key[32], mac_key[32];
    uint8_t nonce[AEAD_NONCE_LEN], tag[AEAD_TAG_LEN], aad[16];

    spin_lock(&storage_lock);
    int rc = storage_derive_block_keys(ino, block, mfs->volume_key,
                                       sizeof(mfs->volume_key), enc_key, mac_key);
    if (rc != 0) {
        spin_unlock(&storage_lock);
        return rc;
    }

    secure_random_bytes(nonce, sizeof(nonce));
    size_t aad_len = storage_block_aad(ino, block, aad);

    rc = rust_aead_seal(enc_key, mac_key, nonce, aad, aad_len,
                        (uint8_t *)buf, BLOCK_SIZE, tag);
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    if (rc != 0) {
        spin_unlock(&storage_lock);
        return -1;
    }

    for (int i = 0; i < AEAD_NONCE_LEN; i++) g_block_meta[phys].nonce[i] = nonce[i];
    for (int i = 0; i < AEAD_TAG_LEN; i++)   g_block_meta[phys].tag[i]   = tag[i];
    g_block_meta[phys].present = 1;
    /* Persist nonce+tag to disk immediately so they survive a reboot.
     * Written before the caller writes the ciphertext block: a crash between
     * here and the data write leaves new-meta / old-ciphertext, which the
     * AEAD rejects (fail-closed), never silently serving stale plaintext. */
    flush_meta_block(phys);
    spin_unlock(&storage_lock);
    return 0;
}

/* Verify + decrypt `buf` (full BLOCK_SIZE) in place. Loads the per-block
 * (nonce,tag) recorded at encrypt time; a block never written through the AEAD,
 * or one whose tag/AAD/key no longer matches, fails closed (buf zeroed). */
int storage_decrypt_block(uint64_t phys, uint64_t ino, uint64_t block, void *buf)
{
    if (phys >= BLOCKS_PER_DISK) { secure_zero(buf, BLOCK_SIZE); return -1; }
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || !mfs->unlocked) { secure_zero(buf, BLOCK_SIZE); return -1; }

    uint8_t enc_key[32], mac_key[32];
    uint8_t nonce[AEAD_NONCE_LEN], tag[AEAD_TAG_LEN], aad[16];

    spin_lock(&storage_lock);
    if (!g_block_meta[phys].present) {
        spin_unlock(&storage_lock);
        secure_zero(buf, BLOCK_SIZE);
        return -1;
    }
    for (int i = 0; i < AEAD_NONCE_LEN; i++) nonce[i] = g_block_meta[phys].nonce[i];
    for (int i = 0; i < AEAD_TAG_LEN; i++)   tag[i]   = g_block_meta[phys].tag[i];

    int rc = storage_derive_block_keys(ino, block, mfs->volume_key,
                                       sizeof(mfs->volume_key), enc_key, mac_key);
    if (rc != 0) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        spin_unlock(&storage_lock);
        secure_zero(buf, BLOCK_SIZE);
        return rc;
    }

    size_t aad_len = storage_block_aad(ino, block, aad);
    rc = rust_aead_open(enc_key, mac_key, nonce, aad, aad_len,
                        (uint8_t *)buf, BLOCK_SIZE, tag);
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    spin_unlock(&storage_lock);
    /* rust_aead_open zeroes buf itself on authentication failure. */
    return (rc == 0) ? 0 : -1;
}

struct block_device *storage_get_default_device(void) {
    return current_bd;
}

void storage_set_default_device(struct block_device *bd) {
    if (bd) current_bd = bd;
}

/* Raw block transport. This deliberately goes straight to the in-kernel block
 * device. A previous "userspace block backend" let ring 3 register function
 * pointers that the kernel then called from ring 0 — an SMEP violation and a
 * TCB escape. It has been removed (SYS_REGISTER_STORAGE_BACKEND now fails
 * closed). The ETM crypto/MAC layer above this is kernel-mediated, so the
 * transport only ever moves ciphertext; a userspace disk driver, if ever
 * wanted, belongs behind an IPC server, not an in-kernel callback. */
static int raw_block_read(uint64_t block, void *buf) {
    return current_bd->read_block(current_bd, block, buf);
}

static int raw_block_write(uint64_t block, const void *buf) {
    return current_bd->write_block(current_bd, block, buf);
}

/* ---- Write-ahead redo log (journal) --------------------------------------- *
 * A multi-block filesystem update (allocate a data block -> update the bitmap ->
 * link it in the inode -> write the per-block crypto metadata + its superblock
 * meta_hmac -> write the ciphertext) touches up to a handful of separate
 * sectors. A crash partway through used to leave the volume inconsistent — and,
 * worst of all, could desync the metadata region from sb.meta_hmac, which makes
 * storage_unlock refuse to mount (a whole-volume brick).
 *
 * The journal makes each such update atomic. journal_begin() opens a
 * transaction; while one is open, do_block_write STAGES (block, content) in RAM
 * instead of writing home, and do_block_read returns staged content
 * (read-your-writes). journal_commit() then:
 *   1. writes the staged blocks into the journal data region;
 *   2. writes the journal header — targets + a keyed HMAC over the payload — in
 *      one atomic sector: this is the commit point;
 *   3. applies the staged writes to their home locations;
 *   4. clears the header.
 * A crash before step 2 leaves home untouched (old state); after step 2, mount
 * replays the committed transaction (idempotent redo) to complete it — so the
 * filesystem is always either fully before or fully after the operation.
 *
 * Security: the header carries an HMAC keyed by journal_mac_key (derived from
 * disk_key), so an attacker with raw disk access cannot forge a committed
 * transaction that replay would blind-write to arbitrary blocks; every replay
 * target is bounds-checked to the fs body (never the superblock-below region,
 * never the journal itself). Staged data blocks are already ciphertext; staged
 * metadata is plaintext exactly as it lives on disk — no new disclosure. */
#define JOURNAL_MAGIC     0x4C52574Au        /* "JWRL" */
#define JOURNAL_DATA_MAX  16                  /* max home sectors one txn may touch */
#define JOURNAL_BLOCKS    (1 + JOURNAL_DATA_MAX)   /* header sector + data sectors */

struct journal_header {
    uint32_t magic;                      /* JOURNAL_MAGIC when a committed txn is present */
    uint32_t count;                      /* number of home sectors (1..JOURNAL_DATA_MAX) */
    uint64_t seq;                        /* monotonically increasing; also an HMAC input */
    uint64_t target[JOURNAL_DATA_MAX];   /* home block number for each staged sector */
    uint8_t  hmac[32];                   /* HMAC(journal_mac_key, seq||count||targets||data) */
};
_Static_assert(sizeof(struct journal_header) <= BLOCK_SIZE,
               "journal header must fit one sector");

static struct {
    int      active;
    int      overflow;                   /* a txn tried to touch > JOURNAL_DATA_MAX sectors */
    int      n;
    uint64_t target[JOURNAL_DATA_MAX];
    uint8_t  data[JOURNAL_DATA_MAX][BLOCK_SIZE];
} g_txn;
static uint64_t g_journal_seq = 1;

/* HMAC preimage scratch (seq||count||targets||data), guarded by storage_lock. */
static uint8_t g_jscratch[8 + 4 + JOURNAL_DATA_MAX * 8 + JOURNAL_DATA_MAX * BLOCK_SIZE];

static int do_block_read(uint64_t block, void *buf) {
    if (g_txn.active) {
        for (int i = g_txn.n - 1; i >= 0; i--)          /* newest staged write wins */
            if (g_txn.target[i] == block) { my_memcpy(buf, g_txn.data[i], BLOCK_SIZE); return 0; }
    }
    return raw_block_read(block, buf);
}

static int do_block_write(uint64_t block, const void *buf) {
    if (g_txn.active) {
        for (int i = 0; i < g_txn.n; i++)               /* coalesce repeat writes to a block */
            if (g_txn.target[i] == block) { my_memcpy(g_txn.data[i], buf, BLOCK_SIZE); return 0; }
        if (g_txn.n >= JOURNAL_DATA_MAX) { g_txn.overflow = 1; return -1; }
        g_txn.target[g_txn.n] = block;
        my_memcpy(g_txn.data[g_txn.n], buf, BLOCK_SIZE);
        g_txn.n++;
        return 0;
    }
    return raw_block_write(block, buf);
}

static void journal_begin(void) {
    g_txn.active = 1; g_txn.overflow = 0; g_txn.n = 0;
}

static void journal_abort(void) {
    g_txn.active = 0; g_txn.overflow = 0; g_txn.n = 0;   /* discard staged writes; home untouched */
}

static int journal_compute_hmac(const uint8_t *mac_key, uint64_t seq, uint32_t count,
                                const uint64_t *targets, const uint8_t (*data)[BLOCK_SIZE],
                                uint8_t out32[32]) {
    size_t off = 0;
    my_memcpy(g_jscratch + off, &seq,   8); off += 8;
    my_memcpy(g_jscratch + off, &count, 4); off += 4;
    for (uint32_t i = 0; i < count; i++) { my_memcpy(g_jscratch + off, &targets[i], 8); off += 8; }
    for (uint32_t i = 0; i < count; i++) { my_memcpy(g_jscratch + off, data[i], BLOCK_SIZE); off += BLOCK_SIZE; }
    return rust_hmac_sha256(mac_key, 32, g_jscratch, off, out32);
}

/* Crash-injection hook: WAL_CRASHTEST builds halt right after the commit header
 * is durable but before the home apply, to exercise redo recovery on next boot.
 * storage_fresh_format lets the two-boot test tell boot 1 (formatted a fresh
 * disk) from boot 2 (mounted the existing one). */
#ifdef WAL_CRASHTEST
int g_wal_crash_armed = 0;
int storage_fresh_format = 0;
#endif

/* Commit the open transaction (see the block comment above). Returns 0 on
 * success (or when nothing was staged), -1 on overflow / write error — in which
 * case nothing is applied to home and the caller should surface an error. */
static int journal_commit(void) {
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || mfs->sb.journal_start == 0) { journal_abort(); return -1; }
    if (g_txn.overflow) { journal_abort(); return -1; }
    if (g_txn.n == 0)   { g_txn.active = 0; return 0; }

    uint32_t count = (uint32_t)g_txn.n;
    uint64_t jstart = mfs->sb.journal_start;

    /* 1. Journal data region. */
    for (uint32_t i = 0; i < count; i++)
        if (raw_block_write(jstart + 1 + i, g_txn.data[i]) != 0) { journal_abort(); return -1; }

    /* 2. Commit header (one atomic sector). */
    struct journal_header hdr;
    my_memset(&hdr, 0, sizeof(hdr));
    hdr.magic = JOURNAL_MAGIC;
    hdr.count = count;
    hdr.seq   = g_journal_seq;
    for (uint32_t i = 0; i < count; i++) hdr.target[i] = g_txn.target[i];
    if (journal_compute_hmac(mfs->journal_mac_key, hdr.seq, count, hdr.target,
                             (const uint8_t (*)[BLOCK_SIZE])g_txn.data, hdr.hmac) != 0) {
        journal_abort(); return -1;
    }
    uint8_t hbuf[BLOCK_SIZE];
    my_memset(hbuf, 0, BLOCK_SIZE);
    my_memcpy(hbuf, &hdr, sizeof(hdr));
    if (raw_block_write(jstart, hbuf) != 0) { journal_abort(); return -1; }

#ifdef WAL_CRASHTEST
    if (g_wal_crash_armed) {
        /* Commit header is now durable; the home apply below has NOT run. Announce
         * and halt — the two-boot test kills QEMU here and reboots to recover. */
        println("WAL_CRASHTEST: crashed-after-commit");
        for (;;) __asm__ volatile ("hlt");
    }
#endif

    /* 3. Apply to home locations. */
    for (uint32_t i = 0; i < count; i++)
        raw_block_write(g_txn.target[i], g_txn.data[i]);

    /* 4. Clear the header so recovery finds nothing to replay. */
    my_memset(hbuf, 0, BLOCK_SIZE);
    raw_block_write(jstart, hbuf);

    g_journal_seq++;
    g_txn.active = 0; g_txn.n = 0;
    return 0;
}

int storage_block_read(uint64_t block, void *buf) {
    return raw_block_read(block, buf);
}

int storage_block_write(uint64_t block, const void *buf) {
    return raw_block_write(block, buf);
}

/* Serialize and write the metadata sector that covers physical block `phys`.
 * Called while holding storage_lock (single-CPU ring-0, so a blocking ATA
 * write inside the lock is safe — the timer never preempts ring 0). */
static void flush_meta_block(uint64_t phys)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || mfs->sb.meta_start == 0) return;
    if (phys >= BLOCKS_PER_DISK) return;

    uint64_t meta_blk = phys / META_ENTRIES_PER_BLOCK;
    uint64_t base     = meta_blk * META_ENTRIES_PER_BLOCK;

    uint8_t buf[BLOCK_SIZE];
    for (uint64_t i = 0; i < META_ENTRIES_PER_BLOCK; i++) {
        my_memcpy(buf + i * META_ENTRY_SIZE,
                  &g_block_meta[base + i],
                  META_ENTRY_SIZE);
    }
    do_block_write(mfs->sb.meta_start + meta_blk, buf);
    /* Keep the superblock's meta_hmac in sync so mount can verify integrity. */
    update_meta_hmac();
}

/* Read the entire metadata region from disk into g_block_meta on mount. */
static void load_meta_region(struct mounted_fs *mfs)
{
    if (!mfs || mfs->sb.meta_start == 0) return;
    for (uint64_t i = 0; i < META_BLOCKS_COUNT; i++) {
        uint8_t buf[BLOCK_SIZE];
        if (do_block_read(mfs->sb.meta_start + i, buf) != 0) continue;
        uint64_t base = i * META_ENTRIES_PER_BLOCK;
        for (uint64_t j = 0; j < META_ENTRIES_PER_BLOCK; j++) {
            if (base + j >= BLOCKS_PER_DISK) break;
            my_memcpy(&g_block_meta[base + j],
                      buf + j * META_ENTRY_SIZE,
                      META_ENTRY_SIZE);
        }
    }
}

/* Derive the HMAC key for the metadata region:
 *   meta_mac_key = HKDF-SHA256(IKM=disk_key, salt=volume_key_salt, info="horus-meta-mac-v1")
 * disk_key and volume_key_salt are both on-disk stable values, so meta_mac_key
 * is the same across reboots for the same formatted volume. */
static int derive_meta_mac_key(const uint8_t *disk_key,   size_t dk_len,
                                const uint8_t *vk_salt,    size_t salt_len,
                                uint8_t       *out32)
{
    const char *label = "horus-meta-mac-v1";
    uint8_t info[18];
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    return rust_hkdf_sha256(disk_key, dk_len, vk_salt, salt_len, info, p, out32, 32);
}

/* journal_mac_key = HKDF-SHA256(disk_key, volume_key_salt, "horus-journal-mac-v1").
 * A distinct label from the meta-mac key so the two are independent. */
static int derive_journal_mac_key(const uint8_t *disk_key, size_t dk_len,
                                  const uint8_t *vk_salt,  size_t salt_len,
                                  uint8_t       *out32)
{
    const char *label = "horus-journal-mac-v1";
    uint8_t info[21];
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    return rust_hkdf_sha256(disk_key, dk_len, vk_salt, salt_len, info, p, out32, 32);
}

/* Replay any committed transaction left in the journal by a crash. Run at mount,
 * BEFORE the metadata region is loaded and its HMAC verified, so a transaction
 * that updated a meta sector and sb.meta_hmac together is completed atomically.
 * Verifies the header's keyed HMAC and bounds-checks every target, so only a
 * genuine, kernel-authored, intact transaction is ever applied; anything else is
 * discarded (the operation is treated as never having happened). Idempotent. */
static void journal_recover(struct mounted_fs *mfs)
{
    if (!mfs || !mfs->mounted || mfs->sb.journal_start == 0) return;
    uint64_t jstart = mfs->sb.journal_start;

    uint8_t hbuf[BLOCK_SIZE];
    if (raw_block_read(jstart, hbuf) != 0) return;
    struct journal_header hdr;
    my_memcpy(&hdr, hbuf, sizeof(hdr));

    if (hdr.magic != JOURNAL_MAGIC) return;                 /* nothing committed */
    if (hdr.count == 0 || hdr.count > JOURNAL_DATA_MAX) goto discard;

    /* Load the staged data and re-derive the HMAC over exactly what we would
     * apply; a torn/forged journal fails here and is discarded. */
    static uint8_t jdata[JOURNAL_DATA_MAX][BLOCK_SIZE];
    for (uint32_t i = 0; i < hdr.count; i++)
        if (raw_block_read(jstart + 1 + i, jdata[i]) != 0) goto discard;

    uint8_t want[32];
    if (journal_compute_hmac(mfs->journal_mac_key, hdr.seq, hdr.count, hdr.target,
                             (const uint8_t (*)[BLOCK_SIZE])jdata, want) != 0) goto discard;
    int bad = 0;
    for (int i = 0; i < 32; i++) bad |= (want[i] ^ hdr.hmac[i]);
    if (bad) goto discard;

    /* Every target must land in the filesystem body — never block 0 (superblock
     * lives there but is written via the txn's own staged copy, target != 0
     * because update_meta_hmac stages block 0... actually it may; allow 0 since a
     * valid HMAC proves the kernel authored it) — but never inside the journal
     * region, and never past the disk. Fail closed on any out-of-range target. */
    for (uint32_t i = 0; i < hdr.count; i++) {
        uint64_t t = hdr.target[i];
        if (t >= mfs->sb.total_blocks) goto discard;
        if (t >= jstart && t < jstart + mfs->sb.journal_blocks) goto discard;
    }

    /* Redo. */
    for (uint32_t i = 0; i < hdr.count; i++)
        raw_block_write(hdr.target[i], jdata[i]);
    if (hdr.seq >= g_journal_seq) g_journal_seq = hdr.seq + 1;

discard:
    my_memset(hbuf, 0, BLOCK_SIZE);
    raw_block_write(jstart, hbuf);   /* clear the header either way */
}

/* HMAC-SHA256(meta_mac_key, entire g_block_meta[] array) → out32.
 * Covers all BLOCKS_PER_DISK entries at once; at 32 KB this is cheap. */
static int compute_meta_hmac(const uint8_t *mac_key, uint8_t *out32)
{
    return rust_hmac_sha256(mac_key, 32,
                            (const uint8_t *)g_block_meta, sizeof(g_block_meta),
                            out32);
}

/* Recompute the metadata HMAC, store it in the in-memory superblock, and
 * flush the superblock (block 0) to disk.  Called while holding storage_lock
 * after every metadata-sector write, so the HMAC always reflects the current
 * state of the metadata region. */
static void update_meta_hmac(void)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) return;
    uint8_t tag[32];
    if (compute_meta_hmac(mfs->meta_mac_key, tag) != 0) return;
    my_memcpy(mfs->sb.meta_hmac, tag, 32);
    do_block_write(0, &mfs->sb);   /* superblock is always block 0 */
}

/* ATA-backed block device (persistent). A block is one 512-byte LBA sector
 * (BLOCK_SIZE), so the mapping is 1:1. The per-block crypto metadata (nonce/tag)
 * is persisted: storage_encrypt_block flushes each updated meta sector
 * (flush_meta_block) and storage_unlock reloads the region (load_meta_region)
 * and verifies its HMAC, so files survive a reboot — proven by
 * `make smoke-fs-persist`. Compiled unconditionally; storage_init() selects it
 * at runtime when a disk is actually present. */
static int atadisk_read(struct block_device *bd, uint64_t block, void *buf) {
    (void)bd;
    return ata_read((uint32_t)block, buf, 1);
}
static int atadisk_write(struct block_device *bd, uint64_t block, const void *buf) {
    (void)bd;
    return ata_write((uint32_t)block, buf, 1);
}
static struct block_device g_ata_bd = {
    .name = "ata0",
    .total_blocks = BLOCKS_PER_DISK,
    .read_block = atadisk_read,
    .write_block = atadisk_write,
    .private = 0,
};

int storage_init(void) {
    /* Persistent by default: probe for an ATA disk. If one is attached, use the
     * encrypted ATA store — it comes up mounted-but-locked and disk_key is only
     * unwrapped at login (storage_unlock), so files survive a reboot but the
     * volume stays sealed until a user authenticates. A fresh or foreign disk is
     * formatted+sealed at that first login (g_needs_format). If no disk is present
     * — a diskless or CI boot — fall back to the ephemeral in-RAM vdisk, which is
     * formatted and unlocked immediately with a per-boot throwaway key so the
     * system still comes up without a login. ata_init()'s probe is bounded, so a
     * floating/absent bus can never hang the boot. */
#ifdef STORAGE_RING3_DISK
    /* Ring-3 disk_server owns the primary master now: the kernel must NOT probe or
     * drive ATA here (that would fight the ring-3 driver for the same ports). The
     * volume is mounted later, once disk_server has registered (blkdev_on_register
     * enqueues the mount onto storaged). Until then — and on a diskless boot — the
     * ephemeral RAM vdisk below brings the system up. */
    (void)atadisk_read; (void)atadisk_write; (void)g_ata_bd;
#else
    if (ata_init()) {
        current_bd = &g_ata_bd;
        if (storage_mount(&g_ata_bd) != 0) {
            g_needs_format    = 1;   /* no valid v4 volume yet: seal it at first login */
            g_needs_format_bd = &g_ata_bd;
        }
        return 0;                    /* unlock deferred to login */
    }
#endif

    /* No disk: ephemeral in-RAM virtual disk, formatted and unlocked immediately
     * with a per-boot random password (the vdisk is never persisted, so the
     * password is discarded after unlock and no login is required to use it). */
    g_vdisk.data        = g_vdisk_buffer;
    g_vdisk.size        = sizeof(g_vdisk_buffer);
    g_vdisk.block_count = BLOCKS_PER_DISK;
    my_memset(g_vdisk.data, 0, g_vdisk.size);
    current_bd = &g_vdisk_bd;

    uint8_t boot_pass[32];
    secure_random_bytes(boot_pass, sizeof(boot_pass));
    if (storage_format_sealed(&g_vdisk_bd, (const char *)boot_pass,
                              sizeof(boot_pass)) != 0) {
        secure_zero(boot_pass, sizeof(boot_pass));
        return -1;
    }
    if (storage_mount(&g_vdisk_bd) != 0) {
        secure_zero(boot_pass, sizeof(boot_pass));
        return -1;
    }
    int rc = storage_unlock((const char *)boot_pass, sizeof(boot_pass));
    secure_zero(boot_pass, sizeof(boot_pass));
    return rc;
}

static int bitmap_test(const uint8_t *bitmap, uint64_t bit) {
    return (bitmap[bit / 8] & (1 << (bit % 8))) != 0;
}

static void bitmap_set(uint8_t *bitmap, uint64_t bit) {
    bitmap[bit / 8] |= (1 << (bit % 8));
}

static void bitmap_clear(uint8_t *bitmap, uint64_t bit) {
    bitmap[bit / 8] &= ~(1 << (bit % 8));
}

static int64_t bitmap_find_free(const uint8_t *bitmap, uint64_t max_bits) {
    for (uint64_t i = 0; i < max_bits; i++) {
        if (!bitmap_test(bitmap, i)) return i;
    }
    return -1;
}

static int read_block_bitmap(struct block_device *bd, const struct fs_superblock *sb, uint8_t *buf) {
    (void)bd; return do_block_read(sb->block_bitmap_start, buf);
}

static int write_block_bitmap(struct block_device *bd, const struct fs_superblock *sb, const uint8_t *buf) {
    (void)bd; return do_block_write(sb->block_bitmap_start, buf);
}

int64_t storage_alloc_block(struct block_device *bd, struct fs_superblock *sb) {
    uint8_t bitmap[BLOCK_SIZE];
    if (read_block_bitmap(bd, sb, bitmap) != 0) return -1;

    int64_t block = bitmap_find_free(bitmap, sb->block_count);
    if (block < 0) return -1;

    bitmap_set(bitmap, block);
    write_block_bitmap(bd, sb, bitmap);

    return sb->data_start + block;
}

void storage_free_block(struct block_device *bd, struct fs_superblock *sb, uint64_t block) {
    uint8_t bitmap[BLOCK_SIZE];
    if (read_block_bitmap(bd, sb, bitmap) != 0) return;

    uint64_t rel = block - sb->data_start;
    bitmap_clear(bitmap, rel);
    write_block_bitmap(bd, sb, bitmap);
}

int64_t storage_alloc_inode(struct block_device *bd, struct fs_superblock *sb) {
    uint8_t bitmap[BLOCK_SIZE];
    (void)bd; if (do_block_read(sb->inode_bitmap_start, bitmap) != 0) return -1;

    int64_t ino = bitmap_find_free(bitmap, sb->inode_count);
    if (ino < 0) return -1;

    bitmap_set(bitmap, ino);
    do_block_write(sb->inode_bitmap_start, bitmap);
    return ino;
}

void storage_free_inode(struct block_device *bd, struct fs_superblock *sb, uint64_t ino) {
    uint8_t bitmap[BLOCK_SIZE];
    (void)bd; if (do_block_read(sb->inode_bitmap_start, bitmap) != 0) return;
    bitmap_clear(bitmap, ino);
    do_block_write(sb->inode_bitmap_start, bitmap);
}

int storage_read_inode(struct block_device *bd, struct fs_superblock *sb,
                       uint64_t ino, struct on_disk_inode *inode_out) {
    if (ino >= sb->inode_count) return -1;

    uint64_t block = sb->inode_table_start + (ino / INODES_PER_BLOCK);
    uint32_t offset = (ino % INODES_PER_BLOCK) * sizeof(struct on_disk_inode);

    uint8_t buf[BLOCK_SIZE];
    (void)bd; if (do_block_read(block, buf) != 0) return -1;

    my_memcpy(inode_out, buf + offset, sizeof(struct on_disk_inode));
    return 0;
}

int storage_write_inode(struct block_device *bd, struct fs_superblock *sb,
                        uint64_t ino, const struct on_disk_inode *inode) {
    if (ino >= sb->inode_count) return -1;

    uint64_t block = sb->inode_table_start + (ino / INODES_PER_BLOCK);
    uint32_t offset = (ino % INODES_PER_BLOCK) * sizeof(struct on_disk_inode);

    uint8_t buf[BLOCK_SIZE];
    (void)bd; if (do_block_read(block, buf) != 0) return -1;

    my_memcpy(buf + offset, inode, sizeof(struct on_disk_inode));
    return do_block_write(block, buf);
}

int storage_dir_lookup(struct mounted_fs *mfs, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    struct on_disk_inode dir;
    if (storage_read_inode(mfs->bd, &mfs->sb, dir_ino, &dir) != 0) return -1;

    size_t name_len = my_strlen(name);
    uint8_t block_buf[BLOCK_SIZE];

    uint64_t file_blocks = (dir.size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (uint64_t b = 0; b < file_blocks; b++) {
        if (storage_read_file_block(mfs, dir_ino, b, block_buf) != 0) continue;

        for (size_t off = 0; off + sizeof(struct dir_entry) <= BLOCK_SIZE; off += sizeof(struct dir_entry)) {
            struct dir_entry *de = (struct dir_entry *)(block_buf + off);
            if (de->inode == 0) continue;

            if (de->name_len == name_len && my_strncmp(de->name, name, name_len) == 0) {
                *out_ino = de->inode;
                return 0;
            }
        }
    }
    return -1;
}

int storage_dir_add(struct mounted_fs *mfs, uint64_t dir_ino, const char *name,
                    uint64_t child_ino, uint8_t type) {
    struct on_disk_inode dir;
    if (storage_read_inode(mfs->bd, &mfs->sb, dir_ino, &dir) != 0) return -1;

    size_t name_len = my_strlen(name);
    uint8_t block_buf[BLOCK_SIZE];
    uint64_t file_blocks = (dir.size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (uint64_t b = 0; b < file_blocks; b++) {
        if (storage_read_file_block(mfs, dir_ino, b, block_buf) != 0) continue;

        for (size_t off = 0; off + sizeof(struct dir_entry) <= BLOCK_SIZE; off += sizeof(struct dir_entry)) {
            struct dir_entry *de = (struct dir_entry *)(block_buf + off);
            if (de->inode == 0) {
                de->inode = child_ino;
                de->name_len = name_len;
                de->type = type;
                my_strncpy(de->name, name, sizeof(de->name));

                storage_write_file_block(mfs, dir_ino, b, block_buf);
                return 0;
            }
        }
    }

    uint64_t new_block = file_blocks;
    my_memset(block_buf, 0, BLOCK_SIZE);

    struct dir_entry *de = (struct dir_entry *)block_buf;
    de->inode = child_ino;
    de->name_len = name_len;
    de->type = type;
    my_strncpy(de->name, name, sizeof(de->name));

    if (storage_write_file_block(mfs, dir_ino, new_block, block_buf) != 0) {
        return -1;
    }

    dir.size = (new_block + 1) * BLOCK_SIZE;
    storage_write_inode(mfs->bd, &mfs->sb, dir_ino, &dir);

    return 0;
}

/* Derive a 32-byte Key Encryption Key from password + kek_salt using Argon2id.
 * No kernel_pepper: the KEK must reproduce from the same inputs across reboots.
 * Domain-separated from the login hash by the different salt length (32B vs 32B
 * login_salt||pepper) and the different downstream use (wrapping vs verification). */
static int derive_kek(const char *password, size_t plen,
                      const uint8_t *kek_salt, uint8_t *kek32)
{
    /* Uses kernel_argon2id (syscall.c) to share the single 4MiB scratch buffer.
     * No kernel_pepper: kek_salt is random per-format and stable across reboots,
     * so the same password always yields the same KEK from the same disk. */
    return kernel_argon2id((const uint8_t *)password, plen,
                           kek_salt, 32, kek32, 32);
}

/* Format a block device and seal disk_key with the user's password.
 * disk_key is randomly generated, never stored in plaintext on disk.
 * KEK = Argon2id(password, kek_salt); wrapped = AEAD(KEK, disk_key). */
static int storage_format_sealed(struct block_device *bd,
                                  const char *password, size_t plen)
{
    struct fs_superblock sb;
    my_memset(&sb, 0, sizeof(sb));

    sb.magic = STORAGE_MAGIC;
    sb.version = STORAGE_VERSION;
    sb.total_blocks = bd->total_blocks;
    sb.block_size = BLOCK_SIZE;

    /* Block 0: superblock.  Blocks 1..META_BLOCKS_COUNT: crypto metadata region.
     * All other regions are shifted past it so the metadata lives at a fixed,
     * known offset regardless of disk geometry. */
    sb.meta_start         = 1;
    sb.meta_blocks        = META_BLOCKS_COUNT;
    /* Write-ahead redo log sits right after the metadata region. */
    sb.journal_start      = 1 + META_BLOCKS_COUNT;
    sb.journal_blocks     = JOURNAL_BLOCKS;
    uint64_t after_j      = sb.journal_start + JOURNAL_BLOCKS;
    sb.inode_bitmap_start = after_j;
    sb.block_bitmap_start = after_j + 1;
    sb.inode_table_start  = after_j + 2;

    /* Geometry is computed from the device size instead of hardcoded. One bitmap
     * block addresses at most BLOCK_SIZE*8 (=4096) bits, so both the inode count
     * and the data region are bounded to a single bitmap block; multi-block
     * bitmaps (larger disks) are a documented follow-up. */
    const uint64_t BITS_PER_BLOCK = (uint64_t)BLOCK_SIZE * 8;

    uint64_t inodes = bd->total_blocks / 4;   /* ~1 inode per 4 blocks */
    if (inodes < 16) inodes = 16;
    if (inodes > BITS_PER_BLOCK) inodes = BITS_PER_BLOCK;
    uint64_t table_blocks = (inodes + INODES_PER_BLOCK - 1) / INODES_PER_BLOCK;
    inodes = table_blocks * INODES_PER_BLOCK;

    sb.inode_count = inodes;
    sb.data_start  = sb.inode_table_start + table_blocks;
    if (sb.data_start >= bd->total_blocks) return -1;   /* disk too small */

    uint64_t data_blocks = bd->total_blocks - sb.data_start;
    if (data_blocks > BITS_PER_BLOCK) data_blocks = BITS_PER_BLOCK;
    sb.block_count = data_blocks;

    /* Per-volume HKDF diversifier — random per-format, stable on disk. */
    secure_random_bytes(sb.volume_key_salt, sizeof(sb.volume_key_salt));

    /* Generate disk_key — root of all per-block key derivation.
     * Never written in plaintext to disk; sealed below with the user's KEK. */
    uint8_t disk_key[32];
    secure_random_bytes(disk_key, sizeof(disk_key));

    /* KEK = Argon2id(password, kek_salt).  kek_salt is random per-format but
     * contains no kernel_pepper so the same password always yields the same KEK
     * across reboots.  KEK is expanded to 64 bytes via HKDF then used as the
     * enc_key||mac_key pair for the wrapping AEAD. */
    secure_random_bytes(sb.kek_salt,          sizeof(sb.kek_salt));
    secure_random_bytes(sb.wrapped_key_nonce, sizeof(sb.wrapped_key_nonce));
    {
        uint8_t kek[32];
        if (derive_kek(password, plen, sb.kek_salt, kek) != 0) {
            secure_zero(disk_key, sizeof(disk_key));
            return -1;
        }
        uint8_t wrap_keys[64];
        {
            const char *label = "horus-wrap-v1";
            uint8_t info[13]; size_t n = 0;
            for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
            if (rust_hkdf_sha256(kek, 32, sb.kek_salt, sizeof(sb.kek_salt),
                                 info, n, wrap_keys, 64) != 0) {
                secure_zero(kek, sizeof(kek));
                secure_zero(disk_key, sizeof(disk_key));
                return -2;
            }
        }
        secure_zero(kek, sizeof(kek));
        my_memcpy(sb.wrapped_key_ct, disk_key, 32);
        rust_aead_seal(wrap_keys, wrap_keys + 32, sb.wrapped_key_nonce,
                       sb.volume_key_salt, sizeof(sb.volume_key_salt),
                       sb.wrapped_key_ct, 32, sb.wrapped_key_tag);
        secure_zero(wrap_keys, sizeof(wrap_keys));
    }

    /* Compute the initial metadata HMAC over an all-zeros g_block_meta[] so
     * the first storage_unlock after format passes the verify step cleanly. */
    my_memset(g_block_meta, 0, sizeof(g_block_meta));
    {
        uint8_t fmt_mac_key[32];
        if (derive_meta_mac_key(disk_key, sizeof(disk_key),
                                sb.volume_key_salt, sizeof(sb.volume_key_salt),
                                fmt_mac_key) == 0) {
            compute_meta_hmac(fmt_mac_key, sb.meta_hmac);
            secure_zero(fmt_mac_key, sizeof(fmt_mac_key));
        }
    }
    secure_zero(disk_key, sizeof(disk_key));

    bd->write_block(bd, 0, &sb);

    uint8_t zero[BLOCK_SIZE];
    my_memset(zero, 0, BLOCK_SIZE);

    /* Zero the crypto metadata region so every block starts with present=0;
     * load_meta_region reads it back on mount and initialises g_block_meta. */
    for (uint64_t m = 0; m < META_BLOCKS_COUNT; m++) {
        bd->write_block(bd, sb.meta_start + m, zero);
    }

    /* Zero the journal region: a cleared header (magic 0) means "no committed
     * transaction to replay" — a fresh volume has nothing to recover. */
    for (uint32_t j = 0; j < sb.journal_blocks; j++) {
        bd->write_block(bd, sb.journal_start + j, zero);
    }

    bd->write_block(bd, sb.block_bitmap_start, zero);

    /* Zero the whole inode table so inodes sharing a block with a freshly used
     * one read back clean (matters on a garbage ATA disk at first format). */
    for (uint64_t b = 0; b < table_blocks; b++) {
        bd->write_block(bd, sb.inode_table_start + b, zero);
    }

    /* inode 0 (root) is allocated in the inode bitmap. */
    bitmap_set(zero, 0);
    bd->write_block(bd, sb.inode_bitmap_start, zero);

    struct on_disk_inode root;
    my_memset(&root, 0, sizeof(root));
    root.type = 2;          /* directory */
    root.mode = 0040755;
    root.links = 2;
    storage_write_inode(bd, &sb, 0, &root);

    return 0;
}

static struct mounted_fs g_mounted_fs;

int storage_mount(struct block_device *bd) {
    uint8_t block_buf[BLOCK_SIZE];
    if (bd->read_block(bd, 0, block_buf) != 0) {
        return -1;
    }

    struct fs_superblock *sb = (struct fs_superblock *)block_buf;

    /* Reject disks with the wrong magic or an older on-disk version.  A v1 disk
     * has no metadata region (meta_start=0) and would silently serve undecryptable
     * blocks after reboot.  Returning -2 here triggers storage_init to reformat,
     * which is the correct recovery for an incompatible layout. */
    if (sb->magic != STORAGE_MAGIC || sb->version != STORAGE_VERSION) {
        return -2;
    }

    g_mounted_fs.bd       = bd;
    g_mounted_fs.sb       = *sb;
    g_mounted_fs.mounted  = 1;
    g_mounted_fs.unlocked = 0;
    /* Key derivation deferred to storage_unlock() — we need the user's
     * password to unwrap disk_key before any crypto work can proceed. */
    return 0;
}

struct mounted_fs *storage_get_mounted_fs(void) {
    return &g_mounted_fs;
}

/* Called at first successful login.  If no valid v4 disk exists (g_needs_format)
 * formats and seals one with the user's password first; then unwraps disk_key,
 * derives volume_key + meta_mac_key, and verifies the metadata HMAC. */
int storage_unlock(const char *password, size_t plen)
{
    if (g_needs_format) {
        if (storage_format_sealed(g_needs_format_bd, password, plen) != 0) return -1;
        if (storage_mount(g_needs_format_bd) != 0) return -1;
        g_needs_format    = 0;
        g_needs_format_bd = NULL;
#ifdef WAL_CRASHTEST
        storage_fresh_format = 1;   /* this boot formatted a fresh disk (boot 1) */
#endif
    }

    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted)  return -2;
    if (mfs->unlocked)  return 0;   /* idempotent: already unlocked */

    struct fs_superblock *sb = &mfs->sb;

    /* Step 1 — Derive KEK from password + stable on-disk salt (no kernel_pepper). */
    uint8_t kek[32];
    if (derive_kek(password, plen, sb->kek_salt, kek) != 0) return -3;

    /* Step 2 — Expand KEK → enc_key[32] || mac_key[32] for wrapping AEAD. */
    uint8_t wrap_keys[64];
    {
        const char *label = "horus-wrap-v1";
        uint8_t info[13]; size_t n = 0;
        for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
        if (rust_hkdf_sha256(kek, 32, sb->kek_salt, sizeof(sb->kek_salt),
                             info, n, wrap_keys, 64) != 0) {
            secure_zero(kek, sizeof(kek));
            return -4;
        }
    }
    secure_zero(kek, sizeof(kek));

    /* Step 3 — AEAD-open the wrapped disk_key.
     * Tag mismatch → wrong password or tampered header; deny without revealing which. */
    uint8_t disk_key[32];
    my_memcpy(disk_key, sb->wrapped_key_ct, 32);
    if (rust_aead_open(wrap_keys, wrap_keys + 32, sb->wrapped_key_nonce,
                       sb->volume_key_salt, sizeof(sb->volume_key_salt),
                       disk_key, 32, sb->wrapped_key_tag) != 0) {
        secure_zero(disk_key,   sizeof(disk_key));
        secure_zero(wrap_keys,  sizeof(wrap_keys));
        return -5;
    }
    secure_zero(wrap_keys, sizeof(wrap_keys));

    /* Step 4 — Store plaintext disk_key in RAM; derive volume_key + meta_mac_key. */
    my_memcpy(mfs->disk_key, disk_key, 32);
    secure_zero(disk_key, sizeof(disk_key));

    {
        const char *label = "horus-volume-key-v2";
        uint8_t info[19]; size_t n = 0;
        for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
        if (rust_hkdf_sha256(mfs->disk_key, 32,
                             sb->volume_key_salt, sizeof(sb->volume_key_salt),
                             info, n,
                             mfs->volume_key, sizeof(mfs->volume_key)) != 0) {
            secure_zero(mfs->disk_key, sizeof(mfs->disk_key));
            return -6;
        }
    }
    if (derive_meta_mac_key(mfs->disk_key, 32,
                            sb->volume_key_salt, sizeof(sb->volume_key_salt),
                            mfs->meta_mac_key) != 0) {
        secure_zero(mfs->disk_key,   sizeof(mfs->disk_key));
        secure_zero(mfs->volume_key, sizeof(mfs->volume_key));
        return -7;
    }
    if (derive_journal_mac_key(mfs->disk_key, 32,
                               sb->volume_key_salt, sizeof(sb->volume_key_salt),
                               mfs->journal_mac_key) != 0) {
        secure_zero(mfs->disk_key,   sizeof(mfs->disk_key));
        secure_zero(mfs->volume_key, sizeof(mfs->volume_key));
        secure_zero(mfs->meta_mac_key, sizeof(mfs->meta_mac_key));
        return -7;
    }

    /* Replay any committed transaction a crash left in the journal BEFORE the
     * metadata region is loaded and its HMAC checked — so an update that touched
     * a meta sector and sb.meta_hmac together is completed as a unit and the two
     * always agree. */
    journal_recover(mfs);
    /* Recovery may have re-applied a committed transaction that included the
     * superblock (its meta_hmac). Reload the in-RAM superblock so the HMAC check
     * below compares against the post-recovery value, not the stale mount-time one. */
    {
        uint8_t sbbuf[BLOCK_SIZE];
        if (raw_block_read(0, sbbuf) == 0) my_memcpy(&mfs->sb, sbbuf, sizeof(mfs->sb));
    }

    /* Step 5 — Load metadata region and verify HMAC (detects nonce/tag rollback). */
    load_meta_region(mfs);
    {
        uint8_t computed[32];
        if (compute_meta_hmac(mfs->meta_mac_key, computed) != 0) {
            secure_zero(mfs->disk_key,      sizeof(mfs->disk_key));
            secure_zero(mfs->volume_key,    sizeof(mfs->volume_key));
            secure_zero(mfs->meta_mac_key,  sizeof(mfs->meta_mac_key));
            return -8;
        }
        int bad = 0;
        for (int i = 0; i < 32; i++)
            bad |= (computed[i] ^ mfs->sb.meta_hmac[i]);
        secure_zero(computed, sizeof(computed));
        if (bad) {
            secure_zero(mfs->disk_key,      sizeof(mfs->disk_key));
            secure_zero(mfs->volume_key,    sizeof(mfs->volume_key));
            secure_zero(mfs->meta_mac_key,  sizeof(mfs->meta_mac_key));
            my_memset(g_block_meta, 0, sizeof(g_block_meta));
            return -9;   /* partial metadata rollback detected */
        }
    }

    mfs->unlocked = 1;
    storage_fsck_pass(mfs);
    return 0;
}

/* Sweep the inode bitmap and free any slot that is allocated but contains
 * stale data from an interrupted operation:
 *
 *   type == 0, all fields zero:
 *     storage_alloc_inode set the bitmap bit, but the kernel crashed before
 *     storage_write_inode ran.  The slot is still the zeroed bytes written at
 *     format time.  No data blocks were ever allocated (that happens at first
 *     write, after the inode is initialized), so clearing the bitmap bit is
 *     the complete fix.
 *
 *   type != 0, links == 0:
 *     storage_free_inode_blocks freed the data blocks and wrote back the inode
 *     with links=0, but the kernel crashed before storage_free_inode cleared the
 *     bitmap bit.  The data blocks are already freed; we just need to clear the
 *     bit to avoid a permanent "inode slot occupied" leak.
 *
 * Reads one inode table block per iteration (INODES_PER_BLOCK inodes each) to
 * avoid re-reading the same sector for every inode.  Writes the updated bitmap
 * only when at least one slot was reclaimed (dirty flag). */
static void storage_fsck_pass(struct mounted_fs *mfs)
{
    uint8_t inode_bitmap[BLOCK_SIZE];
    if (do_block_read(mfs->sb.inode_bitmap_start, inode_bitmap) != 0) return;

    uint8_t block_bitmap[BLOCK_SIZE];
    int have_bb = (do_block_read(mfs->sb.block_bitmap_start, block_bitmap) == 0);

    /* Data blocks reachable from a live inode's direct/single-indirect pointers.
     * Indexed by rel = phys - data_start, matching the block bitmap. */
    static uint8_t referenced[BLOCK_SIZE];
    my_memset(referenced, 0, BLOCK_SIZE);
    const uint64_t data_start  = mfs->sb.data_start;
    const uint64_t block_count = mfs->sb.block_count;

    int inode_dirty = 0;
    uint64_t table_blocks =
        (mfs->sb.inode_count + INODES_PER_BLOCK - 1) / INODES_PER_BLOCK;

    for (uint64_t tb = 0; tb < table_blocks; tb++) {
        uint8_t blk[BLOCK_SIZE];
        if (do_block_read(mfs->sb.inode_table_start + tb, blk) != 0) continue;
        struct on_disk_inode *slots = (struct on_disk_inode *)blk;

        for (int i = 0; i < INODES_PER_BLOCK; i++) {
            uint64_t ino = tb * (uint64_t)INODES_PER_BLOCK + (uint64_t)i;
            if (ino >= mfs->sb.inode_count) continue;
            if (!bitmap_test(inode_bitmap, ino)) continue;

            struct on_disk_inode *nd = &slots[i];
            int alive = (nd->type != 0 && nd->links != 0);

            /* Reclaim an allocated inode slot left dangling by an interrupted
             * op (never the root inode 0): type==0 (bitmap set before the inode
             * was initialised) or links==0 (freed before the bitmap bit cleared).
             * Its data blocks, if any, are then reclaimed by the block sweep. */
            if (ino != 0 && !alive) {
                bitmap_clear(inode_bitmap, ino);
                inode_dirty = 1;
                continue;
            }

            /* Live inode (including root): mark every data block it references. */
            for (int d = 0; d < 12; d++) {
                uint64_t p = nd->direct[d];
                if (p >= data_start && p < data_start + block_count)
                    bitmap_set(referenced, p - data_start);
            }
            if (nd->indirect >= data_start && nd->indirect < data_start + block_count) {
                bitmap_set(referenced, nd->indirect - data_start);
                uint8_t ib[BLOCK_SIZE];
                if (do_block_read(nd->indirect, ib) == 0) {
                    uint64_t *ptrs = (uint64_t *)ib;
                    for (unsigned k = 0; k < BLOCK_SIZE / sizeof(uint64_t); k++) {
                        uint64_t p = ptrs[k];
                        if (p >= data_start && p < data_start + block_count)
                            bitmap_set(referenced, p - data_start);
                    }
                }
            }
        }
    }

    if (inode_dirty)
        do_block_write(mfs->sb.inode_bitmap_start, inode_bitmap);

    /* Reclaim data blocks the bitmap marks allocated but no live inode references
     * (crash-orphaned: allocated before the operation that would link them
     * committed). Only clears bits; never touches a referenced block. */
    if (have_bb) {
        int bb_dirty = 0;
        for (uint64_t r = 0; r < block_count; r++) {
            if (bitmap_test(block_bitmap, r) && !bitmap_test(referenced, r)) {
                bitmap_clear(block_bitmap, r);
                bb_dirty = 1;
            }
        }
        if (bb_dirty)
            do_block_write(mfs->sb.block_bitmap_start, block_bitmap);
    }
}

int storage_rekey(const char *new_password, size_t plen)
{
    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted || !mfs->unlocked) return -1;

    struct fs_superblock *sb = &mfs->sb;

    /* Fresh salt + nonce so the old wrapped key is immediately invalidated. */
    uint8_t new_kek_salt[32], new_nonce[12];
    secure_random_bytes(new_kek_salt, sizeof(new_kek_salt));
    secure_random_bytes(new_nonce,    sizeof(new_nonce));

    uint8_t kek[32];
    if (derive_kek(new_password, plen, new_kek_salt, kek) != 0) return -2;

    uint8_t wrap_keys[64];
    {
        const char *label = "horus-wrap-v1";
        uint8_t info[13]; size_t n = 0;
        for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
        if (rust_hkdf_sha256(kek, 32, new_kek_salt, sizeof(new_kek_salt),
                             info, n, wrap_keys, 64) != 0) {
            secure_zero(kek, sizeof(kek));
            return -3;
        }
    }
    secure_zero(kek, sizeof(kek));

    uint8_t new_ct[32], new_tag[16];
    my_memcpy(new_ct, mfs->disk_key, 32);
    rust_aead_seal(wrap_keys, wrap_keys + 32, new_nonce,
                   sb->volume_key_salt, sizeof(sb->volume_key_salt),
                   new_ct, 32, new_tag);
    secure_zero(wrap_keys, sizeof(wrap_keys));

    my_memcpy(sb->kek_salt,          new_kek_salt, 32);
    my_memcpy(sb->wrapped_key_nonce, new_nonce,    12);
    my_memcpy(sb->wrapped_key_ct,    new_ct,       32);
    my_memcpy(sb->wrapped_key_tag,   new_tag,      16);

    mfs->bd->write_block(mfs->bd, 0, sb);
    return 0;
}

int derive_and_store_user_file_key(uint32_t uid, const char *material, size_t material_len)
{
    extern tcb_t tasks[MAX_TASKS];

    extern uint8_t kernel_pepper[16];

    if (get_current_task() < 0 || get_current_task() >= MAX_TASKS) return -1;

    
    if (get_current_task() != 0 && !has_encrypted_storage_cap()) {
        return -3;
    }

    /* Per-user file master key = HKDF-SHA256(password material, salt=pepper,
     * info="horus-user-file-key-v1" || uid). Replaces the previous custom
     * 8-round XOR/add mixing, which had no diffusion guarantees. */
    uint8_t *mk = tasks[get_current_task()].user_file_master_key;
    const uint8_t zero = 0;
    const uint8_t *ikm = (material && material_len > 0) ? (const uint8_t *)material : &zero;
    size_t ikm_len = (material && material_len > 0) ? material_len : 1;

    uint8_t info[23 + 4];
    const char *label = "horus-user-file-key-v1";
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    for (int i = 0; i < 4; i++) info[p++] = (uint8_t)(uid >> (i * 8));

    if (rust_hkdf_sha256(ikm, ikm_len, kernel_pepper, 16, info, p, mk, 32) != 0) {
        return -1;
    }
    tasks[get_current_task()].has_file_key = 1;
    return 0;
}

int do_rotate_keys(void)
{
    extern tcb_t tasks[MAX_TASKS];

    if (get_current_task() < 0 || get_current_task() >= MAX_TASKS) return -1;
    if (!tasks[get_current_task()].has_file_key) return -2;
    if (get_current_task() != 0 && !has_encrypted_storage_cap()) return -4;

    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) return -3;

    uint32_t uid = tasks[get_current_task()].uid;
    uint32_t rotated = 0;

    
    for (uint64_t ino = 0; ino < mfs->sb.inode_count && rotated < 64; ino++) {
        struct on_disk_inode inode;
        if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) continue;
        if (inode.links == 0 || inode.uid != uid) continue;

        
        for (uint64_t b = 0; b < 4; b++) {
            uint8_t tmp[BLOCK_SIZE];
            if (storage_read_file_block(mfs, ino, b, tmp) != 0) break;
            
            if (storage_write_file_block(mfs, ino, b, tmp) == 0) {
                rotated++;
            }
        }
    }

    /* (The legacy capfs fs_objects[] integrity-tag refresh was removed with the
     * capfs engine; only the encrypted object store above is rotated now.) */

    spin_lock(&storage_lock);
    intent_append(4 , uid, rotated, (uint32_t)read_tsc());
    spin_unlock(&storage_lock);

    return (int)rotated;
}

int storage_create_file(struct mounted_fs *mfs, uint32_t uid, uint32_t gid,
                        const char *name, uint64_t dir_ino, uint64_t *out_ino) {
    int64_t ino = storage_alloc_inode(mfs->bd, &mfs->sb);
    if (ino < 0) return -1;
    
    spin_lock(&storage_lock);
    intent_append(2 , (uint64_t)ino, dir_ino, uid);
    spin_unlock(&storage_lock);

    struct on_disk_inode inode;
    my_memset(&inode, 0, sizeof(inode));
    inode.uid = uid;
    inode.gid = gid;
    inode.mode = 0100644;
    inode.links = 1;

    /* Per-file key and IV from the central CSPRNG. The old code derived these
     * from a raw TSC read (predictable from ring 3) and additionally ran its
     * key loop to index 32 on a 16-byte array (out-of-bounds write). */
    secure_random_bytes(inode.file_key, sizeof(inode.file_key));
    secure_random_bytes(inode.file_iv, sizeof(inode.file_iv));

    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);
    storage_dir_add(mfs, dir_ino, name, ino, 1);

    *out_ino = ino;
    return 0;
}

/* A pointer block holds this many 64-bit block pointers. At BLOCK_SIZE=512 that
 * is 64 — NOT 1024. (An earlier single-indirect implementation used 1024 here,
 * which indexed a 512-byte stack buffer out of bounds for any file past block
 * 12+64; it was never hit because no test wrote a file that large.) */
#define PTRS_PER_BLOCK   (BLOCK_SIZE / (uint64_t)sizeof(uint64_t))

/* Fetch (and, when allocate!=0, lazily allocate) the physical block backing an
 * inode's logical block. Layout: 12 direct, then one single-indirect block
 * (PTRS_PER_BLOCK entries), then one double-indirect block (PTRS_PER_BLOCK
 * single-indirect blocks x PTRS_PER_BLOCK entries each). Returns the physical
 * block number, or 0 on absent/unallocatable/out-of-range. Pointer (indirect)
 * blocks are stored unencrypted — they hold block numbers, not file data — so
 * they use do_block_read/write directly, matching the single-indirect path. */
static uint64_t get_physical_block(struct mounted_fs *mfs, struct on_disk_inode *inode,
                                   uint64_t logical_block, int allocate) {
    struct block_device *bd = mfs->bd;
    struct fs_superblock *sb = &mfs->sb;

    if (logical_block < 12) {
        uint64_t phys = inode->direct[logical_block];
        if (phys == 0 && allocate) {
            phys = storage_alloc_block(bd, sb);
            if (phys == (uint64_t)-1) return 0;
            inode->direct[logical_block] = phys;
        }
        return phys;
    }

    logical_block -= 12;

    /* Single-indirect: one pointer block of PTRS_PER_BLOCK data blocks. */
    if (logical_block < PTRS_PER_BLOCK) {
        uint64_t indirect_phys = inode->indirect;
        if (indirect_phys == 0) {
            if (!allocate) return 0;
            indirect_phys = storage_alloc_block(bd, sb);
            if (indirect_phys == (uint64_t)-1) return 0;
            inode->indirect = indirect_phys;
            uint8_t zero[BLOCK_SIZE];
            my_memset(zero, 0, BLOCK_SIZE);
            do_block_write(indirect_phys, zero);
        }

        uint8_t indirect_block[BLOCK_SIZE];
        do_block_read(indirect_phys, indirect_block);

        uint64_t *ptrs = (uint64_t *)indirect_block;
        uint64_t phys = ptrs[logical_block];

        if (phys == 0 && allocate) {
            phys = storage_alloc_block(bd, sb);
            if (phys == (uint64_t)-1) return 0;
            ptrs[logical_block] = phys;
            do_block_write(indirect_phys, indirect_block);
        }
        return phys;
    }

    logical_block -= PTRS_PER_BLOCK;

    /* Double-indirect: a pointer block of PTRS_PER_BLOCK single-indirect blocks,
     * each mapping PTRS_PER_BLOCK data blocks. */
    if (logical_block < PTRS_PER_BLOCK * PTRS_PER_BLOCK) {
        uint64_t dbl_index = logical_block / PTRS_PER_BLOCK;   /* which single-indirect block */
        uint64_t sng_index = logical_block % PTRS_PER_BLOCK;   /* slot within it */

        /* Level 1: the double-indirect block (single-indirect block pointers). */
        uint64_t dbl_phys = inode->double_indirect;
        if (dbl_phys == 0) {
            if (!allocate) return 0;
            dbl_phys = storage_alloc_block(bd, sb);
            if (dbl_phys == (uint64_t)-1) return 0;
            inode->double_indirect = dbl_phys;
            uint8_t zero[BLOCK_SIZE];
            my_memset(zero, 0, BLOCK_SIZE);
            do_block_write(dbl_phys, zero);
        }
        uint8_t dbl_block[BLOCK_SIZE];
        do_block_read(dbl_phys, dbl_block);
        uint64_t *dptrs = (uint64_t *)dbl_block;

        /* Level 2: the single-indirect block for dbl_index. */
        uint64_t sng_phys = dptrs[dbl_index];
        if (sng_phys == 0) {
            if (!allocate) return 0;
            sng_phys = storage_alloc_block(bd, sb);
            if (sng_phys == (uint64_t)-1) return 0;
            dptrs[dbl_index] = sng_phys;
            do_block_write(dbl_phys, dbl_block);          /* persist the new L2 pointer */
            uint8_t zero[BLOCK_SIZE];
            my_memset(zero, 0, BLOCK_SIZE);
            do_block_write(sng_phys, zero);
        }
        uint8_t sng_block[BLOCK_SIZE];
        do_block_read(sng_phys, sng_block);
        uint64_t *sptrs = (uint64_t *)sng_block;

        /* Level 3: the data block. */
        uint64_t phys = sptrs[sng_index];
        if (phys == 0 && allocate) {
            phys = storage_alloc_block(bd, sb);
            if (phys == (uint64_t)-1) return 0;
            sptrs[sng_index] = phys;
            do_block_write(sng_phys, sng_block);
        }
        return phys;
    }

    /* Beyond double-indirect (12 + 64 + 64*64 = 4172 blocks): out of range.
     * The 2 MiB volume can never reach this, so it is a hard ceiling, not a
     * silent truncation of a reachable file. */
    return 0;
}

int storage_read_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, void *buf) {
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) return -1;

    uint64_t phys = get_physical_block(mfs, &inode, block, 0);
    if (phys == 0) return -1;

    uint8_t temp[BLOCK_SIZE];
    if (do_block_read(phys, temp) != 0) return -1;

    if (storage_decrypt_block(phys, ino, block, temp) != 0) {
        my_memset(buf, 0, BLOCK_SIZE);
        return -1;
    }

    my_memcpy(buf, temp, BLOCK_SIZE);
    return 0;
}

int storage_write_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, const void *buf) {
    /* One atomic transaction: the data-block allocation (block bitmap), the inode
     * link, the per-block crypto metadata (+ its superblock meta_hmac), and the
     * ciphertext all commit together or not at all. A crash therefore leaves the
     * file either fully before or fully after this write — never with a dangling
     * block or a meta_hmac that no longer matches the metadata region. */
    journal_begin();

    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { journal_abort(); return -1; }

    /* get_physical_block updates the inode's direct/indirect/double_indirect
     * mapping in place when it allocates, so just persist it. (The old explicit
     * inode.direct[block] fix-up here both duplicated that and indexed direct[]
     * out of bounds for block >= 12.) */
    uint64_t phys = get_physical_block(mfs, &inode, block, 1);
    if (phys == 0) { journal_abort(); return -1; }

    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);

    uint8_t temp[BLOCK_SIZE];
    my_memcpy(temp, buf, BLOCK_SIZE);

    if (storage_encrypt_block(phys, ino, block, temp) != 0) { journal_abort(); return -1; }
    if (do_block_write(phys, temp) != 0)                     { journal_abort(); return -1; }

    return journal_commit();
}

/* Free every data block an inode references (direct + single-indirect +
 * double-indirect) and release the inode, as one atomic transaction. Backs the
 * FS server's delete path via SYS_FS_INODE_FREE.
 *
 * The per-block crypto metadata (nonce/tag) of freed blocks is deliberately left
 * untouched: the blocks are deallocated in the bitmap, and when one is later
 * reallocated storage_encrypt_block overwrites its metadata with a fresh nonce,
 * so the stale entry is harmless. Clearing it here instead would flush one meta
 * sector (and its superblock meta_hmac) per freed block — many non-atomic writes
 * that both overflow the journal and risk the very meta_hmac desync the journal
 * exists to prevent. All the bitmap clears coalesce onto the single block-bitmap
 * sector, so the transaction is only ~3 sectors (block bitmap + inode + inode
 * bitmap). */
int storage_free_inode_blocks(struct mounted_fs *mfs, uint64_t ino) {
    journal_begin();

    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { journal_abort(); return -1; }

    for (int i = 0; i < 12; i++) {
        if (inode.direct[i]) {
            storage_free_block(mfs->bd, &mfs->sb, inode.direct[i]);
            inode.direct[i] = 0;
        }
    }
    if (inode.indirect) {
        uint8_t ib[BLOCK_SIZE];
        if (do_block_read(inode.indirect, ib) == 0) {
            uint64_t *ptrs = (uint64_t *)ib;
            for (unsigned k = 0; k < PTRS_PER_BLOCK; k++)
                if (ptrs[k]) storage_free_block(mfs->bd, &mfs->sb, ptrs[k]);
        }
        storage_free_block(mfs->bd, &mfs->sb, inode.indirect);
        inode.indirect = 0;
    }

    /* Double-indirect: free every data block via each single-indirect block,
     * then each single-indirect block, then the double-indirect block itself. */
    if (inode.double_indirect) {
        uint8_t db[BLOCK_SIZE];
        if (do_block_read(inode.double_indirect, db) == 0) {
            uint64_t *dptrs = (uint64_t *)db;
            for (unsigned d = 0; d < PTRS_PER_BLOCK; d++) {
                if (!dptrs[d]) continue;
                uint8_t sb2[BLOCK_SIZE];
                if (do_block_read(dptrs[d], sb2) == 0) {
                    uint64_t *sptrs = (uint64_t *)sb2;
                    for (unsigned k = 0; k < PTRS_PER_BLOCK; k++)
                        if (sptrs[k]) storage_free_block(mfs->bd, &mfs->sb, sptrs[k]);
                }
                storage_free_block(mfs->bd, &mfs->sb, dptrs[d]);
            }
        }
        storage_free_block(mfs->bd, &mfs->sb, inode.double_indirect);
        inode.double_indirect = 0;
    }

    inode.size = 0;
    inode.links = 0;
    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);
    storage_free_inode(mfs->bd, &mfs->sb, ino);
    return journal_commit();
}

int storage_write_capfs_blob(uint64_t inode, const void *data, size_t len) {
    (void)len;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs->mounted) return -1;
    return storage_write_file_block(mfs, inode, 0, data);
}

int storage_read_capfs_blob(uint64_t inode, void *data, size_t len) {
    (void)len;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs->mounted) return -1;
    return storage_read_file_block(mfs, inode, 0, data);
}

int storage_sync(void)
{
    
    spin_lock(&storage_lock);
    
    for (int i = 0; i < INTENT_LOG_SLOTS; i++) {
        intent_log[i].kind = 0;
        intent_log[i].arg0 = 0;
        intent_log[i].arg1 = 0;
        intent_log[i].gen  = 0;
    }
    intent_head = 0;
    intent_append(5 , 0, 0, 0);
    spin_unlock(&storage_lock);
    return 0;
}
