# 小星记账 (com.cxincx.xxjz) `.lch` backup format

Reverse-engineering notes for the Android app **小星记账 (com.cxincx.xxjz)**, APK
`4.0.8`. The goal is interoperability: decrypt a backup produced by the app and
read the transaction data offline.

> Scope: this documents the file format and how to read it. It contains no
> account numbers, no personal data, and no real transactions. Sample values in
> this document are placeholders.

## 0. Why the APK is not enough

The APK is hardened with **百度加固 (Baidu Protect)**:

* `assets/baiduprotect*.jar` / `baiduprotect-sec.dex` start with encrypted
  magic (`fe 70 59 ce`, `f6 4e …`);
* `classes.dex` / `classes2.dex` contain **zero** `Lcom/cxincx/...` class
  definitions — only third-party libraries (kotlin, okhttp, objectbox, bugly,
  umeng).

Static jadx therefore only yields third-party code. The app's own classes were
taken from a **runtime dump** of the live app (`/tmp/src_all/*/sources`, header
`/* JADX INFO: loaded from: /tmp/udex_N.dex */`). The relevant code lives under
`com/cxincx/xxjz/setting/backup/**`, `g4/**`, `h4/**`, and `c3/h.java`.

## 1. Overall nesting

```
*.lch
└─ WinZip AES-256 ZIP (zip4j, AE-2, DEFLATE)          ← layer 1
   └─ v<appVersion>_db2  =  ObjectBox data.mdb
      └─ LMDB environment                              ← layer 2
         └─ ObjectBox schema + object FlatBuffers      ← layer 3
```

The sibling `账单图片/` directory (bill images) and the `我的密钥` file are **not**
part of this encrypted archive.

## 2. Layer 1 — the `.lch` file is an encrypted ZIP

### 2.1 Export path

`g4/c.java` (base backup manager) copies the ObjectBox data file to the cache
and zips it:

```java
// g4/c.java
zArr[0] = com.cxincx.xxjz.utils.b.t(file, string, l.m());   // l = x9.l
```

```java
// com/cxincx/xxjz/utils/b.java:t()
h9.a aVar = new h9.a(str, str2.toCharArray());   // zip4j ZipFile + password
l lVar = new l();                                // o9.l == ZipParameters
lVar.c = true;                                   // encryptFiles
lVar.d = EncryptionMethod.AES;
lVar.f = AesKeyStrength.KEY_STRENGTH_256;
aVar.a(file, lVar);                              // addFile + write
```

`h9.a` is `net.lingala.zip4j.ZipFile`, `o9.l` is `ZipParameters`,
`c = encryptFiles`, `d = encryptionMethod`, `f = aesKeyStrength`.

### 2.2 Password

The password is a hard-coded constant, **not** device-derived, so backups are
portable across devices:

```java
// x9/l.java
public static String m() { return u(3).substring(2) + "w@"; }
...
if (i == 3) return ")dEuIDl^FFs29x1s";
```

```
u(3).substring(2) = "EuIDl^FFs29x1s"
m()               = "EuIDl^FFs29x1sw@"     ← zip password
```

`x9.l.u()` also contains an anti-piracy guard (throws for one known foreign
signature); it does not affect the password. `x9.l.l()` (Android ID) and
`x9.l.n()` are used elsewhere, **not** for the backup ZIP.

### 2.3 Restore path

`h4/b.java` decrypts with the same password:

```java
String strM = x9.l.m();
aVar = new h9.a(str, strM.toCharArray());
aVar.d(str2);          // extractAll
```

### 2.4 Exact crypto parameters

| item | value |
|---|---|
| algorithm | WinZip AES (AE-2), 256-bit |
| KDF | PBKDF2-HMAC-SHA1, 1000 iterations |
| salt | 16 random bytes (per archive) |
| derived key | 66 bytes = 32 AES + 32 HMAC + 2 verifier |
| cipher | AES-256-CTR (WinZip counter: little-endian `u32` in bytes 0–3, rest 0, starts at 1) |
| authentication | HMAC-SHA1 over the ciphertext, first 10 bytes stored |
| compression | raw DEFLATE |
| entry name | `v<appVersion>_db2` |

File naming: `v{appVersion}_{deviceModel}_{yyyy-MM-dd_HHmmss}_d{dbVer}b{dbVersion}.lch`,
e.g. `vA.B.C_DEVICE_YYYY-MM-DD_HHMMSS_dNNNNNb2.lch`.

Decryptor: `tmp/decrypt_lch.py`. The two independent checks (password verifier
and HMAC over ciphertext) both match on real files, which proves the key
derivation before any decompression is attempted.

```bash
python3 tmp/decrypt_lch.py BACKUP.lch -o out/
```

## 3. Layer 2 — LMDB container

`file` reports the decrypted payload as generic `data`. It is an **LMDB**
environment:

* 10,199,040 bytes = 2490 × 4096 → **4096-byte pages**;
* pages 0 and 1 are the two meta pages; little-endian magic
  **`0xBEEFC0DE`** at offset 16, LMDB version `1` at offset 20;
* one single LMDB database (no named sub-databases);
* 98,312 key/value entries.

Standard tools can read it:

```bash
mdb_stat -n data.mdb      # Main DB: depth 3, 2393 leaf pages, 98312 entries
mdb_dump -n data.mdb      # hex key/value pairs
```

### 3.1 Key families

ObjectBox multiplexes everything into the one LMDB database. Keys carry a
4-byte type prefix:

| key | shape | example | count | meaning |
|---|---|---|---|---|
| 8 B | `00 00 00 00 00 00 00 XX` | `…0006` | 47 | schema rows: key `0` = model header, keys `2…58` = one row per entity (46) |
| 8 B | `<prefix 18 00 00 XX>` + 4-byte id | `18 00 00 18 00 00 00 01` | 8369 | object data (id < 2³²) |
| 12 B | `<prefix 18 00 00 XX>` + 8-byte id | `18 00 00 09 00 00 01 7f …` | 4 | object data (id ≥ 2³²) |
| 12 B | `08 00 00 XX` + 8 B | `08 00 00 04 …` | 23553 | index entry (value empty) |
| 16 B | `20 00 00 XX` + 12 B | `20 00 00 14 …` | 62028 | index entry (value empty) |
| 20 B | `20 00 00 XX` + 16 B | `20 00 00 cc …` | 6 | index entry (value empty) |

The prefix identifies the entity/property index. For `DetailEntity` the data
prefix is `0x18000018` (8369 rows) and its six indexes are `0x20000014`,
`0x20000018`, `0x20000034`, `0x20000038`, `0x20000048`, `0x200000b0` — each
exactly 8369 rows. Prefixes must be discovered per entity; they are not simply
the entity id.

The 4th key byte is `entity_id << 2 | width`, where `width` is 0 for a 4-byte
object id and 1 for an 8-byte one. Ids from timestamp-style generators exceed
2³² and therefore use 12-byte keys — `AccountBookEntity` (账本) and
`CycleEntity` (周期) are the common cases. A reader that only matches 8-byte keys
silently drops those whole entities; match on `key[3] >> 2` and take the
remaining bytes as the id instead.

## 4. Layer 3 — ObjectBox schema and objects

### 4.1 Schema

The per-entity schema rows are ObjectBox `ModelEntity` / `ModelProperty`
FlatBuffers (schema in `objectbox-java`'s `model.fbs`). Every entity and
property carries an `IdUid` = `{u32 id; u64 uid}`. The top-level `Model`
flatbuffer also holds `lastEntityId`, `lastIndexId`, `lastRelationId`.

The model is **not** shipped in the APK. The app builds it in code with
ObjectBox's `ModelBuilder`:

```java
// c3/h.java
j8.f fVar = new j8.f();                       // ModelBuilder
fVar.d = 58; fVar.e = 0x…;                    // lastEntityId (id, uid)
fVar.f = 55; fVar.g = 0x…;                    // lastIndexId
fVar.h = 15; fVar.i = 0x…;                    // lastRelationId
j8.b e = fVar.c("SomeEntity");                // EntityBuilder
e.e(6, 0x…);                                  // entity id + uid
e.f(52, 0x…);                                 // lastPropertyId
e.d();                                        // entity flags = 1
e.g(6, "id", null, null).c(1, 0x…);           // property(type, name, target, virtual) + id/uid
e.g(11, "typeId", "TypeEntity", "type").c(14, 0x…).d(13, 0x…);  // relation + index
e.b();
```

`c3/h.java` adds ~29 entities inline and then calls `h4.b.c(fVar)` …
`h4.b.s(fVar)`, which add the rest. `tmp/parse_model.py` replays those
statements into an exact model JSON:

* 46 entities, 372 properties, 29 indexes (plus the top-level model row);
* `tmp/xxjz_objectbox_model.json`.

### 4.2 Object values

An object row is a FlatBuffer for the entity, with the key rule:

> **flatbuffer field index = property id − 1**

Property ids start at 1 and the `id` property is id 1 (field 0). Field types are
the ObjectBox enum:

| code | type |
|---|---|
| 1 | Bool |
| 5 | Int (i32) |
| 6 | Long (i64) |
| 7 | Float (f32) |
| 8 | Double (f64) |
| 9 | String (length-prefixed offset) |
| 10 | Date (i64 ms) |
| 11 | Relation (u64 target id) |

Strings/objects are standard FlatBuffer offsets; absent scalars are simply not
present in the vtable.

## 5. Reading the database

ObjectBox validates the model against the stored schema, so the exact model is
required. Procedure used here:

1. Decrypt `.lch` → `data.mdb`.
2. Copy `data.mdb` to a scratch directory (ObjectBox needs to persist a schema
   hash; open the **copy**, never the original backup).
3. Rebuild the model (`tmp/parse_model.py`) and build it through the ObjectBox C
   API (`tmp/open_db.py`), including relations via
   `obx_model_property_relation`.
4. Read each entity box inside a read transaction and decode objects with
   `slot = property id − 1` (`tmp/decode_obx.py`).

```bash
# requires the `objectbox` Python package (C API bindings)
python3 tmp/parse_model.py                       # writes /tmp/obx_model.json
cp data.mdb scratch/data.mdb
python3 tmp/open_db.py                            # opens scratch/, prints counts
python3 tmp/decode_obx.py DetailEntity 20         # first 20 transactions as JSON
```

Note: `obx_opt_read_only(True)` fails with *“Can not update schema when opening
in read-only mode”* against a 4.0.8 backup; a writable copy works and preserves
every row (verified by row counts, e.g. `DetailEntity` stays at 8369).

## 6. Entity catalogue (4.0.8 backup)

Populated entities, by object count:

| entity | id | rows | props |
|---|---|---|---|
| DetailEntity | 6 | 8369 | 44 |
| AutoBookMapEntity | 35 | 1320 | 3 |
| AutoTypeMapEntity | 19 | 1073 | 3 |
| ItemTypeEntity | 13 | 664 | 11 |
| ItemTypeAccountMapEntity | 22 | 261 | 2 |
| ItemTypeMemberMapEntity | 25 | 261 | 1 |
| SmsEntity | 30 | 234 | 4 |
| SearchHistoryEntity | 27 | 105 | 5 |
| AutoAccountMapEntity | 18 | 78 | 3 |
| TypeEntity | 14 | 57 | 8 |
| CurrencyEntity | 31 | 50 | 9 |
| AutoTagMapEntity | 34 | 34 | 2 |
| AutoMemberMapEntity | 38 | 30 | 2 |
| TagEntity | 26 | 29 | 9 |
| MemberEntity | 7 | 24 | 7 |
| AccountEntity | 3 | 21 | 30 |
| AppConfigEntity | 51 | 11 | 3 |
| AccountBalanceEditEntity | 44 | 10 | 2 |
| CycleEntity | 21 | 9 | 23 |
| TagGroupEntity | 42 | 8 | 5 |
| DetailLinkEntity | 53 | 7 | 2 |
| AccountGroupEntity | 20 | 6 | 5 |
| AccountBookEntity | 2 | 4 | 14 |
| AutoRemarkMapEntity | 33 | 4 | 4 |
| BudgetGroupEntity | 56 | 4 | 5 |
| BudgetItemEntity | 28 | 4 | 25 |
| ShopGroupEntity | 45 | 4 | 5 |
| DbFixEntity | 50 | 3 | 3 |
| PraiseEntity | 49 | 2 | 5 |
| AutoDraftEntity | 40 | 1 | 5 |
| BudgetEntity | 4 | 1 | 8 |
| ConfigEntity | 17 | 1 | 35 |
| DetailRestartConfig | 47 | 1 | 8 |
| ImportBillEntity | 23 | 1 | 3 |

(The remaining model entities exist in the schema but hold no rows.)

### 6.1 `DetailEntity` fields

`property id` is the flatbuffer field index + 1.

| id | field | type | notes |
|---|---|---|---|
| 1 | id | Long | primary key |
| 2 | time | Date | transaction time, ms epoch |
| 13 | detailType | Int | transaction kind |
| 4 | amount | Double | book-currency amount |
| 5 | currency | Int | currency index |
| 45 | baseCurrency | Int | |
| 33 | currencyAmount | Double | |
| 48 | accountAmount | Double | amount in account currency |
| 49 | accountAmount2 | Double | second account leg |
| 46 | baseCurrencyAmount | Double | |
| 44 | currencyRate | Float | |
| 6 | isReimbursement | Bool | |
| 23 | bx | Int | |
| 7 | remark | String | |
| 16 | isDelete | Bool | soft delete flag |
| 19 | amountDisplay | String | |
| 42 | amountRawDisplay | String | |
| 20 | itemTypeName | String | category name |
| 21 | typeName | String | type name |
| 29 | tagName | String | |
| 38 | shopName | String | |
| 22 | from | Int | |
| 24 | cycleId | Long | |
| 25 | refundAmount | Double | |
| 34 | refundCurrencyAmount | Double | |
| 26 | refundAccountId | Long | relation |
| 27 | img | String | |
| 31 | installment | Int | |
| 32 | isPre | Bool | |
| 35 | isNotInclude | Bool | |
| 36 | preferentialAmount | Double | |
| 41 | bxAmount | Double | |
| 40 | bxCurrencyAmount | Double | |
| 47 | borrowDate | Date | |
| 52 | lastUpdateTime | Long | |
| 43 | memberAmount | String | |
| 14 | typeId | Relation | → `TypeEntity` |
| 15 | itemTypeId | Relation | → `ItemTypeEntity` |
| 11 | accountId | Relation | → `AccountEntity` |
| 17 | account2Id | Relation | → `AccountEntity` |
| 12 | accountBookId | Relation | → `AccountBookEntity` |
| 37 | shopId | Relation | → `ShopEntity` |
| 50 | linkId | Relation | → `DetailLinkEntity` |
| 51 | locationId | Relation | → `LocationEntity` |

Relation IDs are plain foreign keys; resolve them against the target entity.
Book/account ids are sometimes self-assigned timestamps, so they can look large.

## 7. Tools

| file | purpose |
|---|---|
| `tmp/decrypt_lch.py` | `.lch` → decrypted `data.mdb` |
| `tmp/parse_model.py` | replay the model-builder code → `tmp/xxjz_objectbox_model.json` |
| `tmp/xxjz_objectbox_model.json` | reconstructed ObjectBox model (ids/uids/types/indexes/relations) |
| `tmp/open_db.py` | build the model through the ObjectBox C API and open the store |
| `tmp/decode_obx.py` | read one entity's objects and decode the FlatBuffer |

Dependencies: `parse_model.py` needs the runtime dump at `/tmp/src_all`;
`open_db.py` / `decode_obx.py` need the `objectbox` Python package (tested with
4.0.0). `tmp/` is not tracked by git.

## 8. Bean-sieve integration

`bean-sieve` ships a provider for these backups: `src/bean_sieve/providers/payment/xiaoxing_backup.py`
(`provider_id = "xiaoxing_backup"`), with the decoders in
`src/bean_sieve/providers/payment/_xxbackup.py`. It performs the whole pipeline
in memory - AES decrypt, LMDB walk, FlatBuffer decode - and needs no
`objectbox` package. It accepts either one `.lch` file or a backup directory;
a directory resolves to the newest `.lch` in it, ordered by the timestamp in
the file name and falling back to the modification time. Refund legs (rows of
`detailType` 4 / `from` 5 tied to their parent by `cycleId`) net into the parent
amount and feed the `refund` / `refund_account` metadata, mirroring the
`xiaoxing` XLS provider.

Foreign-currency rows store the book-currency amount in `amount` (property 4)
and the pre-conversion amount in `currencyAmount` (property 33). The provider
reports the book amount as the transaction amount/currency and moves the
pre-conversion amount to `original_amount` / `original_currency`, matching the
credit-card providers. `linkId` (property 50) resolves against
`DetailLinkEntity` (53) to fill `metadata["link"]`. `baseCurrency` (45) is
never populated in 4.0.8, so the book currency defaults to CNY.

## 9. Caveats

* The Baidu-protected APK alone is not sufficient; the app classes came from a
  runtime dump. The model is version-specific — a different app version can
  change entity/property ids, uids and the hard-coded password.
* Open ObjectBox on a **copy** of `data.mdb`; the core updates the schema hash.
* The password constant and this document are for interoperability with your
  own backups. Do not put real statement data into the repository; test
  fixtures must be synthetic.
