# Changelog

The per-patch-set breakdown, newest first. Each set is built on top of
the previous one; see the README for the build pipeline and the feature
overview.

## Patch set v11 — ESR counter grouping + Use UTF-8 option

Patch set v11 (`build-patched-v11.py`) is built **on top of patch set v10**
and adds the features below plus a version stamp (version **3.43.104.5**,
file size unchanged; the .text ESR sites stay virgin — only the seven
utf8e hook sites, ≤6B each, are touched in .text). The new caves are
assembled from the `.s` sources in the `asm/` folder:

* **ESR grouping of read-only counters** — a single `.rdata` vtable slot
  swap (0x596CE0, the plain-u64 type slot) redirects the number→string
  conversion to a new cave (`asm/esrc_conv.s`, 136B @0x65B500): a div-10
  loop, digit groups of 3, a space separator, the full u64 range,
  negatives handled exactly like the stock formatter. Read Ops 8.6e9
  renders as "8 589 934 747". Unlike the v10 ESR revert (which removed
  the grouping from every field to fix the editable-field regression),
  this targets the u64 type slot only — the read-only counters get the
  grouping back with **zero .text edits** (the old formatter and its
  thunk become dead code, left untouched).
* **"Use UTF-8" option** — a compatibility layer for the non-English data
  WinBox 4 writes: WB4 stores Russian list comments and WiFi names as
  UTF-8, which stock WB3 (an ACP/cp1251 application) renders as mojibake
  and sends back mangled. With the option ON the client converts at the
  M2 boundary — UTF-8→ACP on receive, ACP→UTF-8 on send — so a Russian
  comment left in WinBox 4 becomes readable and a Russian WiFi SSID
  reaches the router as proper UTF-8. OFF by default = byte-for-byte
  stock behavior (`asm/utf8_option.s`, a 1555B cave @0x65B600 + seven
  .text hooks, 25B total):
  * receive: UTF-8→ACP on the way into the model (storage_conv, a hook
    in the M2 value decoder) — the whole model (the list, dialog boxes,
    send defaults) sees a consistent ACP;
  * send native-edit: ACP→UTF-8 after GetWindowTextA (conv_gwta; the
    edit-field reserve is doubled by stub_dblres);
  * send canvas: ACP→UTF-8 (cf286_hook, gated by the caller return
    address) — covers the WiFi SSID and other canvas field editors;
  * menu: a "Use UTF-8" checkbox (id 0x99A) + utf8.dat persistence in
    the profile folder.
* **Version stamp**: `3.43.104.4` → `3.43.104.5`.

Trade-offs: unsigned, 2,483,712 bytes; needs GNU binutils to build.

## Patch set v10 — ESR number-grouping revert + RouterOS 7.24.5 handle leak

Patch set v10 (`build-patched-v10.py`) is built **on top of patch set v9**
and adds the fixes below plus a version stamp (version **3.43.104.4**, file
size unchanged). The new cave is assembled from the `.s` source in the
`asm/` folder; the two ESR sites are restored byte-exact from the original
`winbox64.v3.43.exe` (the source of truth — no hardcoded hex strings):

* **ESR number-grouping regression fixed** — an old in-place replacement of
  the common number→string converter (meant for the Stats counters only)
  added space-grouping every 3 digits and hit **every** numeric field: the
  Partition Offset showed "65 536" with a RED mark (validation rejects the
  space — the stock WB4-consistent semantics), the Disks "+" button aborted
  on `def:65536`, and Apply threw "Error — number expected!". Both ESR
  sites (the converter body @0x46BF23, 142B, and the call site @0x46810F,
  12B) are copied byte-exact from the original binary — the grouping is
  gone completely (= WB4 behavior). Read-only counters ("1 176") use the
  native wb3 path and are not touched.
* **RouterOS 7.24.5 connection fix** — on 7.24.x the jg files carry no
  `bignumberrange`, so the Range pre-check took its not-found branch —
  which jumped past the CloseHandle block (0x65915A–0x659186), leaving the
  jg file handle open → a share-lock on roteros.jg → "could not open" →
  "Could not start plugins" → disconnect. The range pre-check cave
  (`asm/range_marker_gate_p10.s`, @0x65A700, 65B) is reassembled with the
  not-found jmp routed through the CloseHandle block (0x659187 →
  0x65915A, a 1-byte change inside the rel32).
* **Version stamp**: `3.43.104.3` → `3.43.104.4`.

Trade-offs: unsigned, 2,483,712 bytes; needs GNU binutils to build.

## Patch set v9 — Policy Rules fix + in-memory Ping/Traceroute fields

Patch set v9 (`build-patched-v9.py`) is built **on top of patch set v8** and
adds the fixes below plus a version stamp (version **3.43.104.3**, file size
unchanged, `.text` untouched — everything lives in `.wbox`). The new caves
are assembled from the `.s` sources in the `asm/` folder:

* **Policy Rules fix** — Routing → Settings → Policy Rules showed a red
  mark on the first open (a race: the `strict:1` validation fired before
  the chains arrived from the router; the second open was black only
  thanks to the chain cache), and Apply with an empty string failed with
  "Error in - selection expected!" even for a no-op. Fixed by a
  same-length jg grammar edit: `strict:1` → `min:1`.
* **Ping/Traceroute fields regression fixed** — in v8 the Interface/VRF
  injections were accidentally dead code (the fopen hook had been
  retargeted to the Range-only jgmem cave, so the fields stopped
  rendering — a v8 regression). A unified cave now performs the Ping
  (Interface/VRF) + Traceroute (Interface/VRF) injections in-memory,
  piecewise-idempotently — reopening the dialogs never duplicates the
  fields.
* **100% in-memory jg machinery** — the dead disk-write-era stab is fully
  cleaned (it wrote +367B of injections ON DISK, polluted the cache and
  changed the md5); a Range pre-check activates the transformation only
  when `bignumberrange` is really present in the buffer, and a piecewise
  fseek correction keeps the reads coherent across the three insertions.
  The on-disk file stays virgin (md5 before = after).
* **Version stamp**: `3.43.104.1` → `3.43.104.3`.

Trade-offs: unsigned, 2,483,712 bytes; needs GNU binutils to build.

## Patch set v8 — Win7 launch + NTP/Range display + Apply fix + heap shield

Patch set v8 (`build-patched-v8.py`) is built **on top of patch set v7** and
adds five components plus a version stamp (version **3.43.104.1**, file
size unchanged). The new caves are assembled from the `.s` sources in the
`asm/` folder:

* **Win7 launch fix** — Win7 has no `GetDpiForWindow`. The fallback return
  site is re-aimed at a tiny helper that arms a marker; a bridge in the
  host function takes the fallback path **only when the marker is armed** —
  on Win10 the fallback is unreachable, so the behavior stays stock there.
* **NTP/Range field display** — RouterOS 7.25+ sends fields of the new
  types `bigfixedpoint` (NTP Time/Offset/Delay…) and `bignumberrange`;
  the stock parser skips them, leaving the dialogs empty. The cave masks
  the type names to ones the client knows (`bigfixedpoint`→`bignumber`,
  `bignumberrange`→`numberrange`) before parsing — the fields render.
* **Num Set → Apply fix** — Apply rejects Range input on 7.25+ ("num range
  not specified"). The cave keeps a transformed **in-memory image** of
  `roteros.jg` (Range: `bignumberrange` → a tuple of two `bignumber`,
  idempotent; the on-disk file is never touched) and serves it through
  `fopen`/`fread`/`fseek`/`fclose` interception, with a strict
  roteros.jg-path handle gate cleared on `fclose` (msvcrt reuses `FILE*`
  structs — without the clearing the icon sprites and foreign jg files
  would receive foreign data).
* **Stronger heap shield** — replaces the v7 free-shield's badsize check
  (a leak source) with pure address checks plus a parse-arena signature,
  and adds **double-free protection** for the Dashboard
  element builder: three dedup caves check the target against a ring of
  recent frees with fresh stamps (an instant burst = a true double-free
  → skip; a stale stamp = the block was reallocated → a legit free).
* **Version stamp**: `3.43.103.77` → `3.43.104.1`.

Trade-offs: unsigned, 2,483,712 bytes; needs GNU binutils to build.

## Patch set v7 — CMR improvements + dynamic title + Ping/Traceroute fields

Patch set v7 (`build-patched-v7.py`) is built **on top of patch set v6** and
adds seven patch steps plus the final version stamp. All new caves are
assembled from the cave sources in the `asm/` folder with the real GNU
toolchain — the same pipeline as the v4 converter blobs:

* **`.wbox` grows by 64KB** (SizeOfImage `0x258000`→`0x268000`,
  VirtualSize/RawSize `0x20000`→`0x30000`; new free zone VA
  `0x658000`–`0x668000`).
* **CMR improvements — Dashboard free-shield** (68B cave at
  `0x658000`): the hook at `0x4CF0DA` validates the CRT allocation header at
  `[buf-8]` before `free` — the confirmed Dashboard crash fix. The v5 layer-3
  child-validation hook is retired (restored to pristine bytes): the
  free-shield handles the Dashboard properly.
* **Fixed a patch set 5 regression — disappearing fields**: the v5 layer-3
  child-validation hook skipped dialog children that failed its string
  check, which made the `Check For Updates` field in System → Packages and
  the `repull`/`save` fields in Container disappear. Retiring the hook
  (step 2) eliminates the regression.
* **Window title, rebuilt on toggle** (782B cave at
  `0x65B07E`, four retarget hooks) — the esr5 "Swap title order" mechanic.
* **Dynamic-version window title** (145B cave at
  `0x657C00`): replaces the previous title-tail mechanic at hook `0x4B49F8`;
  the `" - WinBox "` prefix is static and the version is read from the PE
  title on every call, so the window title always matches the stamped
  version.
* **Ping/Traceroute dialog fields + CMR types** (cave at
  `0x65B400`, hook `0x4B7A17` `fopen`): restores the `Interface`/`VRF`
  fields in the Ping and Traceroute dialogs of `roteros.jg` — fields
  MikroTik themselves dropped already in RouterOS 7.2x, so the original
  client lost them too (General:
  Ping To → Interface → VRF → ARP Ping…), applies the CMR type fixes to
  `cmr.jg` (drop-`enmbools` → unwrap-`tag` → `tags`-to-multi), closes the
  read handle before writing (sharing-violation fix) and gates every
  injection by scanning the dialog zone, so fields are never duplicated.
  The stab data at `0x65CE00` (340B from `icons/cmr_icons.bin` — the CMR-mechanics
  markers/templates, incl. the Dashboard icons) is restored after the stab
  code, which is what keeps the CMR icons working.
* **Version stamp**: `3.43.103.04` → `3.43.103.63` (8 bytes) and then the
  integrated `setversion()` stamps the final **`3.43.103.77`** — the ANSI
  titles plus the UTF-16 FileVersion/ProductVersion fields; the window
  title syncs automatically (the step-5 cave reads the PE title on every
  call).
* **Internal build testing under strict PageHeap**: the builds are
  smoke-tested internally with full-page heap verification enabled via the
  Image File Execution Options registry flags
  (`"GlobalFlag"=dword:02000000`, `"PageHeapFlags"=dword:00000003`) —
  heap corruptions, overruns and frees of invalid blocks surface
  immediately instead of staying silent.

Trade-offs: unsigned, 2,483,712 bytes (the file grows by 64KB); needs GNU
binutils to build. The icon mechanics stay byte-identical to v6 (verified).

## Patch set v6 — WiFi realms-raw + ENV TZ widget + ESR usability set

Patch set v6 (`build-patched-v6.py`) is built **on top of patch set v5** and
adds three feature layers plus a version stamp (20 byte clusters, 748
bytes, file size unchanged) — every patch is
documented ("what it is responsible for") inside the build script:

* **WiFi `interworking.realms-raw`**: saving a WiFi object no
  longer submits an empty `realms-raw`. A hook in the wire-serializer's array
  branch reroutes to a `.wbox` stub that skips the node entirely when the
  value is empty (varnum `0xd00d`); non-empty user values are encoded as before.
* **Container `ENV`**: the corner TZ widget of the ENV
  element is hidden, DPI-invariantly — a stub in the geometry setter checks
  the element's vtable (`0x5a6138`) and a `w*10 < h*7` ratio gate.
* **ESR usability set** (by **teslasystems** — MikroTik Forum user
  [@teslasystems](https://forum.mikrotik.com/u/teslasystems); see Credits):
  * **Ctrl+wheel zoom** in list windows;
  * **Stats counters ≥ 10^9** — a new CRT-free number converter with
    thousands grouping replaces the broken sprintf path on Stats;
  * **window title** shows `… — RouterOS v<ros> via WinBox 3.43.103.04`
    (the router version in the title tail instead of the client name);
  * **Log Entry**: `ES_NOHIDESELECTION` on the Message edit — the selection
    stays visible when the control loses focus;
  * **filter-value swap fix** — the swap functions are retargeted to a
    rebased copy in the `.wbox` corridor (out of the startup runtime cells).
* **Version stamp**: resource ProductVersion/FileVersion → `3.43.103.04`
  (title pieces via the `2.98`→`3.04` imm32 clusters).

Trade-offs: same as v5 (unsigned, 2,418,176 bytes).

## Patch set v5 — RouterOS 7.26 / initial CMR support

Patch set v5 (`build-patched-v5.py`) is built **on top of patch set v4** and
makes WinBox 3.43 usable against RouterOS 7.26 with the `cmr` package
installed. Four layers, all inside
`.text` hooks + `.wbox` caves:

* **CMR table model-unfolding**: RouterOS 7.26+CMR wraps the table
  properties (`path`, `c:` with the columns) into a `model:{...}` node; the
  'table' handler only looked for them on the node itself → zero columns →
  crash (AV `0x47c65e`) right after connect. A hook in the property loop
  reroutes unknown properties to a cave that unwraps `model` nodes and
  re-enters the loop head (`path`/`c` keep working natively).
* **Dashboard NULL-resource guard**: the virtual selector of Dashboard
  objects returns NULL/dangling; a cave skips the resource read when the
  selector result is NULL (AV `0x49705b` on opening the CMR Dashboard).
* **Dashboard child validation**: children fed to the notify loop carry a
  child-array instead of an `nv::string`; borrowing that garbage string
  corrupted the heap. The cave validates the string (non-NULL, inner
  pointer in the heap window, sane length) before the borrow and exits
  through the function epilogue on failure.
* **CMR menu icons**: 9 icons rasterized from the webfig 7.26 inline-SVG
  CSS into cells 48, 49, 52–58 (row 1) of the embedded sprites
  (`icons/icons16/24/32-cmr.png`); the sprites are replaced in place inside
  `.wbox` — the new PNGs are smaller, the rest of each zone is
  zero-padded (the PNG parser stops at IEND; the startup extractor's size
  table stays valid).

No version-stamp change. Trade-offs:
same as v4 (unsigned, 2,418,176 bytes).

This is a *stability* fix, not full CMR support: the WinBox 3 parser still
does not know the CMR field/container types — see the Roadmap.

## Patch set v4 — bytes/bigbytes value editors

Patch set v4 (`build-patched-v4.py`) is built **on top of patch set v3** and
restores the two value editors broken since RouterOS 7.2x (an older
WinBox 3 bug; lineage v98 of the
community patch):

* **`bytes` fields (u32)** — the field that triggered the analysis is
  *IPv4 → Settings → Fragment Threshold*: the
  router stopped sending the `bytes` field converter, so WinBox 3.43 shows
  such fields red and silently discards every edit (the defect affects all
  writable bytes fields). The patch wires the converter's empty parse/commit
  slots to a hand-written parser that accepts the WinBox4 grammar
  (KiB/MiB/GiB/TiB binary, k/M/G/T decimal, bare `B`, empty = 0, clamped
  to 0xFFFFFFFF).
* **`bigbytes` fields (u64)** — the Container one: *Container → Shm Size*,
  plus the other 64-bit fields (tmpfs/memory
  limits, disk file size/offset): the 64-bit variant of the same problem;
  a separate u64 parser + commit stub restores editing.
* **Version stamp**: window titles and VERSIONINFO show `3.43.102.98`.

The two converter blobs are **not hardcoded**: their assembly sources
(kept in the `asm/` folder) are assembled with the real GNU toolchain
(`as` + `ld -Ttext` + `objcopy`) by `build-patched-v4.py` itself — the same
pipeline as patch set v7 (it needs binutils: preinstalled on Linux/CI, WSL or
MinGW on Windows). The blobs are not verified separately; the final exe is
verified as a whole by its SHA-256. The converter bridges and the rest of
the value-commit chain are left untouched.

Trade-offs: same as v3 (unsigned, 2,418,176 bytes).

## Patch set v3 — Win11 launch fix + Switch icon + Format Drive guard

Patch set v3 (`build-patched-v3.py`) is built **on top of patch set v2** and
adds three functional tweaks plus a new version stamp (lineage v83 of the
community patch):

* **Win11 launch fix**: the `.wbox` entry wrapper gets `sub/add rsp,8`
  around its frame, so `rsp` is 16-byte aligned at WinAPI calls — without it
  Windows 11 crashes with `MOVAPS` inside `CreateFileA` during the icon
  extraction (the PNG-table `lea` disp and the final `jmp` are re-aimed
  accordingly).
* **Format Drive NULL-guard** (`.text` cave): a NULL pointer in the
  Format Drive / Power Cycle dialog path returned garbage and crashed the
  client; the guard makes it return safely instead.
* **Switch icon (CHR)**: a 120-byte lazy `getIcon` blob in `.wbox`
  (basis `0x638300`) with the icon slot re-pointed to it — fixes the empty
  Switch icon on CHR routers (looks up glyph 24 when the item name is
  `Switch`, caches the result).
* **Version stamp**: window titles and VERSIONINFO show `3.43.102.83`.

Trade-offs: same as v2 (unsigned, 2,418,176 bytes); `VS_FIXEDFILEINFO`
keeps the v2 value, matching the reference build.

## Patch set v2 — embedded icons + version stamp

Patch set v2 = patch set v1 plus everything needed to make the patched client a
single self-contained file (consolidated from the whole icon-integration
development series into one deterministic build step, `build-patched-v2.py`):

* **New RWX section `.wbox`** (RVA `0x238000`, 0x20000 bytes, appended after
  `.reloc`) holding a 472-byte startup extractor and the three icon sprites
  (`icons/icons16/24/32.png`, byte-identical to the RouterOS 7.24.5 webfig
  files).
* **Startup icon extraction**: `AddressOfEntryPoint` is redirected to the
  extractor. Before the original `mainCRTStartup` runs, it unpacks the three
  PNGs to `%TEMP%\icons16/24/32.png` (plain KERNEL32 calls:
  `GetTempPathA`/`CreateFileA`/`WriteFile`/`CloseHandle`) and wires the icon
  loader's built-in fallback structures (`VirtualProtect` on the read-only
  `.rdata` globals, P-slots/Q-structures in `.wbox`). WinBox then finds its
  icons regardless of the working directory — no files needed next to the exe.
* **Version stamp**: window titles and the VERSIONINFO resource
  (FileVersion/ProductVersion, Details tab) show `3.43.102.38`, so the patched
  build is easily distinguishable from a stock 3.43.
* **Authenticode signature is dropped** (unavoidable: the image grows and the
  certificate no longer matches); the Security directory entry is zeroed and
  the checksum cleared.

Trade-offs: the file grows from 2,295,976 to 2,418,176 bytes; SmartScreen may
warn about the unsigned binary. Patch set v1 remains available for anyone who
prefers the minimal patch and placing the three PNG files next to the exe.

## Patch set v1 — startup compatibility

All offsets are file offsets (`VMA − 0x400C00`); "cave" = hand-written code placed into
dead assert/log blocks.

| # | Location (VMA) | What it does | Trade-off |
|---|---|---|---|
| 1 | `0x4FA51C` | Ignore the server-advertised minimum WinBox version (`jbe` → `jmp`) | none |
| 2 | `0x4FA991` | Always take the built-in "no skin" branch instead of downloading the router skin | user skins/layouts from the router are not loaded |
| 3 | `0x4A7945` + cave `0x4FD931` | Menu parser: `title ?: name` fallback before `strlen` | none |
| 4 | `0x4A28AA`, `0x49DCB8` | Unknown field types are skipped (instead of an assert crash); unknown conv types degrade to the `u32_u32` handler | NTP windows lose 9 `bigfixedpoint` / 1 `bignumberrange` fields; Power Cycle / Format Drive pre-fill may not work |
| 5 | `0x4A3799` + cave `0x49DD4A` | Guard id-less `multinumber` fields: NULL id → full frame unwind → field skipped | none |
| 6 | `0x4837A0` | Defuse the `SlotRef … slot not found` assert → graceful exit | none |
| 7 | `0x4A1426` + cave `0x483724` | Check for the `id` property **before** any allocation; skip id-less fields cleanly. A return-address guard rejects accidental entries into the cave | the Interfaces column in the Power Cycle dialog is not built |
| 8 | `0x4A0DFC` + cave `0x49DD6F` | Field-parser entry guard: if called with a small integer (7.25 resolves `multicmdsrc` by slot number, not node pointer) → return NULL → field skipped | none |
| 9 | `0x492DEE` | Defuse the `no slot found for cond` assert → return NULL via the function epilogue | none |
| 10 | `0x484862` + cave `0x49DD85` | Skip NULL holes in the window children array left by the skip in #7 (the indexer would write to `0+0x18`) | none |
| 11 | `0x4A7420` + cave `0x483781` | Menu index builder (opening tabs): the same `title ?: name` fallback; the leftover original builder call is nop'd out | none |
| 12 | `0x4A7119` | QuickSet: third consumer of `title` → reuse the same fallback cave | none |
