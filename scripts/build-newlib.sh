#!/bin/sh
# Reproducibly build the newlib libc port used by Horus's newlib userspace
# (hello_newlib + the POSIX fd layer) into newlib/install/i686-elf.
#
# There is no real i686-elf cross toolchain: newlib is built with host `gcc` in
# freestanding -m32 mode via thin i686-elf-* shims, exactly as the tracked-working
# install was produced. Idempotent, pinned, and offline-friendly (a cached tarball
# matching the checksum is reused instead of re-downloaded). Used by `make newlib`
# and by the smoke-newlib CI job.
set -eu

NEWLIB_VERSION="4.5.0.20241231"
NEWLIB_SHA256="33f12605e0054965996c25c1382b3e463b0af91799001f5bb8c0630f2ec8c852"
NEWLIB_URL="https://sourceware.org/pub/newlib/newlib-${NEWLIB_VERSION}.tar.gz"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
# Overridable for testing; defaults to the tree the Makefile expects.
NEWLIB_DIR="${NEWLIB_DIR:-$REPO_ROOT/newlib}"

PREFIX="$NEWLIB_DIR/install"
TOOLS="$NEWLIB_DIR/tools"
SRC="$NEWLIB_DIR/src"
BUILD="$NEWLIB_DIR/build"
TARBALL="$NEWLIB_DIR/newlib-${NEWLIB_VERSION}.tar.gz"

# Idempotent: a complete install (incl. the stdio64 patch below) means nothing to
# do — the fast path on a cache hit. Checking __swrite64 forces a rebuild of a
# stale/incomplete cached archive rather than silently reusing it.
if [ -f "$PREFIX/i686-elf/lib/libc.a" ] && [ -f "$PREFIX/i686-elf/include/stdio.h" ] &&
   nm "$PREFIX/i686-elf/lib/libc.a" 2>/dev/null | grep -q 'T __swrite64'; then
    echo "newlib already present and complete at $PREFIX — nothing to do."
    exit 0
fi

mkdir -p "$NEWLIB_DIR" "$TOOLS"

# i686-elf-* shims: host gcc/binutils in freestanding -m32 mode. No cross gcc.
cat > "$TOOLS/i686-elf-gcc" <<'SH'
#!/bin/sh
exec gcc -m32 -ffreestanding -fno-stack-protector -fno-builtin "$@"
SH
cp "$TOOLS/i686-elf-gcc" "$TOOLS/i686-elf-cc"
printf '#!/bin/sh\nexec ar "$@"\n'      > "$TOOLS/i686-elf-ar"
printf '#!/bin/sh\nexec ranlib "$@"\n'  > "$TOOLS/i686-elf-ranlib"
printf '#!/bin/sh\nexec strip "$@"\n'   > "$TOOLS/i686-elf-strip"
printf '#!/bin/sh\nexec readelf "$@"\n' > "$TOOLS/i686-elf-readelf"
chmod +x "$TOOLS"/i686-elf-*

# Fetch + verify source (reuse a cached tarball only if it matches the checksum).
if [ ! -f "$TARBALL" ] || ! printf '%s  %s\n' "$NEWLIB_SHA256" "$TARBALL" | sha256sum -c - >/dev/null 2>&1; then
    echo "Downloading newlib ${NEWLIB_VERSION} ..."
    curl -fsSL "$NEWLIB_URL" -o "$TARBALL"
fi
printf '%s  %s\n' "$NEWLIB_SHA256" "$TARBALL" | sha256sum -c -

# Extract fresh.
rm -rf "$SRC"; mkdir -p "$SRC"
tar -xf "$TARBALL" -C "$SRC" --strip-components=1

# Configure + build + install — the exact recipe behind the working install.
rm -rf "$BUILD"; mkdir -p "$BUILD"
cd "$BUILD"
PATH="$TOOLS:$PATH" "$SRC/configure" \
    --target=i686-elf --prefix="$PREFIX" \
    --disable-multilib --disable-newlib-supplied-syscalls \
    --enable-newlib-reent-small --enable-newlib-io-c99-formats
# Build ONLY the newlib libc for the target — Horus supplies its own crt0/syscalls
# (userspace/newlib_glue.c, crt0.c, posix.c) and links -lc, so libgloss (board
# bring-up / monitor stubs, which also fails to build under modern gcc) is neither
# built nor needed.
# Serial build: newlib's recursive makefiles race under -j and can drop objects
# (e.g. stdio64.o, leaving __swrite64/__sseek64 undefined). It is small; a serial
# build is a few minutes and is cached, so reliability wins over speed here.
PATH="$TOOLS:$PATH" make all-target-newlib
PATH="$TOOLS:$PATH" make install-target-newlib

# findfp.c references __swrite64/__sseek64 because newlib defines __LARGE64_FILES
# for this target, but the full libc/stdio64 dir won't build freestanding
# (fseeko64.c needs a complete `struct stat` we don't supply with
# --disable-newlib-supplied-syscalls). Compile just stdio64.c — which defines
# exactly those two large-file stdio helpers — and add it to the installed archive
# so any stdio use links. (Horus does its own file I/O; the 64-bit path is unused.)
NLSRC="$SRC/newlib"
"$TOOLS/i686-elf-gcc" -O2 -DHAVE_CONFIG_H -D_COMPILING_NEWLIB \
    -I"$NLSRC/libc/stdio" -I"$NLSRC/libc/stdio64" \
    -I"$BUILD/i686-elf/newlib" -I"$BUILD/i686-elf/newlib/targ-include" \
    -I"$NLSRC/libc/include" \
    -c "$NLSRC/libc/stdio64/stdio64.c" -o "$BUILD/stdio64.o"
"$TOOLS/i686-elf-ar" rcs "$PREFIX/i686-elf/lib/libc.a" "$BUILD/stdio64.o"

echo "newlib ${NEWLIB_VERSION} installed to $PREFIX"
