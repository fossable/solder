# solder

> Don't rebuild it, `solder` it!
>
> Actually, you should probably try rebuilding it first, but if that doesn't
> work out, then you can `solder` it.

**solder** is a post-link static merger for ELF executables. It extracts symbols
from shared libraries and fuses them directly into executables, removing runtime
dependencies altogether.

## Partial static linking

When you need a partially static binary, not all build tools make this easy. If
you find yourself hacking `configure` scripts or generated Makefiles to
accomplish this, consider post-processing your binary with `solder` instead.

You don't have to recompile anything. Just give it your executable and the
shared objects you want statically linked.

### Excluded libraries

The following libraries are excluded because static linking them can cause
unpleasant problems (even when you initially static link them at build time).

- ld-linux
- ld-musl
- linux-vdso
- linux-gate
- libc
- libm
- librt
- libpthread
- libdl
- libresolv
- libnss\_
- libgcc_s

## Usage

```sh
# Merge all possible libraries into the executable (in-place)
solder ./myapp

# Merge only specific libraries
solder ./myapp -m libfoo.so.1 -m libbar.so.2

# Add additional library search paths
solder ./myapp -L /opt/mylibs -L ./libs

# Preview what would happen without writing output
solder ./myapp --dry-run
```

## How It Works

- Parses the executable's dynamic section to identify imported symbols
- Resolves which shared libraries provide those symbols (using regular library
  search paths)
- Extracts the minimal set of code/data needed
  - Uses symbolic execution to identify jump tables in .rodata
- Applies relocations and creates trampolines for any remaining external calls
- Appends a new `PT_LOAD` segment containing the merged code
- Patches GOT entries to point directly to the merged symbols
- Removes the merged libraries from `DT_NEEDED`

## Limitations

- x86_64 only
- We can't merge `dlopen` libraries
