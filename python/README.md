# pylpc55

Very much WIP.

To use this, install `maturin` (e.g. `pacman -S maturin` on Arch Linux).

Then, `maturin build --manylinux off` builds wheels (libudev is "forbidden" for manylinux),
and `maturin develop` installs into an existing environment.

The naming is done such that the following kind of snippet works:
```python
import lpc55
bl = lpc55.Bootloader(vid=0x1209, pid=0xbeee)
uuid = bl.uuid
```

The PyPI package is `pylpc55` and just a namesquat currently.
