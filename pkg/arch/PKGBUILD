# Maintainer: Nicolas Stalder <n+archlinux@stalder.io>
pkgname=lpc55
pkgver=0.1.0pre
pkgrel=2
pkgdesc='lpc55 host-side utilities'
arch=('x86_64')
url="https://github.com/lpc55/lpc55-host"
license=(Apache)
# we only need `libudev.so`, during build we also need `pkgconfig/udev/.pc`
depends=(systemd-libs)
# note we do not need Arch `hidapi` package here, it's a git submodule of Rust hidapi
makedepends=(cargo git systemd)
source=("$pkgname-$pkgver.tar.gz::https://github.com/chmln/sd/archive/v${pkgver}.tar.gz")
source=("git+file:///home/nicolas/projects/lpc55")
sha256sums=('SKIP')

build() {
  cd "$pkgname"
  cargo build --release
}

check() {
  cd "$pkgname"
  # make sure shared libs work
  target/release/lpc55 --version
  # Currently, tests assume a device is accessible
  # cargo test --release
}

package() {
  install -Dm755 "$pkgname/target/release/$pkgname" "$pkgdir/usr/bin/$pkgname"
  # install -Dm644 "$pkgname-$pkgver/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"

  # completions
  install -Dm644 $pkgname/target/release/_lpc55 -t $pkgdir/usr/share/zsh/site-functions
  install -Dm644 $pkgname/target/release/lpc55.bash $pkgdir/usr/share/bash-completion/completions/lpc55

  # udev rule
  install -Dm644 $pkgname/70-raw-lpc55-mcuboot.rules -t $pkgdir/usr/lib/udev/rules.d
}
