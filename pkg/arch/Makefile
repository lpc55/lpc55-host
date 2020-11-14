# Note: do not mix aurutils and "external" package methods.
# - aurutils uses a local repository, so you can `pacman -S lpc55`
# - makepkg/devootls output an "external" package, that you can
#   `pacman -U lpc55-<pkgve>-<pkgrel>-x86_64.pkg.tar.zst`
# Mixing these confuses pacman :)

build-install-aurutils-chroot:
	# uses `aurutils` package by AladW from AUR
	# this builds in a chroot, ensuring all dependencies are properly listed!
	aur build -cfN
	sudo pacman -Syu
	sudo pacman -S lpc55

build-install-makepkg:
	makepkg -f

build-makepkg:
	makepkg -fi

build-devtools-chroot:
	extra-x86_64-build

clean:
	rm -rf lpc55* pkg src *.log
