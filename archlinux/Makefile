build-install-chroot:
	# uses `aurutils` package by AladW from AUR
	# this builds in a chroot, ensuring all dependencies are properly listed!
	aur build -cfN
	sudo pacman -S lpc55

build-install:
	# rm -f lpc55-*.pkg.tar.*
	makepkg -fi
	# yes | sudo pacman -U lpc55-*.pkg.tar.*

clean:
	rm -rf lpc55* pkg src
