build-install:
	rm -f lpc55-*.pkg.tar.*
	makepkg -f
	yes | sudo pacman -U lpc55-*.pkg.tar.*

clean:
	rm -rf lpc55* pkg src
