# WIP...

class Lpc55Bin < Formula
    version '0.1.0-pre'
  desc "lpc55 host-side utilities"
  homepage "https://github.com/nickray/lpc55"

  if OS.mac?
      url "https://github.com/BurntSushi/ripgrep/releases/download/#{version}/ripgrep-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "7ff2fd5dd3a438d62fae5866ddae78cf542b733116f58cf21ab691a58c385703"
  elsif OS.linux?
      url "https://github.com/BurntSushi/ripgrep/releases/download/#{version}/ripgrep-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "88d3b735e43f6f16a0181a8fec48847693fae80168d5f889fdbdeb962f1fc804"
  end

  conflicts_with "lpc55"

  def install
    bin.install "lpc55"
    man1.install "doc/lpc55.1"

    bash_completion.install "complete/lpc55.bash"
    zsh_completion.install "complete/_lpc55"
  end
end
