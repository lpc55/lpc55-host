use std::env;
use std::fs;
use std::path;
use std::process;

#[cfg(feature = "cli")]
#[allow(dead_code)]
#[path = "src/cli/app.rs"]
mod app;

fn main() {
    // OUT_DIR is set by Cargo and it's where any additional build artifacts
    // are written.
    let env_outdir = match env::var_os("OUT_DIR") {
        Some(outdir) => outdir,
        None => {
            eprintln!(
                "OUT_DIR environment variable not defined. \
                 Please file a bug: \
                 https://github.com/BurntSushi/ripgrep/issues/new"
            );
            process::exit(1);
        }
    };
    // place side by side with binaries
    let outdir = path::PathBuf::from(path::PathBuf::from(env_outdir).ancestors().skip(3).next().unwrap());
    fs::create_dir_all(&outdir).unwrap();
    println!("{:?}", &outdir);

    #[cfg(feature = "cli")] {
        use clap::Shell;

        // Use clap to build completion files.
        // Pro-tip: use `fd -HIe bash` to get OUT_DIR
        let mut app = app::app();
        app.gen_completions("lpc55", Shell::Bash, &outdir);
        app.gen_completions("lpc55", Shell::Fish, &outdir);
        app.gen_completions("lpc55", Shell::PowerShell, &outdir);
        // // Note that we do not use clap's support for zsh. Instead, zsh completions
        // // are manually maintained in `complete/_rg`.
        app.gen_completions("lpc55", Shell::Zsh, &outdir);
    }

    // Make the current git hash available to the build.
    if let Some(rev) = git_revision_hash() {
        println!("cargo:rustc-env=LPC55_BUILD_GIT_HASH={}", rev);
    }
}

fn git_revision_hash() -> Option<String> {
    let result = process::Command::new("git")
        .args(&["rev-parse", "--short=10", "HEAD"])
        .output();
    result.ok().and_then(|output| {
        let v = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    })
}
