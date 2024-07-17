//! The goal of this mod is to ensure the launcher shell function
//! is available for fish i.e. the `br` shell function can
//! be used to launch broot (and thus make it possible to execute
//! some commands, like `cd`, from the starting shell.
//!
//!
//! In a correct installation, we have:
//! - a function declaration script in ~/.local/share/broot/launcher/fish/br.fish
//! - a link to that script in ~/.config/fish/functions/br.fish
//! (exact paths depend on XDG variables)
//!
//! fish stores functions in FISH_CONFIG_DIR/functions (for example,
//! ~/.config/fish/functions) and lazily loads (or reloads) them as
//! needed.

use {
    super::ShellInstall,
    crate::{conf, errors::*},
    directories::BaseDirs,
    directories::ProjectDirs,
    std::path::PathBuf,
};

const NAME: &str = "fish";
const SCRIPT_FILENAME: &str = "br.fish";

const FISH_FUNC: &str = r#"
# This script was automatically generated by the broot program
# More information can be found in https://github.com/Canop/broot
# This function starts broot and executes the command
# it produces, if any.
# It's needed because some shell commands, like `cd`,
# have no useful effect if executed in a subshell.
function br --wraps=broot
    set -l cmd_file (mktemp)
    if broot --outcmd $cmd_file $argv
        read --local --null cmd < $cmd_file
        rm -f $cmd_file
        eval $cmd
    else
        set -l code $status
        rm -f $cmd_file
        return $code
    end
end
"#;

pub fn get_script() -> &'static str {
    FISH_FUNC
}

/// return the root of fish's config
fn get_fish_dir() -> PathBuf {
    if let Some(base_dirs) = BaseDirs::new() {
        let fish_dir = base_dirs.home_dir().join(".config/fish");
        if fish_dir.exists() {
            return fish_dir;
        }
    }
    ProjectDirs::from("fish", "fish", "fish") // hem...
        .expect("Unable to find configuration directories")
        .config_dir()
        .to_path_buf()
}

/// return the fish functions directory
fn get_fish_functions_dir() -> PathBuf {
    get_fish_dir().join("functions")
}

/// return the path to the link to the function script
///
/// At version 0.10.4 we change the location of the script:
/// It was previously with the link, but it's now in
/// ~/.config/fish/functions/br.fish
fn get_link_path() -> PathBuf {
    get_fish_functions_dir().join("br.fish")
}

/// return the path to the script containing the function.
///
/// At version 0.10.4 we change the location of the script:
/// It was previously with the link, but it's now in
/// ~/.local/share/broot/launcher/fish/br.fish
fn get_script_path() -> PathBuf {
    conf::app_dirs()
        .data_dir()
        .join("launcher")
        .join(NAME)
        .join(SCRIPT_FILENAME)
}

/// check for fish shell
///
/// As fish isn't frequently used, we first check that it seems
/// to be installed. If not, we just do nothing.
pub fn install(si: &mut ShellInstall) -> Result<(), ShellInstallError> {
    let fish_dir = get_fish_dir();
    if !fish_dir.exists() {
        debug!("no fish config directory. Assuming fish isn't used.");
        return Ok(());
    }
    info!("fish seems to be installed");
    let script_path = get_script_path();
    si.write_script(&script_path, FISH_FUNC)?;
    let link_path = get_link_path();
    // creating the link may create the fish/conf.d directory
    si.create_link(&link_path, &script_path)?;
    si.done = true;
    Ok(())
}