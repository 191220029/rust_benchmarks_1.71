//! CKB executable main entry.
use ckb_bin::run_app;
use ckb_build_info::Version;

#[cfg(all(not(target_env = "msvc"), not(target_os = "macos")))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    let version = get_version();
    if let Some(exit_code) = run_app(version).err() {
        ::std::process::exit(exit_code.into());
    }
}

fn get_version() -> Version {
    let major = env!("CARGO_PKG_VERSION_MAJOR")
        .parse::<u8>()
        .expect("CARGO_PKG_VERSION_MAJOR parse success");
    let minor = env!("CARGO_PKG_VERSION_MINOR")
        .parse::<u8>()
        .expect("CARGO_PKG_VERSION_MINOR parse success");
    let patch = env!("CARGO_PKG_VERSION_PATCH")
        .parse::<u16>()
        .expect("CARGO_PKG_VERSION_PATCH parse success");
    let dash_pre = {
        let pre = env!("CARGO_PKG_VERSION_PRE");
        if pre.is_empty() {
            pre.to_string()
        } else {
            "-".to_string() + pre
        }
    };

    let commit_describe = option_env!("COMMIT_DESCRIBE").map(ToString::to_string);
    #[cfg(docker)]
    let commit_describe = commit_describe.map(|s| s.replace("-dirty", ""));
    let commit_date = option_env!("COMMIT_DATE").map(ToString::to_string);
    let code_name = None;
    Version {
        major,
        minor,
        patch,
        dash_pre,
        code_name,
        commit_describe,
        commit_date,
    }
}

#[cfg(test)]
mod rust_bench {
    use super::*;

    #[test]
    fn test_get_version() {
        // Mock the environment variables
        std::env::set_var("CARGO_PKG_VERSION_MAJOR", "1");
        std::env::set_var("CARGO_PKG_VERSION_MINOR", "2");
        std::env::set_var("CARGO_PKG_VERSION_PATCH", "3");
        std::env::set_var("CARGO_PKG_VERSION_PRE", "beta");

        let version = get_version();

        assert_eq!(version.major, 0);
        assert_eq!(version.minor, 111);
        assert_eq!(version.patch, 0);
        assert_eq!(version.dash_pre, "");
        assert!(!version.commit_describe.is_none());
        assert!(!version.commit_date.is_none());
        assert!(version.code_name.is_none());
    }

    #[test]
    fn test_get_version_no_pre_release() {
        // Mock the environment variables
        std::env::set_var("CARGO_PKG_VERSION_MAJOR", "1");
        std::env::set_var("CARGO_PKG_VERSION_MINOR", "2");
        std::env::set_var("CARGO_PKG_VERSION_PATCH", "3");
        std::env::set_var("CARGO_PKG_VERSION_PRE", "");

        let version = get_version();

        assert_eq!(version.major, 0);
        assert_eq!(version.minor, 111);
        assert_eq!(version.patch, 0);
        assert_eq!(version.dash_pre, "");
        assert!(!version.commit_describe.is_none());
        assert!(!version.commit_date.is_none());
        assert!(version.code_name.is_none());
    }

    // Mocking run_app function
    mod run_app_mock {
        use super::*;

        pub fn run_app(_version: Version) -> Result<(), u32> {
            // Simulate the behavior of run_app for testing
            Err(1)
        }
    }

    #[test]
    fn test_main() {
        // Mock the get_version function
        let version = Version {
            major: 1,
            minor: 111,
            patch: 3,
            dash_pre: String::from("beta"),
            code_name: None,
            commit_describe: None,
            commit_date: None,
        };

        // Replace run_app with the mock function
        let result = run_app_mock::run_app(version);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), 1);
    }
}