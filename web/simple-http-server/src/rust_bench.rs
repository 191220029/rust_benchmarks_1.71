#[cfg(test)]
mod rust_bench {
    use crate::middlewares::{AuthChecker, CompressionHandler, RequestLogger};
    use crate::util::{enable_string, now_string};
    use crate::MainHandler;
    use crate::{build_spec, Printer};
    use clap::crate_version;
    use iron::{Chain, Iron};
    use iron_cors::CorsMiddleware;
    use std::env;
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, TcpStream};
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;
    use termcolor::{Color, ColorSpec};

    #[test]
    fn performance_test() {
        let server_handle = thread::spawn(|| {
            start_default_http_server();
        });

        thread::sleep(Duration::from_millis(200));

        let request_handle = thread::spawn(move || {
            vec![
                "/",
                "/.ci",
                "/.cargo",
                "/.gitignore",
                "/Cargo.lock",
                "/Cargo.toml",
                "/LICENSE",
                "/Makefile",
                "/perf-config.json",
                "/README.md",
                "/rust-toolchain",
                "/screenshot.png",
                "/src",
                "/test",
            ]
            .repeat(400)
            .iter()
            .for_each(|header| {
                send_request("0.0.0.0:8000", header).unwrap();
            })
        });

        let upload_handle = thread::spawn(move || {
            vec![
                ".gitignore",
                "Cargo.lock",
                "Cargo.toml",
                "perf-config.json",
                "README.md",
                "screenshot.png",
            ]
            .repeat(400)
            .iter()
            .for_each(|f| {
                upload_file("0.0.0.0:8000", f, ("/test/".to_string() + f).as_str()).unwrap();
            })
        });

        request_handle.join().unwrap();
        upload_handle.join().unwrap();
        drop(server_handle);
    }

    fn start_default_http_server() {
        let matches = clap::App::new("Simple HTTP(s) Server")
        .setting(clap::AppSettings::ColoredHelp)
        .version(crate_version!())
        .arg(clap::Arg::with_name("root")
             .index(1)
             .validator(|s| {
                 match fs::metadata(s) {
                     Ok(metadata) => {
                         if metadata.is_dir() { Ok(()) } else {
                             Err("Not directory".to_owned())
                         }
                     },
                     Err(e) => Err(e.to_string())
                 }
             })
             .help("Root directory"))
        .arg(clap::Arg::with_name("index")
             .short("i")
             .long("index")
             .help("Enable automatic render index page [index.html, index.htm]"))
        .arg(clap::Arg::with_name("upload")
             .short("u")
             .long("upload")
             .help("Enable upload files (multiple select)"))
        .arg(clap::Arg::with_name("redirect").long("redirect")
             .takes_value(true)
             .validator(|url_string| iron::Url::parse(url_string.as_str()).map(|_| ()))
             .help("takes a URL to redirect to using HTTP 301 Moved Permanently"))
        .arg(clap::Arg::with_name("nosort")
             .long("nosort")
             .help("Disable directory entries sort (by: name, modified, size)"))
        .arg(clap::Arg::with_name("nocache")
             .long("nocache")
             .help("Disable http cache"))
        .arg(clap::Arg::with_name("norange")
             .long("norange")
             .help("Disable header::Range support (partial request)"))
        .arg(clap::Arg::with_name("cert")
             .long("cert")
             .takes_value(true)
             .validator(|s| {
                 match fs::metadata(s) {
                     Ok(metadata) => {
                         if metadata.is_file() { Ok(()) } else {
                             Err("Not a regular file".to_owned())
                         }
                     },
                     Err(e) => Err(e.to_string())
                 }
             })
             .help("TLS/SSL certificate (pkcs#12 format)"))
        .arg(clap::Arg::with_name("cors")
             .long("cors")
             .help("Enable CORS via the \"Access-Control-Allow-Origin\" header"))
        .arg(clap::Arg::with_name("certpass").
             long("certpass")
             .takes_value(true)
             .help("TLS/SSL certificate password"))
        .arg(clap::Arg::with_name("upload_size_limit")
             .short("l")
             .long("upload-size-limit")
             .takes_value(true)
             .default_value("8000000")
             .value_name("NUM")
             .validator(|s| {
                 match s.parse::<u64>() {
                     Ok(_) => Ok(()),
                     Err(e) => Err(e.to_string())
                 }})
             .help("Upload file size limit [bytes]"))
        .arg(clap::Arg::with_name("ip")
             .long("ip")
             .takes_value(true)
             .default_value("0.0.0.0")
             .validator(|s| {
                 match IpAddr::from_str(&s) {
                     Ok(_) => Ok(()),
                     Err(e) => Err(e.to_string())
                 }
             })
             .help("IP address to bind"))
        .arg(clap::Arg::with_name("port")
             .short("p")
             .long("port")
             .takes_value(true)
             .default_value("8000")
             .validator(|s| {
                 match s.parse::<u16>() {
                     Ok(_) => Ok(()),
                     Err(e) => Err(e.to_string())
                 }
             })
             .help("Port number"))
        .arg(clap::Arg::with_name("auth")
             .short("a")
             .long("auth")
             .takes_value(true)
             .validator(|s| {
                 let parts = s.splitn(2, ':').collect::<Vec<&str>>();
                 if parts.len() < 2 || parts.len() >= 2 && parts[1].is_empty() {
                     Err("no password found".to_owned())
                 } else if parts[0].is_empty() {
                     Err("no username found".to_owned())
                 } else {
                     Ok(())
                 }
             })
             .help("HTTP Basic Auth (username:password)"))
        .arg(clap::Arg::with_name("compress")
             .short("c")
             .long("compress")
             .multiple(true)
             .value_delimiter(",")
             .takes_value(true)
             .help("Enable file compression: gzip/deflate\n    Example: -c=js,d.ts\n    Note: disabled on partial request!"))
        .arg(clap::Arg::with_name("threads")
             .short("t")
             .long("threads")
             .takes_value(true)
             .default_value("3")
             .validator(|s| {
                 match s.parse::<u8>() {
                     Ok(v) => {
                         if v > 0 { Ok(()) } else {
                             Err("Not positive number".to_owned())
                         }
                     }
                     Err(e) => Err(e.to_string())
                 }
             })
             .help("How many worker threads"))
        .arg(clap::Arg::with_name("try-file-404")
             .long("try-file")
             .visible_alias("try-file-404")
             .takes_value(true)
             .value_name("PATH")
             .validator(|s| {
                 match fs::metadata(s) {
                     Ok(metadata) => {
                         if metadata.is_file() { Ok(()) } else {
                             Err("Not a file".to_owned())
                         }
                     },
                     Err(e) => Err(e.to_string())
                 }
             })
             .help("serve this file (server root relative) in place of missing files (useful for single page apps)"))
        .arg(clap::Arg::with_name("silent")
             .long("silent")
             .short("s")
             .takes_value(false)
             .help("Disable all outputs"))
        .get_matches();

        let root = matches
            .value_of("root")
            .map(|s| PathBuf::from(s).canonicalize().unwrap())
            .unwrap_or_else(|| env::current_dir().unwrap());
        let index = matches.is_present("index");
        let upload = true;
        let redirect_to = matches
            .value_of("redirect")
            .map(iron::Url::parse)
            .map(Result::unwrap);
        let sort = !matches.is_present("nosort");
        let cache = !matches.is_present("nocache");
        let range = !matches.is_present("norange");
        let cert = matches.value_of("cert");
        let certpass = matches.value_of("certpass");
        let cors = matches.is_present("cors");
        let ip = matches.value_of("ip").unwrap();
        let port = matches.value_of("port").unwrap().parse::<u16>().unwrap();
        let upload_size_limit = matches
            .value_of("upload_size_limit")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let auth = matches.value_of("auth");
        let compress = matches.values_of_lossy("compress");
        let threads = matches.value_of("threads").unwrap().parse::<u8>().unwrap();
        let try_file_404 = matches.value_of("try-file-404");

        let printer = Printer::new();
        let color_blue = Some(build_spec(Some(Color::Blue), false));
        let color_red = Some(build_spec(Some(Color::Red), false));
        let addr = format!("{}:{}", ip, port);
        let compression_exts = compress
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|s| format!("*.{}", s))
            .collect::<Vec<String>>();
        let compression_string = if compression_exts.is_empty() {
            "disabled".to_owned()
        } else {
            format!("{:?}", compression_exts)
        };
        let silent = matches.is_present("silent");

        if !silent {
            printer
            .println_out(
                r#"     Index: {}, Upload: {}, Cache: {}, Cors: {}, Range: {}, Sort: {}, Threads: {}
          Auth: {}, Compression: {}
         https: {}, Cert: {}, Cert-Password: {}
          Root: {},
    TryFile404: {}
       Address: {}
    ======== [{}] ========"#,
                &vec![
                    enable_string(index),
                    enable_string(upload),
                    enable_string(cache),
                    enable_string(cors),
                    enable_string(range),
                    enable_string(sort),
                    threads.to_string(),
                    auth.unwrap_or("disabled").to_string(),
                    compression_string,
                    (if cert.is_some() {
                        "enabled"
                    } else {
                        "disabled"
                    })
                    .to_string(),
                    cert.unwrap_or("").to_owned(),
                    certpass.unwrap_or("").to_owned(),
                    root.to_str().unwrap().to_owned(),
                    try_file_404.unwrap_or("").to_owned(),
                    format!(
                        "{}://{}",
                        if cert.is_some() { "https" } else { "http" },
                        addr
                    ),
                    now_string(),
                ]
                .iter()
                .map(|s| (s.as_str(), &color_blue))
                .collect::<Vec<(&str, &Option<ColorSpec>)>>(),
            )
            .unwrap();
        }

        let mut chain = Chain::new(MainHandler {
            root,
            index,
            upload: Some(crate::Upload {
                csrf_token: String::from("."),
            }),
            cache,
            range,
            redirect_to,
            sort,
            compress: compress
                .clone()
                .map(|exts| exts.iter().map(|s| format!(".{}", s)).collect()),
            try_file_404: try_file_404.map(PathBuf::from),
            upload_size_limit,
            coop: false,
            coep: false,
            base_url: String::from("127.0.0.1/fxl/rustbench/simple-http-server"),
        });
        if cors {
            chain.link_around(CorsMiddleware::with_allow_any());
        }
        if let Some(auth) = auth {
            match AuthChecker::new(auth) {
                Ok(auth_checker) => {
                    chain.link_before(auth_checker);
                }
                Err(e) => {
                    printer.print_err("{}", &[(&*e, &color_red)]).unwrap();
                    panic!();
                }
            }
        }
        if let Some(ref exts) = compress {
            if !exts.is_empty() {
                chain.link_after(CompressionHandler);
            }
        }
        if !silent {
            chain.link_after(RequestLogger {
                printer: Printer::new(),
                base_url: String::from("127.0.0.1/fxl/rustbench/simple-http-server"),
            });
        }

        let mut server = Iron::new(chain);
        server.threads = threads as usize;
        let rv = if let Some(cert) = cert {
            use hyper_native_tls::NativeTlsServer;
            let ssl = NativeTlsServer::new(cert, certpass.unwrap_or("")).unwrap();
            server.https(&addr, ssl)
        } else {
            server.http(&addr)
        };
        if let Err(e) = rv {
            printer
                .println_err(
                    "{}: Can not bind on {}, {}",
                    &[
                        ("ERROR", &Some(build_spec(Some(Color::Red), true))),
                        (addr.as_str(), &None),
                        (e.to_string().as_str(), &None),
                    ],
                )
                .unwrap();
            std::process::exit(1);
        };
    }

    fn send_request(addr: &str, header: &str) -> std::io::Result<()> {
        let mut stream = TcpStream::connect(addr)?;

        // 构造 HTTP 请求
        let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", header, addr);

        // 发送请求
        stream.write(request.as_bytes())?;

        // 读取响应
        let mut buffer = [0; 1024];
        stream.read(&mut buffer)?;

        // 输出响应
        println!("Response: {:?}", String::from_utf8_lossy(&buffer));

        Ok(())
    }

    fn upload_file(addr: &str, file_path: &str, server_path: &str) -> io::Result<()> {
        // 读取要上传的文件内容
        let mut file_content = Vec::new();
        let mut file = File::open(file_path)?;
        file.read_to_end(&mut file_content)?;

        // 构造 HTTP 请求
        let request = format!(
            "POST {} HTTP/1.1\r\n\
            Host: {}\r\n\
            Content-Length: {}\r\n\
            Content-Type: application/octet-stream\r\n\
            \r\n",
            server_path,
            addr,
            fs::metadata(PathBuf::from(file_path)).unwrap().len(),
        );

        // 连接服务器
        let mut stream = TcpStream::connect(addr)?;

        // 发送 HTTP 请求头部
        stream.write(request.as_bytes())?;

        // 发送文件内容
        stream.write(&file_content)?;

        Ok(())
    }
}
