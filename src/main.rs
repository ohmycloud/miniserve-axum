use anyhow::Result;
use axum::routing::{get};
use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::extract::{Query, State};
use axum::http::{StatusCode, Uri, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::body::Body;
use clap::{CommandFactory, Parser, crate_version};
use colored::*;
use fast_qr::QRBuilder;
use log::{error, warn};
use miniserve_axum::{
    CliArgs, MiniserveConfig, QR_EC_LEVEL, StartupError, configure_header, css, favicon,
    healthcheck, log_error_chain, Entry, EntryType, Breadcrumb, page, ListingQueryParameters,
    ArchiveMethod, Pipe,
};
use std::thread;
use std::time::Duration;
use std::{
    io::{self, IsTerminal, Write},
    net::{IpAddr, SocketAddr},
};
use tokio::net::TcpListener;
use tower_http::{compression::CompressionLayer, trace::TraceLayer};

use futures::channel::mpsc;
use std::path::Path;
use tokio::fs;
use bytesize::ByteSize;

#[derive(serde::Deserialize)]
struct DownloadQuery {
    download: Option<ArchiveMethod>,
}

async fn file_and_directory_handler(
    uri: Uri,
    Query(download_query): Query<DownloadQuery>,
    State(config): State<MiniserveConfig>,
) -> impl IntoResponse {
    let path_str = uri.path();
    let decoded_path = percent_encoding::percent_decode_str(path_str)
        .decode_utf8()
        .unwrap_or_default();
    
    // Remove leading slash and join with served directory
    let relative_path = decoded_path.strip_prefix('/').unwrap_or(&decoded_path);
    let full_path = config.path.join(relative_path);
    
    if !full_path.exists() {
        return (StatusCode::NOT_FOUND, "File not found").into_response();
    }
    
    if full_path.is_file() {
        // Serve file
        match fs::read(&full_path).await {
            Ok(contents) => {
                // Simple content type detection
                let content_type = if path_str.ends_with(".html") {
                    "text/html"
                } else if path_str.ends_with(".css") {
                    "text/css"
                } else if path_str.ends_with(".js") {
                    "application/javascript"
                } else if path_str.ends_with(".png") {
                    "image/png"
                } else if path_str.ends_with(".jpg") || path_str.ends_with(".jpeg") {
                    "image/jpeg"
                } else {
                    "application/octet-stream"
                };
                
                let headers = [(axum::http::header::CONTENT_TYPE, content_type)];
                (headers, contents).into_response()
            }
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Could not read file").into_response(),
        }
    } else if full_path.is_dir() {
        // Check if this is a download request
        if let Some(archive_method) = download_query.download {
            // Handle archive download
            if !archive_method.is_enabled(
                config.tar_enabled,
                config.tar_gz_enabled,
                config.zip_enabled,
            ) {
                return (StatusCode::FORBIDDEN, "Archive creation is disabled.").into_response();
            }

            let file_name = format!(
                "{}.{}",
                full_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("archive"),
                archive_method.extension()
            );

            // Create streaming response
            let (tx, rx) = mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(10);
            let pipe = Pipe::new(tx);

            // Create archive in background thread
            let dir_path = full_path.clone();
            let skip_symlinks = config.no_symlinks;
            tokio::spawn(async move {
                if let Err(err) = archive_method.create_archive(dir_path, skip_symlinks, pipe) {
                    log::error!("Error during archive creation: {:?}", err);
                }
            });

            let body = Body::from_stream(rx);

            let mut response = Response::new(body);
            response.headers_mut().insert(
                "content-type",
                HeaderValue::from_str(&archive_method.content_type())
                    .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
            );
            response.headers_mut().insert(
                "content-transfer-encoding",
                HeaderValue::from_static("binary"),
            );
            response.headers_mut().insert(
                "content-disposition",
                HeaderValue::from_str(&format!("attachment; filename={:?}", file_name)).unwrap(),
            );

            return response;
        } else {
            // Generate directory listing
            match generate_directory_listing(&full_path, &uri, &config).await {
                Ok(html) => Html(html.into_string()).into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Could not read directory").into_response(),
            }
        }
    } else {
        (StatusCode::NOT_FOUND, "Not found").into_response()
    }
}

async fn generate_directory_listing(
    dir_path: &Path,
    uri: &Uri,
    config: &MiniserveConfig,
) -> Result<maud::Markup, std::io::Error> {
    let mut entries = Vec::new();
    let mut dir_entries = fs::read_dir(dir_path).await?;
    
    while let Some(entry) = dir_entries.next_entry().await? {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let metadata = entry.metadata().await.ok();
        
        let entry_type = if entry.file_type().await.map(|ft| ft.is_dir()).unwrap_or(false) {
            EntryType::Directory
        } else {
            EntryType::File
        };
        
        let size = metadata
            .as_ref()
            .filter(|m| m.is_file())
            .map(|m| ByteSize::b(m.len()));
        
        let last_modification_date = metadata
            .as_ref()
            .and_then(|m| m.modified().ok());
        
        let link = if uri.path().ends_with('/') {
            format!("{}{}", uri.path(), file_name)
        } else {
            format!("{}/{}", uri.path(), file_name)
        };
        
        entries.push(Entry {
            name: file_name,
            entry_type,
            link,
            size,
            last_modification_date,
            symlink_info: None,
        });
    }
    
    // Create breadcrumbs
    let path_components: Vec<&str> = uri.path().trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    let mut breadcrumbs = vec![Breadcrumb {
        name: "Home".to_string(),
        link: "/".to_string(),
    }];
    
    let mut current_path = String::new();
    for component in path_components {
        current_path.push('/');
        current_path.push_str(component);
        breadcrumbs.push(Breadcrumb {
            name: component.to_string(),
            link: current_path.clone(),
        });
    }
    
    // Mark the last breadcrumb as current (don't make it a link)
    if let Some(last) = breadcrumbs.last_mut() {
        last.link = ".".to_string();
    }
    
    let is_root = uri.path() == "/" || uri.path().is_empty();
    let encoded_dir = uri.path().to_string();
    let query_params = ListingQueryParameters::default();
    
    // Use the proper miniserve page render function
    Ok(page(
        entries,
        None, // readme
        uri,
        is_root,
        query_params,
        &breadcrumbs,
        &encoded_dir,
        config,
        None, // current_user
    ))
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    if let Some(shell) = args.print_completions {
        let mut clap_app = CliArgs::command();
        let app_name = clap_app.get_name().to_string();
        clap_complete::generate(shell, &mut clap_app, app_name, &mut io::stdout());
        return Ok(());
    }

    if args.print_manpage {
        let clap_app = CliArgs::command();
        let man = clap_mangen::Man::new(clap_app);
        man.render(&mut io::stdout())?;
        return Ok(());
    }

    let miniserve_config = MiniserveConfig::try_from_args(args)?;

    run(miniserve_config).inspect_err(|e| {
        log_error_chain(e.to_string());
    })?;

    Ok(())
}

#[tokio::main]
async fn run(miniserve_config: MiniserveConfig) -> Result<(), StartupError> {
    let log_level = if miniserve_config.verbose {
        simplelog::LevelFilter::Info
    } else {
        simplelog::LevelFilter::Warn
    };

    simplelog::TermLogger::init(
        log_level,
        simplelog::ConfigBuilder::new()
            .set_time_format_rfc2822()
            .build(),
        simplelog::TerminalMode::Mixed,
        if io::stdout().is_terminal() {
            simplelog::ColorChoice::Auto
        } else {
            simplelog::ColorChoice::Never
        },
    )
    .or_else(|_| simplelog::SimpleLogger::init(log_level, simplelog::Config::default()))
    .expect("Couldn't initialize logger");

    if miniserve_config.no_symlinks && miniserve_config.path.is_symlink() {
        return Err(StartupError::NoSymlinksOptionWithSymlinkServePath(
            miniserve_config.path.to_string_lossy().to_string(),
        ));
    }

    if miniserve_config.webdav_enabled && miniserve_config.path.is_file() {
        return Err(StartupError::WebdavWithFileServePath(
            miniserve_config.path.to_string_lossy().to_string(),
        ));
    }

    let inside_config = miniserve_config.clone();

    let canon_path = miniserve_config
        .path
        .canonicalize()
        .map_err(|e| StartupError::IoError("Failed to resolve path to be served".to_string(), e))?;

    // warn if --index is specified but not found
    if let Some(ref index) = miniserve_config.index {
        if !canon_path.join(index).exists() {
            warn!(
                "The file '{}' provided for option --index could not be found.",
                index.to_string_lossy(),
            );
        }
    }

    let path_string = canon_path.to_string_lossy();

    println!(
        "{name} v{version}",
        name = "miniserve".bold(),
        version = crate_version!()
    );
    if !miniserve_config.path_explicitly_chosen {
        // If the path to serve has NOT been explicitly chosen and if this is NOT an interactive
        // terminal, we should refuse to start for security reasons. This would be the case when
        // running miniserve as a service but forgetting to set the path. This could be pretty
        // dangerous if given with an undesired context path (for instance /root or /).
        if !io::stdout().is_terminal() {
            return Err(StartupError::NoExplicitPathAndNoTerminal);
        }

        warn!(
            "miniserve has been invoked without an explicit path so it will serve the current directory after a short delay."
        );
        warn!(
            "Invoke with -h|--help to see options or invoke as `miniserve .` to hide this advice."
        );
        print!("Starting server in ");
        io::stdout()
            .flush()
            .map_err(|e| StartupError::IoError("Failed to write data".to_string(), e))?;
        for c in "3… 2… 1… \n".chars() {
            print!("{c}");
            io::stdout()
                .flush()
                .map_err(|e| StartupError::IoError("Failed to write data".to_string(), e))?;
            thread::sleep(Duration::from_millis(500));
        }
    }

    let display_urls = {
        let (mut ifaces, wildcard): (Vec<_>, Vec<_>) = miniserve_config
            .interfaces
            .clone()
            .into_iter()
            .partition(|addr| !addr.is_unspecified());

        // Replace wildcard addresses with local interface addresses
        if !wildcard.is_empty() {
            let all_ipv4 = wildcard.iter().any(|addr| addr.is_ipv4());
            let all_ipv6 = wildcard.iter().any(|addr| addr.is_ipv6());
            ifaces = if_addrs::get_if_addrs()
                .unwrap_or_else(|e| {
                    error!("Failed to get local interface addresses: {}", e);
                    Default::default()
                })
                .into_iter()
                .map(|iface| iface.ip())
                .filter(|ip| (all_ipv4 && ip.is_ipv4()) || (all_ipv6 && ip.is_ipv6()))
                .collect();
            ifaces.sort();
        }

        ifaces
            .into_iter()
            .map(|addr| match addr {
                IpAddr::V4(_) => format!("{}:{}", addr, miniserve_config.port),
                IpAddr::V6(_) => format!("[{}]:{}", addr, miniserve_config.port),
            })
            .map(|addr| match miniserve_config.tls_rustls_config {
                Some(_) => format!("https://{addr}"),
                None => format!("http://{addr}"),
            })
            .map(|url| format!("{}{}", url, miniserve_config.route_prefix))
            .collect::<Vec<_>>()
    };

    let socket_addresses = miniserve_config
        .interfaces
        .iter()
        .map(|&interface| SocketAddr::new(interface, miniserve_config.port))
        .collect::<Vec<_>>();

    let display_sockets = socket_addresses
        .iter()
        .map(|sock| sock.to_string().green().bold().to_string())
        .collect::<Vec<_>>();

    let app = Router::new()
        .layer(TraceLayer::new_for_http())
        .layer(tower::ServiceBuilder::new().layer(CompressionLayer::new()))
        .layer(from_fn_with_state(inside_config.clone(), configure_header))
        .route(&inside_config.healthcheck_route, get(healthcheck))
        .route(&inside_config.favicon_route, get(favicon))
        .route(&inside_config.css_route, get(css))
        .fallback(file_and_directory_handler)
        .with_state(inside_config);

    println!("Bound to {}", display_sockets.join(", "));

    println!("Serving path {}", path_string.yellow().bold());

    println!(
        "Available at (non-exhaustive list):\n    {}\n",
        display_urls
            .iter()
            .map(|url| url.green().bold().to_string())
            .collect::<Vec<_>>()
            .join("\n    "),
    );

    // print QR code to terminal
    if miniserve_config.show_qrcode && io::stdout().is_terminal() {
        for url in display_urls
            .iter()
            .filter(|url| !url.contains("//127.0.0.1:") && !url.contains("//[::1]:"))
        {
            match QRBuilder::new(url.clone()).ecl(QR_EC_LEVEL).build() {
                Ok(qr) => {
                    println!("QR code for {}:", url.green().bold());
                    qr.print();
                }
                Err(e) => {
                    error!("Failed to render QR to terminal: {:?}", e);
                }
            };
        }
    }

    if io::stdout().is_terminal() {
        println!("Quit by pressing CTRL-C");
    }

    let addr = format!("0.0.0.0:{}", miniserve_config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| StartupError::NetworkError(e.to_string()))?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| StartupError::NetworkError(e.to_string()))?;

    Ok(())
}

/// Allows us to set low-level socket options
///
/// This mainly used to set `set_only_v6` socket option
/// to get a consistent behavior across platforms.
/// see: https://github.com/svenstaro/miniserve/pull/500
fn create_tcp_listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024 /* Default backlog */)?;
    Ok(std::net::TcpListener::from(socket))
}

#[derive(serde::Deserialize, Debug)]
enum ApiCommand {
    /// Request the size of a particular directory
    DirSize(String),
}
