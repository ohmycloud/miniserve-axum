use anyhow::Result;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::{any, get, post};
use clap::{CommandFactory, Parser, crate_version};
use colored::*;
use fast_qr::QRBuilder;
use log::{error, warn};
use miniserve_axum::basic_auth_guard;
use miniserve_axum::error_page::error_page_middleware;
use miniserve_axum::{
    CliArgs, LogColor, MiniserveConfig, QR_EC_LEVEL, StartupError, api, configure_header, css,
    favicon, healthcheck, log_error_chain, rm_file_handler, serve_handler, upload_file_handler,
};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::{future::Future, pin::Pin};
use std::{
    io::{self, IsTerminal, Write},
    net::{IpAddr, SocketAddr},
};
use tower_http::{compression::CompressionLayer, trace::TraceLayer};

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

fn run(miniserve_config: MiniserveConfig) -> Result<(), StartupError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(miniserve_config.workers.max(1))
        .enable_all()
        .build()
        .map_err(|e| StartupError::IoError("Failed to create runtime".into(), e))?;
    runtime.block_on(run_server(miniserve_config))
}

async fn run_server(miniserve_config: MiniserveConfig) -> Result<(), StartupError> {
    let log_level = if miniserve_config.verbose {
        simplelog::LevelFilter::Info
    } else {
        simplelog::LevelFilter::Warn
    };

    let color_choice = match miniserve_config.log_color {
        LogColor::Auto if io::stdout().is_terminal() => simplelog::ColorChoice::Auto,
        LogColor::Always => {
            colored::control::SHOULD_COLORIZE.set_override(true);
            simplelog::ColorChoice::Always
        }
        LogColor::Never => {
            colored::control::SHOULD_COLORIZE.set_override(false);
            simplelog::ColorChoice::Never
        }
        LogColor::Auto => simplelog::ColorChoice::Never,
    };
    simplelog::TermLogger::init(
        log_level,
        simplelog::ConfigBuilder::new()
            .set_time_format_rfc2822()
            .build(),
        simplelog::TerminalMode::Mixed,
        color_choice,
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

    let inside_config = Arc::new(miniserve_config.clone());

    let canon_path = miniserve_config
        .path
        .canonicalize()
        .map_err(|e| StartupError::IoError("Failed to resolve path to be served".to_string(), e))?;

    // warn if --index is specified but not found
    if let Some(ref index) = miniserve_config.index
        && !canon_path.join(index).exists()
        && !miniserve_config.quiet
    {
        warn!(
            "The file '{}' provided for option --index could not be found.",
            index.to_string_lossy(),
        );
    }

    let path_string = canon_path.to_string_lossy();

    if !miniserve_config.quiet {
        println!(
            "{name} v{version}",
            name = "miniserve".bold(),
            version = crate_version!()
        );
    }
    if !miniserve_config.path_explicitly_chosen {
        // If the path to serve has NOT been explicitly chosen and if this is NOT an interactive
        // terminal, we should refuse to start for security reasons. This would be the case when
        // running miniserve as a service but forgetting to set the path. This could be pretty
        // dangerous if given with an undesired context path (for instance /root or /).
        if !io::stdout().is_terminal() {
            return Err(StartupError::NoExplicitPathAndNoTerminal);
        }

        if !miniserve_config.quiet {
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

    // Public routes
    let base_app = Router::<Arc<MiniserveConfig>>::new()
        .route(&inside_config.healthcheck_route, get(healthcheck))
        .route(&inside_config.favicon_route, get(favicon))
        .route(&inside_config.css_route, get(css))
        .route(&inside_config.api_route, post(api));

    // Protected content
    let prefix = &inside_config.route_prefix;
    let mut protected = Router::<Arc<MiniserveConfig>>::new()
        .route(&format!("{prefix}/upload"), post(upload_file_handler))
        .route(&format!("{prefix}/rm"), post(rm_file_handler))
        .route(&format!("{prefix}/"), any(serve_handler))
        .route(&format!("{prefix}/{{*path}}"), any(serve_handler));
    if !prefix.is_empty() {
        protected = protected.route(prefix, any(serve_handler));
    }
    let protected = protected.layer(from_fn_with_state(inside_config.clone(), basic_auth_guard));

    let mut app = base_app
        .merge(protected)
        .layer(from_fn_with_state(
            inside_config.clone(),
            error_page_middleware,
        ))
        .layer(from_fn_with_state(inside_config.clone(), configure_header))
        .layer(TraceLayer::new_for_http())
        .with_state(inside_config)
        // Allow large file uploads by disabling Axum's default 2MB body limit
        .layer(DefaultBodyLimit::disable());
    if miniserve_config.compress_response {
        app = app.layer(CompressionLayer::new());
    }

    if !miniserve_config.quiet {
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
    }

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

    if !miniserve_config.quiet && io::stdout().is_terminal() {
        println!("Quit by pressing CTRL-C");
    }

    let mut servers: Vec<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>> = Vec::new();
    for address in socket_addresses {
        let listener = create_tcp_listener(address)
            .map_err(|e| StartupError::IoError(format!("Failed to bind server to {address}"), e))?;
        let router = app.clone();
        #[cfg(feature = "tls")]
        if let Some(tls) = &miniserve_config.tls_rustls_config {
            let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls.clone()));
            servers.push(Box::pin(async move {
                axum_server::from_tcp_rustls(listener, tls)
                    .serve(router.into_make_service())
                    .await
            }));
            continue;
        }
        servers.push(Box::pin(async move {
            axum_server::from_tcp(listener)
                .serve(router.into_make_service())
                .await
        }));
    }
    futures::future::try_join_all(servers)
        .await
        .map_err(|e| StartupError::NetworkError(e.to_string()))?;

    Ok(())
}

fn create_tcp_listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}
