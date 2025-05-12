use anyhow::Result;
use axum::Router;
use axum::routing::get;
use clap::{CommandFactory, Parser, crate_version};
use colored::*;
use log::{error, info, warn};
use miniserve_axum::{CliArgs, MiniserveConfig, StartupError, healthcheck, log_error_chain};
use std::thread;
use std::time::Duration;
use std::{
    io::{self, IsTerminal, Write},
    net::{IpAddr, SocketAddr},
};
use tokio::net::TcpListener;

static STYLESHEET: &str = grass::include!("data/style.scss");

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
        .route("/", get(healthcheck))
        .with_state(inside_config);

    let addr = format!("0.0.0.0:{}", 3333);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| StartupError::NetworkError(e.to_string()))?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| StartupError::NetworkError(e.to_string()))?;

    Ok(())
}
