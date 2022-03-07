mod config;
mod services;
mod static_def;
mod time;
mod timer;
mod users;
mod stdout_log;


use anyhow::{anyhow, Result};
use structopt::*;

use crate::services::IServiceManager;
use crate::static_def::{CONFIG, SERVICE_MANAGER, TIMER_MANAGER};
use crate::users::Listen;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    install_log()?;

    SERVICE_MANAGER.start();
    TIMER_MANAGER.start();
    let server = Listen::new(format!("0.0.0.0:{}", CONFIG.listen_port)).await?;
    server.start().await
}

#[derive(StructOpt, Debug)]
#[structopt(name = "tcp gateway service")]
#[structopt(version=version())]
struct NavOpt {
    /// 是否开启控制台日志输出
    #[structopt(short, long)]
    syslog: bool,
    /// 是否打印崩溃堆栈
    #[structopt(short, long)]
    backtrace: bool,
}

#[inline(always)]
fn version() -> &'static str {
    concat! {
    "\n",
    "==================================version info=================================",
    "\n",
    "Build Timestamp:", env!("VERGEN_BUILD_TIMESTAMP"), "\n",
    "GIT BRANCH:", env!("VERGEN_GIT_BRANCH"), "\n",
    "GIT COMMIT DATE:", env!("VERGEN_GIT_COMMIT_TIMESTAMP"), "\n",
    "GIT SHA:", env!("VERGEN_GIT_SHA"), "\n",
    "PROFILE:", env!("VERGEN_CARGO_PROFILE"), "\n",
    "==================================version end==================================",
    "\n",
    }
}

#[cfg(all(feature = "flexi_log", not(feature = "env_log")))]
static LOGGER_HANDLER: tokio::sync::OnceCell<flexi_logger::LoggerHandle> = tokio::sync::OnceCell::const_new();

fn install_log() -> Result<()> {
    let opt = NavOpt::from_args();
    if opt.backtrace {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    #[cfg(all(feature = "flexi_log", not(feature = "env_log")))]
    {
        use flexi_logger::{Age, Cleanup, Criterion, FileSpec, Logger, Naming, WriteMode};

        if opt.syslog {
            let logger = Logger::try_with_str("trace, sqlx = error,mio=error")?
                .log_to_file_and_writer(
                    FileSpec::default().directory("logs").suppress_timestamp().suffix("log"),
                    Box::new(stdout_log::StdErrLog::new()),
                )
                .format(flexi_logger::opt_format)
                .rotate(Criterion::AgeOrSize(Age::Day, 1024 * 1024 * 5), Naming::Numbers, Cleanup::KeepLogFiles(30))
                .print_message()
                .set_palette("196;190;2;4;8".into())
                .write_mode(WriteMode::Async)
                .start()?;
            LOGGER_HANDLER.set(logger).map_err(|_| anyhow!("logger set error"))?;
        } else {
            let logger = Logger::try_with_str("trace, sqlx = error,mio = error")?
                .log_to_file(FileSpec::default().directory("logs").suppress_timestamp().suffix("log"))
                .format(flexi_logger::opt_format)
                .rotate(Criterion::AgeOrSize(Age::Day, 1024 * 1024 * 5), Naming::Numbers, Cleanup::KeepLogFiles(30))
                .print_message()
                .write_mode(WriteMode::Async)
                .start()?;
            LOGGER_HANDLER.set(logger).map_err(|_| anyhow!("logger set error"))?;
        }
    }
    #[cfg(all(feature = "flexi_log", feature = "env_log"))]
    {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Trace)
            .filter_module("mio::poll", log::LevelFilter::Error)
            .init();
    }

    Ok(())
}
