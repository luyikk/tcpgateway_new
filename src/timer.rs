mod check_ping;
mod check_timeout;

use anyhow::Result;
use log::*;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{sleep, Duration};

pub use check_ping::PingCheckTimer;
pub use check_timeout::CheckTimeOut;

/// 定时器
#[async_trait::async_trait]
pub trait Timer: Send + Sync {
    /// 初始化,并返回间隔时间
    async fn init(&self) -> Result<(bool, u64)>;
    /// 运行
    async fn run(&self) -> Result<()>;
}

/// 定时器管理器
pub struct TimerManager {
    stats: AtomicBool,
    timers: RefCell<Vec<Box<dyn Timer>>>,
}

unsafe impl Sync for TimerManager {}

impl TimerManager {
    pub fn new(timers: Vec<Box<dyn Timer>>) -> Self {
        TimerManager {
            stats: AtomicBool::new(false),
            timers: RefCell::new(timers),
        }
    }

    /// 启动定时器
    pub fn start(&self) {
        if self
            .stats
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            for p in self.timers.take() {
                tokio::spawn(async move {
                    match p.init().await {
                        Ok((mut now_run, sleep_time_ms)) => loop {
                            if !now_run {
                                sleep(Duration::from_millis(sleep_time_ms)).await;
                            }
                            if let Err(er) = p.run().await {
                                error!("timer error:{:?}", er);
                                if cfg!(debug_assertions) {
                                    break;
                                }
                            }
                            now_run = false;
                        },
                        Err(err) => error!("timer init error:{:?}", err),
                    }
                });
            }

            info!("timer is start");
        }
    }
}
