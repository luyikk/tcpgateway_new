use crate::timer::Timer;
use crate::{IServiceManager, SERVICE_MANAGER};

pub struct PingCheckTimer;

#[async_trait::async_trait]
impl Timer for PingCheckTimer {
    async fn init(&self) -> anyhow::Result<(bool, u64)> {
        Ok((false, 5000))
    }

    async fn run(&self) -> anyhow::Result<()> {
        SERVICE_MANAGER.check_ping().await
    }
}
