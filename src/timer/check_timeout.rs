use crate::static_def::USER_MANAGER;
use crate::timer::Timer;
use crate::users::IUserManager;

/// 检查客户端长时间不发包
pub struct CheckTimeOut;

#[async_trait::async_trait]
impl Timer for CheckTimeOut {
    async fn init(&self) -> anyhow::Result<(bool, u64)> {
        Ok((false, 5000))
    }

    async fn run(&self) -> anyhow::Result<()> {
        USER_MANAGER.check_timeout().await
    }
}
