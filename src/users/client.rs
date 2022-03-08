use crate::time::timestamp;
use crate::{get_len, IServiceManager, SERVICE_MANAGER};
use anyhow::{ensure, Result};
use bytes::BufMut;
use data_rw::DataOwnedReader;
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tcpserver::IPeer;
use tokio::time::sleep;

use crate::users::Peer;

/// 客户端client
pub struct Client {
    pub session_id: u32,
    pub peer: Peer,
    pub address: String,
    pub is_open_zero: AtomicBool,
    pub last_recv_time: AtomicI64,
}

impl Drop for Client {
    fn drop(&mut self) {
        log::debug! {"Client:{} drop",self}
    }
}

impl Display for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.session_id, self.address)
    }
}

impl Client {
    #[inline]
    pub fn new(peer: Peer, session_id: u32) -> Self {
        let address = peer.addr().to_string();
        Self {
            session_id,
            peer,
            address,
            is_open_zero: Default::default(),
            last_recv_time: AtomicI64::new(timestamp()),
        }
    }

    /// 立刻断线 同时清理
    #[inline]
    pub async fn disconnect_now(&self) -> Result<()> {
        // 先关闭OPEN 0 标志位
        self.is_open_zero.store(false, Ordering::Release);
        // 管它有没有 每个服务器都调用下 DropClientPeer 让服务器的 DropClientPeer 自己检查
        SERVICE_MANAGER.disconnect_events(self.session_id).await?;
        // 断线
        self.peer.disconnect().await
    }

    /// 服务器open ok
    #[inline]
    pub async fn open_service(&self, service_id: u32) -> Result<()> {
        log::info!("service:{} open peer:{} OK", service_id, self.session_id);
        self.is_open_zero.store(true, Ordering::Release);
        self.send_open(service_id).await
    }

    /// 服务器通知 关闭某个服务
    #[inline]
    pub async fn close_service(&self, service_id: u32) -> Result<()> {
        log::info!("service:{} close peer:{} ok", service_id, self.session_id);
        if service_id == 0 {
            self.kick().await
        } else {
            self.send_close(service_id).await
        }
    }

    /// kick 命令
    #[inline]
    pub async fn kick_by_delay(&self, service_id: u32, mut delay_ms: i32) -> Result<()> {
        log::info!("service:{} kick peer:{}", service_id, self);
        self.send_close(0).await?;
        if !(0..=30000).contains(&delay_ms) {
            delay_ms = 5000;
        }

        let peer = self.peer.clone();
        let session_id = self.session_id;
        tokio::spawn(async move {
            sleep(Duration::from_millis(delay_ms as u64)).await;
            log::info!("start kick peer:{}", session_id);
            if let Err(err) = peer.disconnect().await {
                log::warn!("kick {} send disconnect err:{}", session_id, err);
            }
        });
        Ok(())
    }

    /// 发送 CLOSE 0 后立即断线清理内存
    #[inline]
    async fn kick(&self) -> Result<()> {
        self.send_close(0).await?;
        self.disconnect_now().await
    }

    /// 发送数据包给客户端
    #[inline]
    pub async fn send(&self, session_id: u32, buff: &[u8]) -> Result<()> {
        let mut buffer = data_rw::Data::new();
        buffer.write_fixed(0u32);
        buffer.write_fixed(session_id);
        buffer.write_buf(buff);
        let len = get_len!(buffer);
        (&mut buffer[0..4]).put_u32_le(len);
        self.send_buff(buffer.into_inner()).await
    }

    /// 发送服务器open
    #[inline]
    async fn send_open(&self, service_id: u32) -> Result<()> {
        let mut buffer = data_rw::Data::new();
        buffer.write_fixed(0u32);
        buffer.write_fixed(0xFFFFFFFFu32);
        buffer.write_var_integer("open");
        buffer.write_var_integer(service_id);
        let len = get_len!(buffer);
        (&mut buffer[0..4]).put_u32_le(len);
        self.send_buff(buffer.into_inner()).await
    }

    /// 发送close 命令
    #[inline]
    async fn send_close(&self, service_id: u32) -> Result<()> {
        let mut buffer = data_rw::Data::new();
        buffer.write_fixed(0u32);
        buffer.write_fixed(0xFFFFFFFFu32);
        buffer.write_var_integer("close");
        buffer.write_var_integer(service_id);
        let len = get_len!(buffer);
        (&mut buffer[0..4]).put_u32_le(len);
        self.send_buff(buffer.into_inner()).await
    }

    /// 发送数据包
    #[inline]
    async fn send_buff<B: Deref<Target = [u8]> + Send + Sync + 'static>(
        &self,
        buff: B,
    ) -> Result<()> {
        if !self.peer.is_disconnect().await? {
            let session_id = self.session_id;
            if let Err(err) = self.peer.send_all(buff).await {
                log::error!("peer:{} send data error:{}", session_id, err)
            }
        }
        Ok(())
    }
}

/// 客户端数据包处理
#[inline]
pub async fn input_buff(client: &Arc<Client>, data: Vec<u8>) -> Result<()> {
    ensure!(
        data.len() > 4,
        "peer:{} data len:{} <4",
        client.session_id,
        data.len()
    );
    let mut reader = DataOwnedReader::new(data);
    let server_id = reader.read_fixed::<u32>()?;
    client.last_recv_time.store(timestamp(), Ordering::Release);
    if u32::MAX == server_id {
        //给网关发送数据包,默认当PING包无脑回
        client.send(server_id, &reader[reader.get_offset()..]).await    
    } else {
        SERVICE_MANAGER
            .send_buffer(client.session_id, server_id, reader)
            .await
    }
}
