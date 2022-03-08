mod client;
mod listen;

use ahash::AHashMap;
use anyhow::{ensure, Result};
use aqueue::Actor;
use data_rw::DataOwnedReader;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::time::timestamp;
pub use client::*;
pub use listen::*;

/// 用户管理类
pub struct UserManager {
    /// session id 种子
    make_session_seed: AtomicU32,
    /// 用户表
    users: AHashMap<u32, Arc<Client>>,
    /// 用户超时时间tick
    client_timeout_tick: i64,
}

impl UserManager {
    pub fn new(client_timeout_sec: i32) -> Actor<Self> {
        Actor::new(Self {
            make_session_seed: AtomicU32::new(1),
            users: Default::default(),
            client_timeout_tick: (client_timeout_sec * 10000000) as i64,
        })
    }
    ///制造一个client
    #[inline]
    fn make_client(&mut self, peer: Peer) -> Result<Arc<Client>> {
        let client = Arc::new(Client::new(peer, self.make_session_id()));
        ensure!(
            self.users
                .insert(client.session_id, client.clone())
                .is_none(),
            "session id:{} repeat",
            client.session_id
        );
        Ok(client)
    }
    /// 删除一个client
    #[inline]
    async fn remove_client(&mut self, session_id: u32) -> Result<()> {
        if let Some(peer) = self.users.remove(&session_id) {
            peer.disconnect_now().await?;
        }
        Ok(())
    }

    /// 返回一个 session_id
    #[inline]
    fn make_session_id(&self) -> u32 {
        let old = self.make_session_seed.fetch_add(1, Ordering::Release);
        if old == u32::MAX - 1 {
            self.make_session_seed.store(1, Ordering::Release);
        }
        old
    }

    /// send open peer 通知
    #[inline]
    async fn open_service(&self, service_id: u32, session_id: u32) -> Result<()> {
        if let Some(client) = self.users.get(&session_id) {
            let client = client.clone();
            tokio::spawn(async move {
                if let Err(err) = client.open_service(service_id).await {
                    log::error!(
                        "service:{} peer:{} open_service error:{}",
                        service_id,
                        session_id,
                        err
                    );
                }
            });
        }
        Ok(())
    }

    /// close service 通知
    #[inline]
    async fn close_service(&self, service_id: u32, session_id: u32) -> Result<()> {
        if let Some(client) = self.users.get(&session_id) {
            let client = client.clone();
            tokio::spawn(async move {
                if let Err(err) = client.close_service(service_id).await {
                    log::error!(
                        "service:{} peer:{} close_service error:{}",
                        service_id,
                        session_id,
                        err
                    );
                }
            });
        }
        Ok(())
    }

    /// kick client 通知
    #[inline]
    async fn kick_client(&self, service_id: u32, session_id: u32, delay_ms: i32) -> Result<()> {
        if let Some(client) = self.users.get(&session_id) {
            let client = client.clone();
            tokio::spawn(async move {
                if let Err(err) = client.kick_by_delay(service_id, delay_ms).await {
                    log::error!(
                        "service:{} peer:{} delay_ms:{} kick_by_delay error:{}",
                        service_id,
                        session_id,
                        delay_ms,
                        err
                    );
                }
            });
        }
        Ok(())
    }

    /// 发送buff
    #[inline]
    async fn send_buffer(
        &self,
        service_id: u32,
        session_id: u32,
        buff: DataOwnedReader,
    ) -> Result<()> {
        if let Some(client) = self.users.get(&session_id) {
            let client = client.clone();
            tokio::spawn(async move {
                if let Err(err) = client.send(service_id, &buff[buff.get_offset()..]).await {
                    log::error!(
                        "service:{}  peer:{} send buffer error:{:?}",
                        service_id,
                        session_id,
                        err
                    );
                }
            });
        }
        Ok(())
    }

    /// 检查长时间不发包的客户端 给他T了
    #[inline]
    async fn check_timeout(&mut self) -> Result<()> {
        let current_timestamp = timestamp();
        for session_id in self
            .users
            .values()
            .filter_map(|client| {
                if current_timestamp - client.last_recv_time.load(Ordering::Acquire)
                    > self.client_timeout_tick
                {
                    Some(client.session_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
        {
            if let Some(client) = self.users.remove(&session_id) {
                log::info!("peer:{} timeout need disconnect", client);
                if let Err(err) = client.disconnect_now().await {
                    log::error!("remove peer:{} is error:{:?}", client, err)
                }
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
pub trait IUserManager {
    /// 制造一个 session_id
    fn make_session_id(&self) -> u32;
    /// 制造一个 client
    async fn make_client(&self, peer: Peer) -> Result<Arc<Client>>;
    /// 删除一个client
    async fn remove_client(&self, session_id: u32) -> Result<()>;
    /// send open service 通知
    async fn open_service(&self, service_id: u32, session_id: u32) -> Result<()>;
    /// close service 通知
    async fn close_service(&self, service_id: u32, session_id: u32) -> Result<()>;
    /// kick client 通知
    async fn kick_client(&self, service_id: u32, session_id: u32, delay_ms: i32) -> Result<()>;
    /// 发送buff
    async fn send_buffer(
        &self,
        service_id: u32,
        session_id: u32,
        buff: DataOwnedReader,
    ) -> Result<()>;
    /// 检查长时间不发包的客户端 给他T了
    async fn check_timeout(&self) -> Result<()>;
}

#[async_trait::async_trait]
impl IUserManager for Actor<UserManager> {
    #[inline]
    fn make_session_id(&self) -> u32 {
        unsafe { self.deref_inner().make_session_id() }
    }
    #[inline]
    async fn make_client(&self, peer: Peer) -> Result<Arc<Client>> {
        self.inner_call(|inner| async move { inner.get_mut().make_client(peer) })
            .await
    }
    #[inline]
    async fn remove_client(&self, session_id: u32) -> Result<()> {
        self.inner_call(|inner| async move { inner.get_mut().remove_client(session_id).await })
            .await
    }

    #[inline]
    async fn open_service(&self, service_id: u32, session_id: u32) -> Result<()> {
        self.inner_call(
            |inner| async move { inner.get().open_service(service_id, session_id).await },
        )
        .await
    }

    #[inline]
    async fn close_service(&self, service_id: u32, session_id: u32) -> Result<()> {
        self.inner_call(
            |inner| async move { inner.get().close_service(service_id, session_id).await },
        )
        .await
    }

    #[inline]
    async fn kick_client(&self, service_id: u32, session_id: u32, delay_ms: i32) -> Result<()> {
        self.inner_call(|inner| async move {
            inner
                .get()
                .kick_client(service_id, session_id, delay_ms)
                .await
        })
        .await
    }
    #[inline]
    async fn send_buffer(
        &self,
        service_id: u32,
        session_id: u32,
        buff: DataOwnedReader,
    ) -> Result<()> {
        self.inner_call(|inner| async move {
            inner.get().send_buffer(service_id, session_id, buff).await
        })
        .await
    }

    #[inline]
    async fn check_timeout(&self) -> Result<()> {
        self.inner_call(|inner| async move { inner.get_mut().check_timeout().await })
            .await
    }
}
