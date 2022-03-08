use anyhow::{ensure, Result};
use aqueue::Actor;
use log::info;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tcpserver::*;
use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::static_def::USER_MANAGER;
use crate::users::{input_buff, Client, IUserManager};
use crate::{IServiceManager, SERVICE_MANAGER};

/// 最大数据表长度限制 512K
const MAX_BUFF_LEN: usize = 512 * 1024;

pub type Peer = Arc<Actor<TCPPeer<TcpStream>>>;

/// 客户端监听服务
pub struct Listen {
    server: Arc<dyn ITCPServer<()>>,
}

impl Listen {
    pub async fn new<ToAddress: ToSocketAddrs>(address: ToAddress) -> Result<Self> {
        let server = Builder::new(address)
            .set_connect_event(|address| {
                info!("address:{} connect", address);
                true
            })
            .set_stream_init(|stream| async move { Ok(stream) })
            .set_input_event(|reader, peer, _| async move {
                let client = USER_MANAGER.make_client(peer).await?;
                let session_id = client.session_id;
                let res = Self::data_input(reader, client).await;
                if let Err(err) = USER_MANAGER.remove_client(session_id).await {
                    log::error!("remove peer:{} error:{}", session_id, err);
                }
                res
            })
            .build()
            .await;
        Ok(Self { server })
    }

    /// 启动服务器
    pub async fn start(&self) -> Result<()> {
        self.server.start_block(()).await
    }

    /// 数据包处理
    #[inline]
    async fn data_input(mut reader: ReadHalf<TcpStream>, client: Arc<Client>) -> Result<()> {
        log::debug!("create peer:{}", client);
        SERVICE_MANAGER
            .open_service(client.session_id, 0, &client.address)
            .await?;

        loop {
            let len = {
                // let res = timeout(
                //     Duration::from_secs(CONFIG.client_timeout_seconds as u64),
                //     reader.read_u32_le(),
                // )
                // .await
                // .map_err(|_| {
                //     anyhow!(
                //         "client:{}-{} {} secs not read data",
                //         session_id,
                //         address,
                //         CONFIG.client_timeout_seconds as u64
                //     )
                // })?;

                // if let Ok(len) = res {
                //     len as usize
                // } else {
                //     log::warn!("client:{} disconnect not read data", client);
                //     break;
                // }

                match reader.read_u32_le().await {
                    Ok(len) => len as usize,
                    Err(err) => {
                        log::warn!("peer:{} disconnect,err:{}", client, err);
                        break;
                    }
                }
            };
            //如果没有OPEN 直接掐线
            if !client.is_open_zero.load(Ordering::Acquire) {
                log::warn!("peer:{} not open send data,disconnect!", client);
                break;
            }

            // 如果长度为0 或者超过最大限制 掐线
            if len >= MAX_BUFF_LEN || len <= 4 {
                log::warn!("disconnect peer:{} packer len error:{}", client, len);
                break;
            }

            let mut data = vec![0; len];
            match reader.read_exact(&mut data).await {
                Ok(rev) => {
                    ensure!(
                        len == rev,
                        "peer:{} read buff error len:{}>rev:{}",
                        client,
                        len,
                        rev
                    );

                    input_buff(&client, data).await?;
                }
                Err(err) => {
                    log::error!("peer:{} read data error:{:?}", client, err);
                    break;
                }
            }
        }
        Ok(())
    }
}
