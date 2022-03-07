use crate::config::Config;
use crate::services::ServiceManager;
use crate::timer::{CheckTimeOut, PingCheckTimer, Timer, TimerManager};
use crate::users::UserManager;
use aqueue::Actor;
use std::env::current_dir;
use std::path::Path;

lazy_static::lazy_static! {
    /// 当前运行路径
    pub static ref CURRENT_EXE_PATH:String={
         match std::env::current_exe(){
            Ok(path)=>{
                if let Some(current_exe_path)= path.parent(){
                    return current_exe_path.to_string_lossy().to_string()
                }
                panic!("current_exe_path get error: is none");
            },
            Err(err)=> panic!("current_exe_path get error:{:?}",err)
        }
    };

    /// 加载网关配置
    pub static ref CONFIG:Config={
       let json_path= {
            let json_path=format!("{}/service_cfg.json", CURRENT_EXE_PATH.as_str());
            let path=Path::new(&json_path);
            if !path.exists(){
                let json_path=format!("{}/service_cfg.json", current_dir()
                    .expect("not found current dir")
                    .display());
                let path=Path::new(&json_path);
                if !path.exists(){
                     panic!("not found config file:{:?}",path);
                }else{
                    json_path
                }
            }
            else { json_path }
        };
        let path=Path::new(&json_path);
        serde_json::from_str::<Config>(&std::fs::read_to_string(path)
            .expect("not read service_cfg.json"))
            .expect("read service_cfg.json error")
    };

    /// 服务器管理器
    pub static ref SERVICE_MANAGER:Actor<ServiceManager>={
        ServiceManager::new()
    };

    /// TIME 管理器
    pub static ref TIMER_MANAGER:TimerManager={
        let ts= vec![
            Box::new(PingCheckTimer) as Box<dyn Timer>,
            Box::new(CheckTimeOut) as Box<dyn Timer>
        ];
        TimerManager::new(ts)
    };

    ///客户端管理器
    pub static ref USER_MANAGER:Actor<UserManager>={
        UserManager::new(CONFIG.client_timeout_seconds)
    };
}

#[macro_export]
macro_rules! get_len {
    ($buff:expr) => {
        ($buff.len() - 4) as u32
    };
}
