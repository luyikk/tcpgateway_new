use chrono::Local;

/// 获取local时间戳 秒后 7个0
#[inline]
pub fn timestamp() -> i64 {
    Local::now().timestamp_nanos() / 100
}
