use vergen::{Config,vergen};

fn main()->anyhow::Result<()> {
    vergen(Config::default())?;
    Ok(())
}