use failure::Error;

#[derive(Debug, Fail)]
pub enum AliEcsCtlError {
    #[fail(display = "no monitor data for instance: {}", _0)]
    NoMonitorData(String),
}

pub type Result<T> = ::std::result::Result<T, Error>;
