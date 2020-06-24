use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::{Ipv4Net, Ipv6Net};
use log::Level;
use serde::Deserialize;
use url::Url;

use crate::parser::{Domain, Parser};

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,

    #[serde(deserialize_with = "parse_log_level", default = "default_log_level")]
    pub log_level: Level,

    #[serde(default)]
    #[serde(deserialize_with = "parse_num_threads")]
    pub core_threads: Option<usize>,

    #[serde(default)]
    #[serde(deserialize_with = "parse_num_threads")]
    pub max_threads: Option<usize>,

    pub aggregate: Option<AggregatePaths>,
    pub bootstrap: Option<Templates>,
    pub diff: Option<ChunkedTemplates>,

    #[serde(default = "empty_hash_map")]
    pub downloads: Downloads,

    #[serde(default = "empty_hash_map")]
    pub ipv4: Groups<Ipv4Net>,

    #[serde(default = "empty_hash_map")]
    pub ipv6: Groups<Ipv6Net>,
}

#[derive(Debug, Deserialize)]
pub struct AggregatePaths {
    pub ipv4: PathBuf,
    pub ipv6: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Templates {
    pub input: PathBuf,
    pub output: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChunkedTemplates {
    #[serde(flatten)]
    pub templates: Templates,
    pub max_ranges_per_file: Option<usize>,
}

pub type Downloads = HashMap<String, RemoteResource>;

pub type Groups<T> = HashMap<String, Group<T>>;

#[derive(Debug, Deserialize)]
pub struct Group<T> {
    pub priority: u16,
    pub kind: Option<String>,

    #[serde(flatten)]
    #[serde(default = "empty_hash_map")]
    pub feeds: Feeds<T>,
}

pub type Feeds<T> = HashMap<String, Feed<T>>;

#[derive(Debug, Clone, Deserialize)]
pub struct Feed<T> {
    #[serde(flatten)]
    pub source: Source<T>,
    pub class: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source<T> {
    Range(T),
    Domain(Domain),
    File(FileSource<T>),
    Remote(RemoteSource<T>),
    Download(DownloadSource<T>),
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileSource<T> {
    pub path: PathBuf,
    pub parser: ParserType<T>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteSource<T> {
    #[serde(flatten)]
    pub resource: RemoteResource,
    pub parser: ParserType<T>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteResource {
    #[serde(deserialize_with = "parse_url")]
    pub url: Url,
    #[serde(deserialize_with = "parse_duration")]
    pub check_interval: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DownloadSource<T> {
    pub name: String,
    pub parser: ParserType<T>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserType<T> {
    Ranges(Parser<T>),
    Domains(Parser<Domain>),
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/drib")
}

fn default_log_level() -> Level {
    Level::Info
}

fn empty_hash_map<T>() -> HashMap<String, T> {
    HashMap::new()
}

fn parse_log_level<'de, D>(deserializer: D) -> Result<Level, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: String = serde::de::Deserialize::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

fn parse_num_threads<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: String = serde::de::Deserialize::deserialize(deserializer)?;
    match s.parse() {
        Ok(0) => Err(serde::de::Error::custom(
            "number of threads must be positive",
        )),
        Ok(n) if n > 2usize.pow(15) => Err(serde::de::Error::custom(
            "number of threads must be less than 32,768",
        )),
        Ok(n) => Ok(Some(n)),
        Err(e) => Err(serde::de::Error::custom(e)),
    }
}

fn parse_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: String = serde::de::Deserialize::deserialize(deserializer)?;
    humantime::parse_duration(&s).map_err(serde::de::Error::custom)
}

fn parse_url<'de, D>(deserializer: D) -> Result<Url, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: String = serde::de::Deserialize::deserialize(deserializer)?;
    let url = Url::parse(&s).map_err(serde::de::Error::custom)?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(serde::de::Error::custom(format!(
            "unsupported {} feed",
            scheme
        )));
    }
    Ok(url)
}
