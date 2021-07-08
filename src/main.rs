use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;
use std::hash::Hash;
use std::io::ErrorKind;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::str;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use chrono::{DateTime, Utc};
use clap::{crate_name, crate_version, Clap};
use ipnet::{Ipv4Net, Ipv6Net};
use iprange::{IpNet, IpRange};
use log::{debug, error, info, warn, Level};
use reqwest::{header::IF_MODIFIED_SINCE, Client, StatusCode};
use tokio::fs::{self, OpenOptions};
use tokio::io;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::AsyncResolver;
use url::Url;

use drib::aggregate::{self, Aggregate, AggregateSaveError, Entry};
use drib::config::{Config, Downloads, Feed, Feeds, Groups, ParserType, RemoteResource, Source};
use drib::domain::Domain;
use drib::error::{ClassIntersectionError, ConfigError};
use drib::net::Net;
use drib::output::{self, Bootstrap, Changes, Diff};
use drib::parser::{Parse, ParseError};
use drib::util::safe_write;

const DOWNLOAD_DIR: &'static str = "downloads";
const IPV4_DIR: &'static str = "ipv4";
const IPV6_DIR: &'static str = "ipv6";
const RESOLVED_DIR: &'static str = "resolved";
const AGGREGATE_FILE: &'static str = "aggregate";
const OLD_AGGREGATE_EXTENSION: &'static str = "old";

type ClassRanges<T> = HashMap<String, IpRange<T>>;

#[derive(Debug, Clap)]
#[clap(name = crate_name!(), version = crate_version!())]
struct Opts {
    #[clap(
        short,
        long,
        name = "FILE",
        default_value = "/etc/drib/drib.yaml",
        parse(from_os_str)
    )]
    config: PathBuf,
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Debug, Copy, Clone, Clap)]
enum Mode {
    #[clap(about = "aggregate mode")]
    Aggregate,
    #[clap(about = "bootstrap mode")]
    Bootstrap(NoDownload),
    #[clap(about = "diff mode")]
    Diff(NoDownload),
}

#[derive(Debug, Clone, Copy, Clap)]
struct NoDownload {
    #[clap(long, about = "use previously generated aggregate")]
    no_download: bool,
}

fn main() -> Result<(), anyhow::Error> {
    let opts = Opts::parse();

    let config = load_config(&opts.config).with_context(|| {
        format!(
            "failed to read configuration file '{}'",
            opts.config.display()
        )
    })?;

    setup_logger(&config.log_level);

    let mut rt = match config.worker_threads {
        Some(1) => Builder::new_current_thread(),
        Some(n) => {
            let mut b = Builder::new_multi_thread();
            b.worker_threads(n);
            b
        }
        None => {
            let n = num_cpus::get();
            let mut b = Builder::new_multi_thread();
            b.worker_threads(n);
            b
        }
    };
    rt.enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(work(&config, opts.mode))
}

fn load_config(path: impl AsRef<Path>) -> Result<Config, anyhow::Error> {
    let path = path.as_ref();
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;
    let config: Config = serde_yaml::from_str(&data).context("configuration deserialize failed")?;
    Ok(config)
}

struct Paths {
    ipv4: PathBuf,
    ipv6: PathBuf,
    aggregate: PathBuf,
    downloads: PathBuf,
}

impl<'a> From<&'a Config> for Paths {
    fn from(config: &Config) -> Paths {
        let path = &config.state_dir;
        Paths {
            ipv4: path.join(IPV4_DIR),
            ipv6: path.join(IPV6_DIR),
            aggregate: path.join(AGGREGATE_FILE),
            downloads: path.join(DOWNLOAD_DIR),
        }
    }
}

async fn work(config: &Config, mode: Mode) -> Result<(), anyhow::Error> {
    let path = &config.state_dir;
    fs::create_dir_all(path)
        .await
        .with_context(|| format!("failed to create protocol path '{}'", path.display()))?;

    let paths = Paths::from(config);

    let (new_ipv4, new_ipv6) = match mode {
        Mode::Aggregate => fetch_aggregates(&paths, &config).await?,
        Mode::Bootstrap(NoDownload { no_download }) if config.bootstrap.is_some() => {
            let (ipv4, ipv6) = if no_download {
                aggregate::deserialize(&paths.aggregate)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to load aggregates from '{}'",
                            &paths.aggregate.display()
                        )
                    })?
            } else {
                fetch_aggregates(&paths, &config).await?
            };

            let bootstrap = Bootstrap::new(&ipv4, &ipv6);
            info!("ipv4: +{}", bootstrap.ipv4_len());
            info!("ipv6: +{}", bootstrap.ipv6_len());
            let templates = config.bootstrap.as_ref().unwrap();
            output::render_bootstrap(&bootstrap, &templates.input, &templates.output).await?;

            (ipv4, ipv6)
        }
        Mode::Bootstrap(_) => {
            return Err(ConfigError::MissingSetting("bootstrap".to_owned()).into());
        }
        Mode::Diff(NoDownload { no_download }) if config.diff.is_some() => {
            let ((new_ipv4, new_ipv6), (cur_ipv4, cur_ipv6)) = if no_download {
                let new = aggregate::deserialize(&paths.aggregate)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to load new aggregates from '{}'",
                            &paths.aggregate.display()
                        )
                    })?;

                let cur = aggregate::deserialize(old_aggregate_path(&paths.aggregate))
                    .await
                    .with_context(|| {
                        format!(
                            "failed to load current aggregates from '{}'",
                            &paths.ipv4.display()
                        )
                    })?;

                (new, cur)
            } else {
                let new = fetch_aggregates(&paths, &config).await?;
                let cur = aggregate::deserialize(&paths.aggregate).await?;
                (new, cur)
            };

            let (ipv4_insert, ipv4_remove) = (&new_ipv4 - &cur_ipv4, &cur_ipv4 - &new_ipv4);
            let (ipv6_insert, ipv6_remove) = (&new_ipv6 - &cur_ipv6, &cur_ipv6 - &new_ipv6);

            let diff = Diff {
                ipv4: Changes::from_aggregates(&ipv4_insert, &ipv4_remove),
                ipv6: Changes::from_aggregates(&ipv6_insert, &ipv6_remove),
            };
            info!(
                "ipv4: +{}, -{}",
                diff.ipv4.insert.len(),
                diff.ipv4.remove.len()
            );
            info!(
                "ipv6: +{}, -{}",
                diff.ipv6.insert.len(),
                diff.ipv6.remove.len()
            );
            let config = config.diff.as_ref().unwrap();
            output::render_diff(
                &diff,
                &config.templates.input,
                &config.templates.output,
                config.max_ranges_per_file,
            )
            .await?;

            (new_ipv4, new_ipv6)
        }
        Mode::Diff(_) => {
            return Err(ConfigError::MissingSetting("diff".to_owned()).into());
        }
    };

    save_aggregates(&paths.aggregate, &new_ipv4, &new_ipv6).await?;

    Ok(())
}

async fn fetch_aggregates(
    paths: &Paths,
    config: &Config,
) -> Result<(Aggregate<Ipv4Net>, Aggregate<Ipv6Net>), anyhow::Error> {
    download(&paths.downloads, &config.downloads).await?;

    let new_ipv4_aggregate = fetch_aggregate(&paths.ipv4, &paths.downloads, &config.ipv4).await?;
    let new_ipv6_aggregate = fetch_aggregate(&paths.ipv6, &paths.downloads, &config.ipv6).await?;

    Ok((new_ipv4_aggregate, new_ipv6_aggregate))
}

async fn download(path: impl AsRef<Path>, downloads: &Downloads) -> Result<(), anyhow::Error> {
    fs::create_dir_all(&path).await.with_context(|| {
        format!(
            "failed to create downloads directory '{}'",
            path.as_ref().display()
        )
    })?;

    for (name, res) in downloads {
        if let Err(e) = download_resource(&path, name, res).await {
            error!("{}: failed to download '{}': {}", name, res.url, e);
            continue;
        }
    }
    Ok(())
}

async fn save_aggregates(
    path: impl AsRef<Path>,
    ipv4: &Aggregate<Ipv4Net>,
    ipv6: &Aggregate<Ipv6Net>,
) -> Result<(), AggregateSaveError> {
    rename_aggregate(&path).await?;
    aggregate::serialize(&path, ipv4, ipv6).await?;
    Ok(())
}

async fn rename_aggregate(path: impl AsRef<Path>) -> Result<(), io::Error> {
    let old = old_aggregate_path(&path);

    match fs::rename(&path, &old).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn old_aggregate_path(path: impl AsRef<Path>) -> PathBuf {
    let mut old = PathBuf::from(path.as_ref());
    old.set_extension(OLD_AGGREGATE_EXTENSION);
    old
}

async fn fetch_aggregate<P, T>(
    path: P,
    downloads_path: P,
    groups: &Groups<T>,
) -> Result<Aggregate<T>, anyhow::Error>
where
    P: AsRef<Path>,
    T: Net + Eq + Hash + Display + Default + Send + Sync + 'static,
{
    fs::create_dir_all(&path).await.with_context(|| {
        format!(
            "failed to create protocol directory '{}'",
            path.as_ref().display()
        )
    })?;

    let groups = fetch_groups(&path, &downloads_path, groups).await?;

    let mut res = Aggregate::new();
    let mut acc = IpRange::new();

    let protocol = T::protocol();

    // The `groups` map is sorted by ascending priority, so we iterate
    // in reverse. For each group, we remove every range that appears
    // in lower priority groups. Its own ranges are then merged with the
    // accumulated ones, to be removed from the next iteration's group.
    for ((priority, kind), class_ranges) in groups.iter().rev() {
        let filtered = remove_lower_priority_ranges(&acc, &class_ranges);

        for (class, ranges) in filtered {
            for range in &ranges {
                let kind = kind.map(|k| k.to_owned());
                let class = class.to_owned();
                let protocol = protocol.to_owned();
                let entry = Entry::new(*priority, kind, class, protocol, range);
                res.insert(entry);
            }
        }

        let merged = merge_class_ranges(&class_ranges);
        acc = acc.merge(&merged);
    }

    Ok(res)
}

async fn fetch_groups<P, T>(
    path: P,
    downloads_path: P,
    groups: &Groups<T>,
) -> Result<BTreeMap<(u16, Option<&str>), ClassRanges<T>>, anyhow::Error>
where
    P: AsRef<Path>,
    T: Net + Eq + Hash + Display + Send + Sync + 'static,
{
    let mut res = BTreeMap::new();

    for (name, group) in groups {
        let path = path.as_ref().join(&name);
        fs::create_dir_all(&path)
            .await
            .with_context(|| format!("failed to create group directory '{}'", path.display()))?;
        let class_ranges = fetch_feed_ranges(&path, &downloads_path, &group.feeds).await?;
        res.insert((group.priority, group.kind.as_deref()), class_ranges);
    }

    Ok(res)
}

async fn fetch_feed_ranges<T>(
    path: impl AsRef<Path>,
    downloads_path: impl AsRef<Path>,
    feeds: &Feeds<T>,
) -> Result<ClassRanges<T>, anyhow::Error>
where
    T: Parse + Net + Eq + Hash + Display + Send + Sync + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel();

    for (name, feed) in feeds {
        let path = PathBuf::from(path.as_ref());
        let downloads_path = PathBuf::from(downloads_path.as_ref());
        let name = name.clone();
        let feed = feed.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let res = fetch_feed(&path, &downloads_path, &name, &feed).await;
            tx.send(res.map(|ranges| (feed.class.clone(), ranges)))
                .expect("send range set failed");
        });
    }

    let mut class_ranges = HashMap::new();

    for _ in 0..feeds.len() {
        let (class, range_set) = rx
            .recv()
            .await
            .expect("receive range set failed")
            .context("fetch field failed")?;
        let ranges = class_ranges.entry(class.clone()).or_insert(IpRange::new());
        let range = IpRange::from_iter(range_set.into_iter());
        *ranges = ranges.merge(&range);
    }

    validate_class_ranges_dont_intersect(&class_ranges)?;

    Ok(class_ranges)
}

async fn fetch_feed<T>(
    path: impl AsRef<Path>,
    downloads_path: impl AsRef<Path>,
    name: &str,
    feed: &Feed<T>,
) -> Result<HashSet<T>, anyhow::Error>
where
    T: Net + Display + Hash + Send + 'static,
{
    match feed.source {
        Source::Range(range) => {
            let mut res = HashSet::new();
            res.insert(range);
            Ok(res)
        }
        Source::Domain(ref domain) => {
            let mut domains = HashSet::new();
            domains.insert(domain.clone());
            resolve_domains(&path, &domains)
                .await
                .with_context(|| format!("{}: failed to resolve", domain))
        }
        Source::File(ref src) => {
            let data = fs::read_to_string(&src.path).await.with_context(|| {
                format!(
                    "{}: failed to read file source from '{}'",
                    name,
                    src.path.display()
                )
            })?;
            parse_feed(&path, &src.parser, &data)
                .await
                .with_context(|| format!("{}: failed to parse feed", name))
        }
        Source::Remote(ref src) => {
            let res = &src.resource;
            let data = download_resource(&path, name, &res)
                .await
                .with_context(|| format!("{}: failed to download from '{}'", name, res.url))?;
            parse_feed(&path, &src.parser, &data)
                .await
                .with_context(|| format!("{}: failed to parse feed", name))
        }
        Source::Download(ref src) => {
            let path = downloads_path.as_ref().join(&src.name);
            let data = fs::read_to_string(&path).await.with_context(|| {
                format!(
                    "{}: failed to read download source {} from '{}'",
                    name,
                    src.name,
                    path.display()
                )
            })?;
            parse_feed(&path, &src.parser, &data)
                .await
                .with_context(|| format!("{}: failed to parse feed", name))
        }
    }
}

async fn parse_feed<P, T>(
    path: P,
    parser: &ParserType<T>,
    data: &str,
) -> Result<HashSet<T>, anyhow::Error>
where
    P: AsRef<Path>,
    T: Net + Display + Hash + Send + 'static,
{
    match parser {
        ParserType::Domains(ref p) => {
            let domains = p.parse(&data)?;
            resolve_domains(&path, &domains)
                .await
                .with_context(|| format!("{}: failed to resolve domains", path.as_ref().display()))
        }
        ParserType::Ranges(ref p) => p.parse(&data).map_err(|e| e.into()),
    }
}

async fn download_resource(
    path: impl AsRef<Path>,
    name: &str,
    res: &RemoteResource,
) -> Result<String, anyhow::Error> {
    let path = path.as_ref().join(name);
    let now = SystemTime::now();
    let last = last_download_time(&path).await.ok();
    if !time_to_download(now, res.check_interval, last) {
        info!("{}: too early to download", name);
        let res = fs::read_to_string(&path).await;
        if let Ok(s) = res {
            return Ok(s);
        }
        let err = res.unwrap_err();
        warn!("{}: downloading anyway due to read error: {}", name, err,);
    }
    loop {
        match get(&res.url, last).await {
            Ok((StatusCode::OK, body)) => {
                info!("{}: downloaded", name);
                safe_write(&path, body.as_bytes())
                    .await
                    .with_context(|| format!("failed to write to '{}'", path.display()))?;
                return Ok(body);
            }
            Ok((StatusCode::NOT_MODIFIED, _body)) => {
                info!("{}: not modified", name);
                let res = fs::read_to_string(&path).await;
                if let Ok(s) = res {
                    return Ok(s);
                }
                let err = res.unwrap_err();
                warn!("{}: downloading anyway due to read error: {}", name, err);
                continue;
            }
            Ok((status, _body)) => {
                warn!("{}: unexpected response status {}", name, status);
                return fs::read_to_string(&path)
                    .await
                    .with_context(|| format!("{}: failed to read file", name));
            }
            Err(e) => {
                error!("failed to download '{}': {}", res.url, e);
                if let Err(e) = touch(&path).await {
                    warn!("failed to touch '{}': {}", path.display(), e);
                }
                return Err(e.into());
            }
        }
    }
}

async fn last_download_time(path: impl AsRef<Path>) -> Result<SystemTime, io::Error> {
    let meta = fs::metadata(path).await?;
    meta.modified()
}

async fn touch(path: impl AsRef<Path>) -> Result<(), io::Error> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .open(path.as_ref())
        .await?;
    Ok(())
}

fn time_to_download(now: SystemTime, interval: Duration, last: Option<SystemTime>) -> bool {
    if let Some(then) = last {
        let dur = now.duration_since(then).expect("clock went backwards");
        return dur >= interval;
    }
    true
}

async fn get(url: &Url, last: Option<SystemTime>) -> reqwest::Result<(StatusCode, String)> {
    let mut req = Client::new().get(url.as_str());
    if let Some(time) = last {
        let datetime = DateTime::<Utc>::from(time);
        let value = datetime.format("%a, %d %b %G %H:%M:%S GMT").to_string();
        req = req.header(IF_MODIFIED_SINCE, value);
    }
    let res = req.send().await?;
    let status = res.status();
    let body = res.text().await?;
    Ok((status, body))
}

async fn resolve_domains<P, T>(
    path: P,
    domains: &HashSet<Domain>,
) -> Result<HashSet<T>, anyhow::Error>
where
    P: AsRef<Path>,
    T: Net + Display + Hash + Send + 'static,
{
    let path = path.as_ref().join(RESOLVED_DIR);
    fs::create_dir_all(&path)
        .await
        .with_context(|| format!("failed to create resolved directory '{}'", path.display()))?;

    let (tx, mut rx) = mpsc::unbounded_channel();

    let resolver = {
        use trust_dns_resolver::system_conf::read_system_conf;
        let (config, mut opts) = read_system_conf()?;
        opts.ip_strategy = T::lookup_strategy();
        AsyncResolver::tokio(config, opts)?
    };

    for domain in domains {
        let path = path.clone();
        let resolver = resolver.clone();
        let domain = domain.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let res = match resolver.lookup_ip(domain.as_str()).await {
                Ok(lookup) => {
                    let addrs = lookup.iter().filter_map(T::from_ip_addr).collect();
                    debug!("{}: {:?}", domain, addrs);
                    Ok((domain.clone(), addrs))
                }
                Err(e) => {
                    if let ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                        Ok((domain.clone(), HashSet::new()))
                    } else {
                        warn!(
                            "dns lookup failed for '{}': {}; reading resolved addresses from previous run",
                            domain, e
                        );
                        load_resolved(&path, &domain)
                            .await
                            .map(|addrs| (domain.clone(), addrs))
                    }
                }
            };
            tx.send(res).expect("failed to send host lookup result");
        });
    }

    let num_domains = domains.len();
    let mut resolved = HashSet::new();

    use std::fmt::Write;

    for _ in 0..num_domains {
        let (domain, addrs) = rx
            .recv()
            .await
            .expect("receive resolved addresses failed")
            .context("host lookup failed")?;
        let path = resolved_domain_path(&path, &domain, T::protocol());
        let mut data = String::new();
        for addr in addrs {
            resolved.insert(addr);
            write!(&mut data, "{}\n", addr)?;
        }
        safe_write(&path, data.as_bytes()).await?;
    }

    Ok(resolved)
}

fn resolved_domain_path<P>(base: P, domain: &Domain, proto: &str) -> PathBuf
where
    P: AsRef<Path>,
{
    let mut path = base.as_ref().join(domain.as_str());
    path.set_extension(proto);
    path
}

async fn load_resolved<P, T>(path: P, domain: &Domain) -> Result<HashSet<T>, anyhow::Error>
where
    P: AsRef<Path>,
    T: Net + Hash,
{
    let path = resolved_domain_path(path, domain, T::protocol());

    let data = match fs::read_to_string(path).await {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(e.into()),
    };

    let mut addrs = HashSet::new();

    for line in data.lines() {
        let addr = line
            .parse()
            .map_err(|e| ParseError::from(e))
            .with_context(|| format!("failed to parse ip address from '{}'", line))?;
        addrs.insert(addr);
    }

    Ok(addrs)
}

fn remove_lower_priority_ranges<T>(higher: &IpRange<T>, lower: &ClassRanges<T>) -> ClassRanges<T>
where
    T: IpNet + Default,
{
    lower
        .iter()
        .map(|(k, r)| (k.clone(), range_sub(r, higher)))
        .collect()
}

fn merge_class_ranges<T: IpNet>(cr: &ClassRanges<T>) -> IpRange<T> {
    cr.iter().fold(IpRange::new(), |rs, (_, r)| rs.merge(&r))
}

// Ensure no network is associated to more than one class.
fn validate_class_ranges_dont_intersect<N>(m: &ClassRanges<N>) -> Result<(), ConfigError>
where
    N: IpNet + Display,
{
    for (c1, r1) in m {
        for (c2, r2) in m {
            if c1 == c2 {
                // we don't care if the ranges are of the same class.
                continue;
            }
            // Here we've found two ranges of the same kind belonging to different classes.
            // If there's a non-empty intersection between them, it's a configuration error.
            let intersection: Vec<_> = r1.intersect(r2).iter().map(|n| n.to_string()).collect();
            if intersection.len() == 0 {
                continue;
            }
            let e = ClassIntersectionError {
                classes: (c1.to_string(), c2.to_string()),
                intersection,
            };
            return Err(ConfigError::ClassIntersection(e));
        }
    }
    Ok(())
}

fn setup_logger(level: &Level) {
    use env_logger::{Builder, Target, WriteStyle};

    let mut builder = Builder::new();
    builder.target(Target::Stdout);
    builder.write_style(WriteStyle::Auto);
    builder.filter_module("drib", level.to_level_filter());

    builder.init();
}

fn range_sub<N>(r1: &IpRange<N>, r2: &IpRange<N>) -> IpRange<N>
where
    N: IpNet + Default,
{
    // exclude returns a range with 0.0.0.0/0 or ::/0
    // if both ranges are equal, so override this here
    // with an empty range.
    let sub = r1.exclude(r2);
    if sub.contains(&N::default()) {
        return IpRange::new();
    }
    sub
}

#[cfg(test)]
#[macro_use]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::convert::TryFrom;
    use std::fmt::Debug;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::sync::Arc;

    use hyper::{
        service::{make_service_fn, service_fn},
        Body, Request, Response, Server,
    };
    use ipnet::{AddrParseError, Ipv4Net, Ipv6Net};
    use log::Level;
    use rand::Rng;
    use serde::Deserialize;
    use tempdir::TempDir;
    use tokio::{
        fs::File,
        io::AsyncWriteExt,
        sync::{
            oneshot::{self, Sender},
            RwLock,
        },
        task,
    };

    use drib::config::*;
    use drib::parser::*;

    use super::*;

    #[tokio::test]
    async fn test_empty_config() {
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let config = test_config(tmp.path()).await;

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert!(diff.ipv4_remove.is_empty());
        assert!(diff.ipv4_insert.is_empty());
        assert!(diff.ipv6_remove.is_empty());
        assert!(diff.ipv6_insert.is_empty());
    }

    #[tokio::test]
    async fn test_manual_blacklists() {
        let tmp = TempDir::new("drib").expect("tempdir failed");

        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Range("1.2.3.4/32".parse().unwrap()),
                        class: "1".to_string(),
                    },
                )]),
            },
        );

        config.ipv6.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Range("abcd::1/128".parse().unwrap()),
                        class: "1".to_string(),
                    },
                )]),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.2.3.4/32", "1", 10)]), diff.ipv4_insert);
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(netvec(&[("abcd::1/128", "1", 10)]), diff.ipv6_insert);
        assert!(diff.ipv6_remove.is_empty());
    }

    #[tokio::test]
    async fn test_manual_whitelists_with_empty_blacklists() {
        let tmp = TempDir::new("drib").expect("tempdir failed");

        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "whitelist".to_string(),
            Group {
                priority: 20,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Range("1.2.3.4/32".parse().unwrap()),
                        class: "1".to_string(),
                    },
                )]),
            },
        );

        config.ipv6.insert(
            "whitelist".to_string(),
            Group {
                priority: 20,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Range("abcd::1/128".parse().unwrap()),
                        class: "1".to_string(),
                    },
                )]),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.2.3.4/32", "1", 20)]), diff.ipv4_insert);
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(netvec(&[("abcd::1/128", "1", 20)]), diff.ipv6_insert);
        assert!(diff.ipv6_remove.is_empty());
    }

    #[tokio::test]
    async fn test_manual_whitelists_removes_networks_from_blacklists() {
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "whitelist".to_string(),
            Group {
                priority: 20,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "1".to_string(),
                        Feed {
                            source: Source::Range("10.0.0.0/25".parse().unwrap()),
                            class: "2".to_string(),
                        },
                    ),
                    (
                        "2".to_string(),
                        Feed {
                            source: Source::Range("10.1.1.1/32".parse().unwrap()),
                            class: "2".to_string(),
                        },
                    ),
                ]),
            },
        );

        config.ipv4.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "1".to_string(),
                        Feed {
                            source: Source::Range("10.0.0.0/24".parse().unwrap()),
                            class: "1".to_string(),
                        },
                    ),
                    (
                        "2".to_string(),
                        Feed {
                            source: Source::Range("10.1.1.1/32".parse().unwrap()),
                            class: "1".to_string(),
                        },
                    ),
                ]),
            },
        );

        config.ipv6.insert(
            "whitelist".to_string(),
            Group {
                priority: 20,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "1".to_string(),
                        Feed {
                            source: Source::Range("aaaa::/17".parse().unwrap()),
                            class: "2".to_string(),
                        },
                    ),
                    (
                        "2".to_string(),
                        Feed {
                            source: Source::Range("abcd::1/128".parse().unwrap()),
                            class: "2".to_string(),
                        },
                    ),
                ]),
            },
        );

        config.ipv6.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "1".to_string(),
                        Feed {
                            source: Source::Range("aaaa::/16".parse().unwrap()),
                            class: "1".to_string(),
                        },
                    ),
                    (
                        "2".to_string(),
                        Feed {
                            source: Source::Range("abcd::1/128".parse().unwrap()),
                            class: "1".to_string(),
                        },
                    ),
                ]),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[
                ("10.0.0.0/25", "2", 20),
                ("10.1.1.1/32", "2", 20),
                ("10.0.0.128/25", "1", 10),
            ]),
            diff.ipv4_insert
        );
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(
            netvec(&[
                ("aaaa::/17", "2", 20),
                ("abcd::1/128", "2", 20),
                ("aaaa:8000::/17", "1", 10),
            ]),
            diff.ipv6_insert
        );
        assert!(diff.ipv6_remove.is_empty());
    }

    #[tokio::test]
    async fn test_feeds() {
        let mut feeds = HashMap::new();
        feeds.insert(
            "/blacklist/ipv4/1".to_string(),
            r#"
                1.2.3.4
                1.1.0.0/16
            "#
            .to_string(),
        );
        feeds.insert(
            "/whitelist/ipv4/1".to_string(),
            r#"
                1.1.0.0/17
            "#
            .to_string(),
        );
        feeds.insert(
            "/blacklist/ipv6/1".to_string(),
            r#"
                abcd::1
                aaaa::/16
            "#
            .to_string(),
        );
        feeds.insert(
            "/whitelist/ipv6/1".to_string(),
            r#"
                aaaa::/17
            "#
            .to_string(),
        );

        let (port, tx) = run_server(Arc::new(RwLock::new(feeds))).await;
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "whitelist".to_string(),
            Group {
                priority: 20,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Remote(RemoteSource {
                            resource: RemoteResource {
                                url: format!("http://localhost:{}/whitelist/ipv4/1", port)
                                    .parse()
                                    .unwrap(),
                                check_interval: Duration::from_secs(24 * 60 * 60),
                            },
                            parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                "#".to_string(),
                            ))),
                        }),
                        class: "2".to_string(),
                    },
                )]),
            },
        );

        config.ipv4.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Remote(RemoteSource {
                            resource: RemoteResource {
                                url: format!("http://localhost:{}/blacklist/ipv4/1", port)
                                    .parse()
                                    .unwrap(),
                                check_interval: Duration::from_secs(24 * 60 * 60),
                            },
                            parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                "#".to_string(),
                            ))),
                        }),
                        class: "1".to_string(),
                    },
                )]),
            },
        );

        config.ipv6.insert(
            "whitelist".to_string(),
            Group {
                priority: 20,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Remote(RemoteSource {
                            resource: RemoteResource {
                                url: format!("http://localhost:{}/whitelist/ipv6/1", port)
                                    .parse()
                                    .unwrap(),
                                check_interval: Duration::from_secs(24 * 60 * 60),
                            },
                            parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                "#".to_string(),
                            ))),
                        }),
                        class: "2".to_string(),
                    },
                )]),
            },
        );

        config.ipv6.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Remote(RemoteSource {
                            resource: RemoteResource {
                                url: format!("http://localhost:{}/blacklist/ipv6/1", port)
                                    .parse()
                                    .unwrap(),
                                check_interval: Duration::from_secs(24 * 60 * 60),
                            },
                            parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                "#".to_string(),
                            ))),
                        }),
                        class: "1".to_string(),
                    },
                )]),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[
                ("1.1.0.0/17", "2", 20),
                ("1.1.128.0/17", "1", 10),
                ("1.2.3.4/32", "1", 10),
            ]),
            diff.ipv4_insert
        );
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(
            netvec(&[
                ("aaaa::/17", "2", 20),
                ("aaaa:8000::/17", "1", 10),
                ("abcd::1/128", "1", 10),
            ]),
            diff.ipv6_insert
        );
        assert!(diff.ipv6_remove.is_empty());

        assert!(tx.send(()).is_ok());
    }

    #[tokio::test]
    async fn test_unexistent_feed_results_in_error() {
        let mut feeds = HashMap::new();
        feeds.insert("/blacklist/ipv4/1".to_string(), "1.1.1.1".to_string());
        feeds.insert("/blacklist/ipv4/2".to_string(), "1.1.1.2".to_string());

        let (port, tx) = run_server(Arc::new(RwLock::new(feeds))).await;
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "1".to_string(),
                        Feed {
                            source: Source::Remote(RemoteSource {
                                resource: RemoteResource {
                                    url: format!("http://localhost:{}/blacklist/ipv4/1", port)
                                        .parse()
                                        .unwrap(),
                                    check_interval: Duration::from_secs(24 * 60 * 60),
                                },
                                parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                    "#".to_string(),
                                ))),
                            }),
                            class: "1".to_string(),
                        },
                    ),
                    (
                        "2".to_string(),
                        Feed {
                            source: Source::Remote(RemoteSource {
                                resource: RemoteResource {
                                    url: format!("http://localhost:{}/blacklist/ipv4/2", port)
                                        .parse()
                                        .unwrap(),
                                    check_interval: Duration::from_secs(24 * 60 * 60),
                                },
                                parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                    "#".to_string(),
                                ))),
                            }),
                            class: "1".to_string(),
                        },
                    ),
                    (
                        "does-not-exist".to_string(),
                        Feed {
                            source: Source::Remote(RemoteSource {
                                resource: RemoteResource {
                                    url: format!("http://localhost:{}/does-not-exist", port)
                                        .parse()
                                        .unwrap(),
                                    check_interval: Duration::from_secs(24 * 60 * 60),
                                },
                                parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                    "#".to_string(),
                                ))),
                            }),
                            class: "1".to_string(),
                        },
                    ),
                ]),
            },
        );

        assert!(work(&config, diff_mode_with_download()).await.is_err());
        assert!(tx.send(()).is_ok());
    }

    #[tokio::test]
    async fn test_feeds_are_not_redownloaded_too_soon() {
        let mut feeds = HashMap::new();
        feeds.insert("/blacklist/ipv4/1".to_string(), "1.1.1.1".to_string());
        feeds.insert("/blacklist/ipv4/2".to_string(), "1.1.1.2".to_string());

        let (port, tx) = run_server(Arc::new(RwLock::new(feeds))).await;
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "1".to_string(),
                        Feed {
                            source: Source::Remote(RemoteSource {
                                resource: RemoteResource {
                                    url: format!("http://localhost:{}/blacklist/ipv4/1", port)
                                        .parse()
                                        .unwrap(),
                                    check_interval: Duration::from_secs(24 * 60 * 60),
                                },
                                parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                    "#".to_string(),
                                ))),
                            }),
                            class: "1".to_string(),
                        },
                    ),
                    (
                        "2".to_string(),
                        Feed {
                            source: Source::Remote(RemoteSource {
                                resource: RemoteResource {
                                    url: format!("http://localhost:{}/blacklist/ipv4/2", port)
                                        .parse()
                                        .unwrap(),
                                    check_interval: Duration::from_secs(24 * 60 * 60),
                                },
                                parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                    "#".to_string(),
                                ))),
                            }),
                            class: "1".to_string(),
                        },
                    ),
                ]),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");

        // Download again
        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert!(diff.ipv4_insert.is_empty());
        assert!(diff.ipv4_remove.is_empty());

        assert!(diff.ipv6_insert.is_empty());
        assert!(diff.ipv6_remove.is_empty());

        assert!(tx.send(()).is_ok());
    }

    #[tokio::test]
    async fn test_feed_updates_are_handled_correctly() {
        let feeds = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut feeds = feeds.write().await;
            feeds.insert("/blacklist/ipv4/1".to_string(), "1.1.1.1".to_string());
            feeds.insert("/blacklist/ipv4/2".to_string(), "1.1.2.2".to_string());
        }

        let (port, tx) = run_server(feeds.clone()).await;
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "1".to_string(),
                        Feed {
                            source: Source::Remote(RemoteSource {
                                resource: RemoteResource {
                                    url: format!("http://localhost:{}/blacklist/ipv4/1", port)
                                        .parse()
                                        .unwrap(),
                                    check_interval: Duration::from_secs(0),
                                },
                                parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                    "#".to_string(),
                                ))),
                            }),
                            class: "1".to_string(),
                        },
                    ),
                    (
                        "2".to_string(),
                        Feed {
                            source: Source::Remote(RemoteSource {
                                resource: RemoteResource {
                                    url: format!("http://localhost:{}/blacklist/ipv4/2", port)
                                        .parse()
                                        .unwrap(),
                                    check_interval: Duration::from_secs(0),
                                },
                                parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                    "#".to_string(),
                                ))),
                            }),
                            class: "1".to_string(),
                        },
                    ),
                ]),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[("1.1.1.1/32", "1", 10), ("1.1.2.2/32", "1", 10)]),
            diff.ipv4_insert
        );
        assert!(diff.ipv4_remove.is_empty());

        // Edit feed 1
        {
            let mut feeds = feeds.write().await;
            feeds.insert("/blacklist/ipv4/1".to_string(), "1.1.1.2".to_string());
        }

        // Download again
        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.1.1.2/32", "1", 10)]), diff.ipv4_insert);
        assert_eq!(netvec(&[("1.1.1.1/32", "1", 10)]), diff.ipv4_remove);

        assert!(diff.ipv6_insert.is_empty());
        assert!(diff.ipv6_remove.is_empty());

        assert!(tx.send(()).is_ok());
    }

    #[tokio::test]
    async fn test_whitelisted_subrange_is_removed_from_blacklisted_range() {
        let feeds = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut feeds = feeds.write().await;
            feeds.insert("/whitelist/ipv4/1".to_string(), "".to_string());
            feeds.insert("/blacklist/ipv4/1".to_string(), "10.0.0.0/24".to_string());
        }

        let (port, tx) = run_server(feeds.clone()).await;
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "whitelist".to_string(),
            Group {
                priority: 20,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Remote(RemoteSource {
                            resource: RemoteResource {
                                url: format!("http://localhost:{}/whitelist/ipv4/1", port)
                                    .parse()
                                    .unwrap(),
                                check_interval: Duration::from_secs(0),
                            },
                            parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                "#".to_string(),
                            ))),
                        }),
                        class: "2".to_string(),
                    },
                )]),
            },
        );

        config.ipv4.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Remote(RemoteSource {
                            resource: RemoteResource {
                                url: format!("http://localhost:{}/blacklist/ipv4/1", port)
                                    .parse()
                                    .unwrap(),
                                check_interval: Duration::from_secs(0),
                            },
                            parser: ParserType::Ranges(Parser::OnePerLine(OnePerLine::new(
                                "#".to_string(),
                            ))),
                        }),
                        class: "1".to_string(),
                    },
                )]),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("10.0.0.0/24", "1", 10)]), diff.ipv4_insert);
        assert!(diff.ipv4_remove.is_empty());

        // Add a subnetwork of the blacklisted network in the whitelist
        {
            let mut feeds = feeds.write().await;
            feeds.insert("/whitelist/ipv4/1".to_string(), "10.0.0.0/25".to_string());
        }

        // Download again
        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[("10.0.0.0/25", "2", 20), ("10.0.0.128/25", "1", 10)]),
            diff.ipv4_insert
        );
        assert_eq!(netvec(&[("10.0.0.0/24", "1", 10)]), diff.ipv4_remove);

        assert!(diff.ipv6_insert.is_empty());
        assert!(diff.ipv6_remove.is_empty());

        assert!(tx.send(()).is_ok());
    }

    #[tokio::test]
    async fn test_old_class_is_removed_and_new_class_is_inserted_on_class_changes() {
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Range("1.2.3.4/32".parse().unwrap()),
                        class: "1".to_string(),
                    },
                )]),
            },
        );

        config.ipv6.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Range("abcd::1/128".parse().unwrap()),
                        class: "1".to_string(),
                    },
                )]),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.2.3.4/32", "1", 10)]), diff.ipv4_insert);
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(netvec(&[("abcd::1/128", "1", 10)]), diff.ipv6_insert);
        assert!(diff.ipv6_remove.is_empty());

        // change the feeds' classes

        let ipv4_blacklist_group = config.ipv4.get_mut("blacklist").unwrap();
        ipv4_blacklist_group.feeds.insert(
            "1".to_string(),
            Feed {
                source: Source::Range("1.2.3.4/32".parse().unwrap()),
                class: "2".to_string(),
            },
        );

        let ipv6_blacklist_group = config.ipv6.get_mut("blacklist").unwrap();
        ipv6_blacklist_group.feeds.insert(
            "1".to_string(),
            Feed {
                source: Source::Range("abcd::1/128".parse().unwrap()),
                class: "2".to_string(),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.2.3.4/32", "2", 10)]), diff.ipv4_insert);
        assert_eq!(netvec(&[("1.2.3.4/32", "1", 10)]), diff.ipv4_remove);

        assert_eq!(netvec(&[("abcd::1/128", "2", 10)]), diff.ipv6_insert);
        assert_eq!(netvec(&[("abcd::1/128", "1", 10)]), diff.ipv6_remove);
    }

    #[tokio::test]
    async fn domain_lists_are_resolved_correctly() {
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "whitelist".to_string(),
            Group {
                priority: 20,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Domain(Domain::try_from("dns.google".to_string()).unwrap()),
                        class: "2".to_string(),
                    },
                )]),
            },
        );

        config.ipv4.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "quad-eight".to_string(),
                        Feed {
                            source: Source::Range("8.8.8.8/32".parse().unwrap()),
                            class: "1".to_string(),
                        },
                    ),
                    (
                        "eight-eith-four-four".to_string(),
                        Feed {
                            source: Source::Range("8.8.4.4/32".parse().unwrap()),
                            class: "1".to_string(),
                        },
                    ),
                ]),
            },
        );

        config.ipv6.insert(
            "whitelist".to_string(),
            Group {
                priority: 20,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "1".to_string(),
                    Feed {
                        source: Source::Domain(Domain::try_from("dns.google".to_string()).unwrap()),
                        class: "2".to_string(),
                    },
                )]),
            },
        );

        config.ipv6.insert(
            "blacklist".to_string(),
            Group {
                priority: 10,
                kind: Some("kind".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "quad-eight".to_string(),
                        Feed {
                            source: Source::Range("2001:4860:4860::8888/128".parse().unwrap()),
                            class: "1".to_string(),
                        },
                    ),
                    (
                        "eight-eith-four-four".to_string(),
                        Feed {
                            source: Source::Range("2001:4860:4860::8844/128".parse().unwrap()),
                            class: "1".to_string(),
                        },
                    ),
                ]),
            },
        );

        work(&config, diff_mode_with_download())
            .await
            .expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[("8.8.4.4/32", "2", 20), ("8.8.8.8/32", "2", 20)]),
            diff.ipv4_insert,
        );
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(
            netvec(&[
                ("2001:4860:4860::8844/128", "2", 20),
                ("2001:4860:4860::8888/128", "2", 20),
            ]),
            diff.ipv6_insert,
        );
        assert!(diff.ipv6_remove.is_empty());
    }

    #[tokio::test]
    async fn test_overlapping_ranges_in_same_group_with_different_classes_are_detected() {
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "whitelist1".to_string(),
            Group {
                priority: 10,
                kind: Some("foo".to_string()),
                feeds: HashMap::from_iter(vec![
                    (
                        "1".to_string(),
                        Feed {
                            source: Source::Range("10.0.0.0/23".parse().unwrap()),
                            class: "1".to_string(),
                        },
                    ),
                    (
                        "2".to_string(),
                        Feed {
                            source: Source::Range("10.0.0.0/24".parse().unwrap()),
                            class: "2".to_string(),
                        },
                    ),
                ]),
            },
        );

        config.ipv4.insert(
            "whitelist2".to_string(),
            Group {
                priority: 20,
                kind: Some("bar".to_string()),
                feeds: HashMap::from_iter(vec![(
                    "3".to_string(),
                    Feed {
                        source: Source::Range("10.0.0.0/24".parse().unwrap()),
                        class: "3".to_string(),
                    },
                )]),
            },
        );

        match work(&config, diff_mode_with_download()).await {
            Err(err) => match err.root_cause().downcast_ref::<ClassIntersectionError>() {
                Some(e) => {
                    let mut classes = vec![e.classes.0.clone(), e.classes.1.clone()];
                    classes.sort();
                    assert_eq!(vec!["1", "2"], classes);
                    assert_eq!(vec!["10.0.0.0/24"], e.intersection);
                }
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    async fn run_server(feeds: Arc<RwLock<HashMap<String, String>>>) -> (u16, Sender<()>) {
        let mut rng = rand::thread_rng();
        let port = rng.gen_range(1024..=65535);
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let make_svc = make_service_fn(move |_conn| {
            let feeds = feeds.clone();
            async move {
                let feeds = feeds.clone();
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let feeds = feeds.clone();
                    async move {
                        let feeds = feeds.read().await;
                        let path = req.uri().path();
                        let resp = if let Some(data) = feeds.get(path) {
                            Response::new(Body::from(data.to_owned()))
                        } else {
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::from("not found"))
                                .unwrap()
                        };
                        Ok::<_, Infallible>(resp)
                    }
                }))
            }
        });
        let (tx, rx) = oneshot::channel::<()>();
        let server = Server::bind(&addr).serve(make_svc);
        let graceful = server.with_graceful_shutdown(async {
            rx.await.ok();
        });
        task::spawn(async move { assert!(graceful.await.is_ok()) });
        (port, tx)
    }

    async fn test_config(path: impl AsRef<Path>) -> Config {
        let path = path.as_ref();
        let template_path = path.join("diff.tpl");
        let template = r#"
ipv4_remove: [
{%- for entry in ipv4.remove %}
  {
    order: -{{entry.priority}},
    priority: {{entry.priority}},
    kind: "{{entry.kind}}",
    class: "{{entry.class}}",
    protocol: "ipv4",
    range: "{{entry.range}}",
  },
{%- endfor %}
]

ipv4_insert: [
{%- for entry in ipv4.insert %}
  {
    order: -{{entry.priority}},
    priority: {{entry.priority}},
    kind: "{{entry.kind}}",
    class: "{{entry.class}}",
    protocol: "ipv4",
    range: "{{entry.range}}",
  },
{%- endfor %}
]

ipv6_remove: [
{%- for entry in ipv6.remove %}
  {
    order: -{{entry.priority}},
    priority: {{entry.priority}},
    kind: "{{entry.kind}}",
    class: "{{entry.class}}",
    protocol: "ipv6",
    range: "{{entry.range}}",
  },
{%- endfor %}
]

ipv6_insert: [
{%- for entry in ipv6.insert %}
  {
    order: -{{entry.priority}},
    priority: {{entry.priority}},
    kind: "{{entry.kind}}",
    class: "{{entry.class}}",
    protocol: "ipv6",
    range: "{{entry.range}}",
  },
{%- endfor %}
]"#;

        let mut file = File::create(&template_path)
            .await
            .expect("failed to create test template");
        file.write_all(&template.as_bytes())
            .await
            .expect("failed to write to test template");
        drop(file);

        Config {
            state_dir: PathBuf::from(path),
            log_level: Level::Error,
            worker_threads: None,

            bootstrap: None,
            diff: Some(ChunkedTemplates {
                templates: Templates {
                    input: PathBuf::from(&template_path),
                    output: format!("{}/diff.out", path.display()),
                },
                max_ranges_per_file: None,
            }),

            downloads: HashMap::new(),
            ipv4: HashMap::new(),
            ipv6: HashMap::new(),
        }
    }

    fn netvec<'a, T: Net>(nets: &[(&str, &str, u16)]) -> Vec<Entry<T>>
    where
        T: Debug + Ord + FromStr<Err = AddrParseError>,
    {
        let mut vec = Vec::with_capacity(nets.len());
        let protocol = T::protocol();
        for (net, class, priority) in nets {
            let range = net.parse::<T>().unwrap();
            let entry = Entry::new(
                *priority,
                Some("kind".to_string()),
                class.to_string(),
                protocol.to_string(),
                range,
            );
            vec.push(entry);
        }
        vec.sort();
        vec
    }

    #[derive(Debug, Deserialize)]
    struct RenderedDiff {
        ipv4_remove: Vec<Entry<Ipv4Net>>,
        ipv4_insert: Vec<Entry<Ipv4Net>>,
        ipv6_remove: Vec<Entry<Ipv6Net>>,
        ipv6_insert: Vec<Entry<Ipv6Net>>,
    }

    async fn parse_diff(config: &Config) -> Result<RenderedDiff, anyhow::Error> {
        let data = fs::read_to_string(&config.diff.as_ref().unwrap().templates.output).await?;
        let diff = serde_yaml::from_str(&data)?;
        Ok(diff)
    }

    fn diff_mode_with_download() -> Mode {
        Mode::Diff(NoDownload { no_download: false })
    }
}
