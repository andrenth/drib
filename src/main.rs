use std::cmp::max;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Display;
use std::hash::Hash;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::str;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use chrono::{DateTime, Utc};
use clap::{crate_name, crate_version, Clap};
use iprange::{IpNet, IpRange};
use lazy_static::lazy_static;
use log::Level;
use log::{debug, error, info, warn};
use regex::Regex;
use reqwest::{header::IF_MODIFIED_SINCE, Client, StatusCode};
use serde::Serialize;
use tinytemplate::TinyTemplate;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{self, AsyncWriteExt};
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::AsyncResolver;
use url::Url;

use drib::config::{
    ChunkedTemplates, Config, Downloads, Feed, Feeds, Groups, ParserType, RemoteResource, Source,
    Templates,
};
use drib::error::ClassError;
use drib::output::{Aggregate, Bootstrap, Changes, Diff, Entry};
use drib::parser::{Domain, Net, Parse, ParseError};

const DOWNLOAD_DIR: &'static str = "downloads";
const IPV4_DIR: &'static str = "ipv4";
const IPV6_DIR: &'static str = "ipv6";
const RESOLVED_DIR: &'static str = "resolved";
const AGGREGATE_FILE: &'static str = "aggregate";

type ClassRanges<T> = HashMap<String, IpRange<T>>;

#[derive(Debug, Clap)]
#[clap(name = crate_name!(), version = crate_version!())]
struct Opts {
    #[clap(
        short,
        long,
        name = "FILE",
        default_value = "/etc/drib/drib.conf",
        parse(from_os_str)
    )]
    config: PathBuf,
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Debug, Copy, Clone, Clap)]
enum Mode {
    #[clap(about = "Bootstrap mode")]
    Bootstrap,
    #[clap(about = "Diff mode")]
    Diff,
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

    let mut rt = Builder::new();
    match (config.core_threads, config.max_threads) {
        (Some(1), Some(1)) => {
            rt.basic_scheduler();
        }
        (Some(n), Some(m)) if n > m => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "max_core_threads can't be greater than max_threads",
            )
            .into());
        }
        (Some(n), Some(m)) => {
            rt.threaded_scheduler();
            rt.core_threads(n);
            rt.max_threads(m);
        }
        (Some(n), None) => {
            rt.threaded_scheduler();
            rt.core_threads(n);
        }
        (None, Some(m)) => {
            let n = num_cpus::get();
            if n > m {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "max_core_threads default is larger than max_threads",
                )
                .into());
            }
            rt.threaded_scheduler();
            rt.max_threads(m);
        }
        (None, None) => {
            rt.threaded_scheduler();
        }
    }
    rt.enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(work(&config, opts.mode))
}

fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, anyhow::Error> {
    let path = path.as_ref();
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;
    let config: Config = serde_yaml::from_str(&data).context("configuration deserialize failed")?;
    Ok(config)
}

async fn work(config: &Config, mode: Mode) -> Result<(), anyhow::Error> {
    let path = &config.state_dir;
    fs::create_dir_all(path)
        .await
        .with_context(|| format!("failed to create protocol path '{}'", path.display()))?;

    let download_path = path.join(DOWNLOAD_DIR);
    download(&download_path, &config.downloads).await?;

    let ipv4_path = path.join(IPV4_DIR);
    let ipv6_path = path.join(IPV6_DIR);

    let new_ipv4_aggregate = fetch_aggregate(&ipv4_path, &download_path, &config.ipv4).await?;
    let new_ipv6_aggregate = fetch_aggregate(&ipv6_path, &download_path, &config.ipv6).await?;

    match mode {
        Mode::Bootstrap => {
            let bootstrap = Bootstrap::new(&new_ipv4_aggregate, &new_ipv6_aggregate);
            render_bootstrap(&bootstrap, &config.bootstrap).await?;
        }
        Mode::Diff => {
            let cur_ipv4_aggregate = load_aggregate(&ipv4_path).await?;
            let cur_ipv6_aggregate = load_aggregate(&ipv6_path).await?;

            save_aggregate(&ipv4_path.join(AGGREGATE_FILE), &new_ipv4_aggregate).await?;
            save_aggregate(&ipv6_path.join(AGGREGATE_FILE), &new_ipv6_aggregate).await?;

            let ipv4_insert = &new_ipv4_aggregate - &cur_ipv4_aggregate;
            let ipv6_insert = &new_ipv6_aggregate - &cur_ipv6_aggregate;

            let ipv4_remove = &cur_ipv4_aggregate - &new_ipv4_aggregate;
            let ipv6_remove = &cur_ipv6_aggregate - &new_ipv6_aggregate;

            let diff = Diff {
                ipv4: Changes::from_aggregates(&ipv4_insert, &ipv4_remove),
                ipv6: Changes::from_aggregates(&ipv6_insert, &ipv6_remove),
            };
            render_diff(diff, &config.diff).await?;
        }
    }

    Ok(())
}

async fn download<P: AsRef<Path>>(path: P, downloads: &Downloads) -> Result<(), anyhow::Error> {
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

#[derive(Serialize)]
struct Wrap<'a, T: Ord> {
    ranges: &'a BTreeSet<&'a Entry<T>>,
}

async fn render_bootstrap<'a>(
    bootstrap: &Bootstrap<'a>,
    config: &Templates,
) -> Result<(), anyhow::Error> {
    info!("ipv4: +{}", bootstrap.ipv4_len());
    info!("ipv6: +{}", bootstrap.ipv6_len());
    for (kind, ranges) in &bootstrap.ipv4 {
        let w = Wrap { ranges };
        render_aggregate(&config, &kind, "ipv4", &w)
            .await
            .context("failed to render ipv4 ranges")?;
    }
    for (kind, ranges) in &bootstrap.ipv6 {
        let w = Wrap { ranges };
        render_aggregate(&config, &kind, "ipv6", &w)
            .await
            .context("failed to render ipv4 ranges")?;
    }
    Ok(())
}

async fn render_aggregate<'a, T>(
    templates: &Templates,
    kind: &Option<String>,
    proto: &str,
    aggregate: &Wrap<'a, T>,
) -> Result<(), anyhow::Error>
where
    T: IpNet + Hash + Serialize,
{
    let kind = kind.as_deref().unwrap_or("");
    let input = &templates.input;
    let output = PathBuf::from(
        templates
            .output
            .replace("{proto}", proto)
            .replace("{kind}", kind),
    );
    render(input, &output, &aggregate).await.with_context(|| {
        format!(
            "failed to render {} bootstrap from '{}' into '{}' (kind '{}')",
            proto,
            input.display(),
            output.display(),
            kind
        )
    })?;
    Ok(())
}

async fn render_diff<'a>(diff: Diff<'a>, config: &ChunkedTemplates) -> Result<(), anyhow::Error> {
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

    let size = config.max_ranges_per_file.unwrap_or(diff.len());

    if size == 0 {
        let input = &config.templates.input;
        let output = PathBuf::from(config.templates.output.replace("{i}", "0"));
        let diff = Diff::empty();
        render(input, &output, &diff).await.with_context(|| {
            format!(
                "failed to render diff from '{}' into '{}' (chunk {})",
                input.display(),
                output.display(),
                0
            )
        })?;
        return Ok(());
    }

    for (i, chunk) in diff.chunks(size).enumerate() {
        let input = &config.templates.input;
        let output = chunk_path(&config.templates.output, i);
        render(input, &output, &chunk).await.with_context(|| {
            format!(
                "failed to render diff from '{}' into '{}' (chunk {})",
                input.display(),
                output.display(),
                i
            )
        })?;
    }

    Ok(())
}

fn chunk_path(output: &str, i: usize) -> PathBuf {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"(\{(\d)*i\})"#).unwrap();
    }
    let path = RE.replace_all(output, |cap: &regex::Captures| -> String {
        let num_zeros: usize = cap.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));
        let s = i.to_string();
        let n = num_zeros.saturating_sub(s.len());
        let mut path = "0".repeat(max(0, n));
        path.push_str(&s);
        path
    });
    PathBuf::from(path.to_string())
}

async fn render<P, T>(template: P, output: P, data: &T) -> Result<(), anyhow::Error>
where
    P: AsRef<Path>,
    T: Serialize,
{
    let template = fs::read_to_string(&template).await.with_context(|| {
        format!(
            "failed to read template file '{}'",
            template.as_ref().display()
        )
    })?;

    let mut tt = TinyTemplate::new();
    tt.add_template("output", &template)
        .context("failed to add template")?;

    let res = tt
        .render("output", data)
        .context("failed to render output")?;
    safe_write(&output, res.as_bytes()).await.with_context(|| {
        format!(
            "failed to write rendered file '{}'",
            output.as_ref().display()
        )
    })?;
    Ok(())
}

async fn fetch_aggregate<P, T>(
    path: P,
    download_path: P,
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

    let groups = fetch_groups(&path, &download_path, groups).await?;

    let mut res = Aggregate::new();
    let mut acc = IpRange::new();

    let is_ipv4 = T::version() == 4;
    let is_ipv6 = T::version() == 6;

    // The `groups` map is sorted by descending priority. For each
    // group, we remove every range that appears in higher priority
    // groups. Its own ranges are then merged with the higher priority
    // ones, to be removed from the next iteration's group.
    for ((priority, kind), class_ranges) in groups {
        let filtered = remove_higher_priority_ranges(&class_ranges, &acc);

        for (class, ranges) in filtered {
            for range in &ranges {
                let kind = kind.map(|k| k.to_owned());
                let class = class.to_owned();
                let entry = Entry {
                    priority,
                    kind,
                    class,
                    range,
                    is_ipv4,
                    is_ipv6,
                };
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
    download_path: P,
    groups: &Groups<T>,
) -> Result<BTreeMap<(usize, Option<&str>), ClassRanges<T>>, anyhow::Error>
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
        let class_ranges = fetch_feed_ranges(&path, &download_path, &group.feeds).await?;
        res.insert((group.priority, group.kind.as_deref()), class_ranges);
    }

    Ok(res)
}

async fn fetch_feed_ranges<P1, P2, T>(
    path: P1,
    download_path: P2,
    feeds: &Feeds<T>,
) -> Result<ClassRanges<T>, anyhow::Error>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
    T: Parse + Net + Eq + Hash + Display + Send + Sync + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel();

    for (name, feed) in feeds {
        let path = PathBuf::from(path.as_ref());
        let download_path = PathBuf::from(download_path.as_ref());
        let name = name.clone();
        let feed = feed.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let res = fetch_feed(&path, &download_path, &name, &feed).await;
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

async fn fetch_feed<P1, P2, T>(
    path: P1,
    download_path: P2,
    name: &str,
    feed: &Feed<T>,
) -> Result<HashSet<T>, anyhow::Error>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
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
            let path = download_path.as_ref().join(&src.name);
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

async fn download_resource<P: AsRef<Path>>(
    path: P,
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

async fn last_download_time<P: AsRef<Path>>(path: P) -> Result<SystemTime, io::Error> {
    let meta = fs::metadata(path).await?;
    meta.modified()
}

async fn touch<P: AsRef<Path>>(path: P) -> Result<(), io::Error> {
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
        AsyncResolver::tokio(config, opts).await?
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
        let path = resolved_domain_path(&path, &domain, T::version());
        let mut data = String::new();
        for addr in addrs {
            resolved.insert(addr);
            write!(&mut data, "{}\n", addr)?;
        }
        safe_write(&path, data.as_bytes()).await?;
    }

    Ok(resolved)
}

fn resolved_domain_path<P>(base: P, domain: &Domain, version: u8) -> PathBuf
where
    P: AsRef<Path>,
{
    let mut path = base.as_ref().join(domain.as_str());
    path.set_extension(version.to_string());
    path
}

async fn load_resolved<P, T>(path: P, domain: &Domain) -> Result<HashSet<T>, anyhow::Error>
where
    P: AsRef<Path>,
    T: Net + Hash,
{
    let path = resolved_domain_path(path, domain, T::version());

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

fn remove_higher_priority_ranges<N>(lower: &ClassRanges<N>, higher: &IpRange<N>) -> ClassRanges<N>
where
    N: IpNet + Default,
{
    lower
        .iter()
        .map(|(k, r)| (k.clone(), range_sub(r, higher)))
        .collect()
}

fn merge_class_ranges<N: IpNet>(cr: &ClassRanges<N>) -> IpRange<N> {
    cr.iter().fold(IpRange::new(), |rs, (_, r)| rs.merge(&r))
}

async fn load_aggregate<P, T>(path: P) -> Result<Aggregate<T>, anyhow::Error>
where
    P: AsRef<Path>,
    T: Hash + Net,
{
    let path = path.as_ref().join(AGGREGATE_FILE);

    let data = match fs::read_to_string(&path).await {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Aggregate::new()),
        Err(e) => return Err(e.into()),
    };

    let mut aggr = Aggregate::new();

    for line in data.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        let len = parts.len();
        if len < 3 || len > 4 {
            return Err(
                ParseError(format!("malformed line: '{}' ({})", line, path.display())).into(),
            );
        }
        let range = parts[0]
            .parse()
            .map_err(|e| ParseError::from(e))
            .with_context(|| {
                format!(
                    "failed to parse network from '{}' in line '{}' ({})",
                    parts[0],
                    line,
                    path.display(),
                )
            })?;
        let priority = parts[1]
            .parse()
            .map_err(ParseError::from)
            .with_context(|| {
                format!(
                    "failed to parse priority from '{}' in line '{}' ({})",
                    parts[1],
                    line,
                    path.display(),
                )
            })?;
        let class = parts[2].to_owned();
        let kind = if len == 4 {
            Some(parts[3].to_owned())
        } else {
            None
        };
        let is_ipv4 = T::version() == 4;
        let is_ipv6 = T::version() == 6;
        let entry = Entry {
            priority,
            kind,
            class,
            range,
            is_ipv4,
            is_ipv6,
        };
        aggr.insert(entry);
    }

    Ok(aggr)
}

// Ensure no network is associated to more than one class.
fn validate_class_ranges_dont_intersect<N>(m: &ClassRanges<N>) -> Result<(), ClassError>
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
            return Err(ClassError {
                classes: (c1.to_string(), c2.to_string()),
                intersection,
            });
        }
    }
    Ok(())
}

async fn save_aggregate<P, T>(path: P, aggregate: &Aggregate<T>) -> Result<(), io::Error>
where
    P: AsRef<Path>,
    T: Ord + Display,
{
    use std::io::Write;

    let mut buf = Vec::new();
    for entry in &aggregate.ranges {
        if let Some(ref k) = entry.kind {
            write!(
                &mut buf,
                "{} {} {} {}\n",
                entry.range, entry.priority, entry.class, k
            )?;
            continue;
        }
        write!(
            &mut buf,
            "{} {} {}\n",
            entry.range, entry.priority, entry.class
        )?;
    }
    safe_write(&path, &buf).await?;
    Ok(())
}

fn setup_logger(level: &Level) {
    use env_logger::{Builder, Target, WriteStyle};

    let mut builder = Builder::new();
    builder.target(Target::Stdout);
    builder.write_style(WriteStyle::Auto);
    builder.filter_module("main", level.to_level_filter());

    builder.init()
}

async fn safe_write<P: AsRef<Path>>(path: P, buf: &[u8]) -> Result<(), io::Error> {
    let tmp = format!("{}.tmp", path.as_ref().display());

    let mut file = File::create(&tmp).await?;
    file.write_all(buf).await?;
    file.sync_all().await?;
    drop(file);

    fs::rename(&tmp, &path).await?;

    Ok(())
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

    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    use ipnet::{AddrParseError, Ipv4Net, Ipv6Net};
    use log::Level;
    use rand::Rng;
    use serde::Deserialize;
    use tempdir::TempDir;
    use tokio::sync::{
        oneshot::{self, Sender},
        RwLock,
    };
    use tokio::task;

    use drib::config::*;
    use drib::output::*;
    use drib::parser::*;

    use super::*;

    #[test]
    fn test_chunk_path() {
        assert_eq!(PathBuf::from("foo"), chunk_path("foo", 42));
        assert_eq!(PathBuf::from("foo42"), chunk_path("foo{i}", 42));
        assert_eq!(PathBuf::from("foo42"), chunk_path("foo{0i}", 42));
        assert_eq!(PathBuf::from("foo42"), chunk_path("foo{1i}", 42));
        assert_eq!(PathBuf::from("foo42"), chunk_path("foo{2i}", 42));
        assert_eq!(PathBuf::from("foo042"), chunk_path("foo{3i}", 42));
        assert_eq!(PathBuf::from("foo0042"), chunk_path("foo{4i}", 42));

        assert_eq!(PathBuf::from("foo42-42"), chunk_path("foo{i}-{i}", 42));
        assert_eq!(PathBuf::from("foo42-42"), chunk_path("foo{0i}-{0i}", 42));
        assert_eq!(PathBuf::from("foo042-0042"), chunk_path("foo{3i}-{4i}", 42));
    }

    #[tokio::test]
    async fn test_empty_config() {
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let config = test_config(tmp.path()).await;

        work(&config, Mode::Diff).await.expect("work failed");
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
                priority: 1,
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
                priority: 1,
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

        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.2.3.4/32", "1", 1)]), diff.ipv4_insert);
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(netvec(&[("abcd::1/128", "1", 1)]), diff.ipv6_insert);
        assert!(diff.ipv6_remove.is_empty());
    }

    #[tokio::test]
    async fn test_manual_whitelists_with_empty_blacklists() {
        let tmp = TempDir::new("drib").expect("tempdir failed");

        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "whitelist".to_string(),
            Group {
                priority: 1,
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
                priority: 1,
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

        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.2.3.4/32", "1", 1)]), diff.ipv4_insert);
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(netvec(&[("abcd::1/128", "1", 1)]), diff.ipv6_insert);
        assert!(diff.ipv6_remove.is_empty());
    }

    #[tokio::test]
    async fn test_manual_whitelists_removes_networks_from_blacklists() {
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "whitelist".to_string(),
            Group {
                priority: 1,
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
                priority: 2,
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
                priority: 1,
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
                priority: 2,
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

        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[
                ("10.0.0.0/25", "2", 1),
                ("10.1.1.1/32", "2", 1),
                ("10.0.0.128/25", "1", 2),
            ]),
            diff.ipv4_insert
        );
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(
            netvec(&[
                ("aaaa::/17", "2", 1),
                ("abcd::1/128", "2", 1),
                ("aaaa:8000::/17", "1", 2),
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
                priority: 1,
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
                priority: 2,
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
                priority: 1,
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
                priority: 2,
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

        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[
                ("1.1.0.0/17", "2", 1),
                ("1.1.128.0/17", "1", 2),
                ("1.2.3.4/32", "1", 2),
            ]),
            diff.ipv4_insert
        );
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(
            netvec(&[
                ("aaaa::/17", "2", 1),
                ("aaaa:8000::/17", "1", 2),
                ("abcd::1/128", "1", 2),
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
                priority: 2,
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

        assert!(work(&config, Mode::Diff).await.is_err());
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
                priority: 2,
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

        work(&config, Mode::Diff).await.expect("work failed");

        // Download again
        work(&config, Mode::Diff).await.expect("work failed");
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
                priority: 2,
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

        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[("1.1.1.1/32", "1", 2), ("1.1.2.2/32", "1", 2)]),
            diff.ipv4_insert
        );
        assert!(diff.ipv4_remove.is_empty());

        // Edit feed 1
        {
            let mut feeds = feeds.write().await;
            feeds.insert("/blacklist/ipv4/1".to_string(), "1.1.1.2".to_string());
        }

        // Download again
        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.1.1.2/32", "1", 2)]), diff.ipv4_insert);
        assert_eq!(netvec(&[("1.1.1.1/32", "1", 2)]), diff.ipv4_remove);

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
                priority: 1,
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
                priority: 2,
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

        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("10.0.0.0/24", "1", 2)]), diff.ipv4_insert);
        assert!(diff.ipv4_remove.is_empty());

        // Add a subnetwork of the blacklisted network in the whitelist
        {
            let mut feeds = feeds.write().await;
            feeds.insert("/whitelist/ipv4/1".to_string(), "10.0.0.0/25".to_string());
        }

        // Download again
        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[("10.0.0.0/25", "2", 1), ("10.0.0.128/25", "1", 2)]),
            diff.ipv4_insert
        );
        assert_eq!(netvec(&[("10.0.0.0/24", "1", 2)]), diff.ipv4_remove);

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
                priority: 2,
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
                priority: 2,
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

        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.2.3.4/32", "1", 2)]), diff.ipv4_insert);
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(netvec(&[("abcd::1/128", "1", 2)]), diff.ipv6_insert);
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

        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(netvec(&[("1.2.3.4/32", "2", 2)]), diff.ipv4_insert);
        assert_eq!(netvec(&[("1.2.3.4/32", "1", 2)]), diff.ipv4_remove);

        assert_eq!(netvec(&[("abcd::1/128", "2", 2)]), diff.ipv6_insert);
        assert_eq!(netvec(&[("abcd::1/128", "1", 2)]), diff.ipv6_remove);
    }

    #[tokio::test]
    async fn domain_lists_are_resolved_correctly() {
        let tmp = TempDir::new("drib").expect("tempdir failed");
        let mut config = test_config(tmp.path()).await;

        config.ipv4.insert(
            "whitelist".to_string(),
            Group {
                priority: 1,
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
                priority: 2,
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
                priority: 1,
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
                priority: 2,
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

        work(&config, Mode::Diff).await.expect("work failed");
        let diff = parse_diff(&config).await.expect("parse diff failed");

        assert_eq!(
            netvec(&[("8.8.4.4/32", "2", 1), ("8.8.8.8/32", "2", 1)]),
            diff.ipv4_insert,
        );
        assert!(diff.ipv4_remove.is_empty());

        assert_eq!(
            netvec(&[
                ("2001:4860:4860::8844/128", "2", 1),
                ("2001:4860:4860::8888/128", "2", 1),
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
                priority: 1,
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
                priority: 2,
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

        match work(&config, Mode::Diff).await {
            Err(err) => match err.root_cause().downcast_ref::<ClassError>() {
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
        let port = rng.gen_range(1024, 65535);
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

    async fn test_config<P: AsRef<Path>>(path: P) -> Config {
        let path = path.as_ref();
        let template_path = path.join("diff.tpl");
        let template = r#"
ipv4_remove: [
{{- for entry in ipv4.remove }}
  \{
    priority: {entry.priority},
    kind: "{entry.kind}",
    class: "{entry.class}",
    range: "{entry.range}",
    is_ipv4: true,
    is_ipv6: false,
  },
{{- endfor }}
]

ipv4_insert: [
{{- for entry in ipv4.insert }}
  \{
    priority: {entry.priority},
    kind: "{entry.kind}",
    class: "{entry.class}",
    range: "{entry.range}",
    is_ipv4: true,
    is_ipv6: false,
  },
{{- endfor }}
]

ipv6_remove: [
{{- for entry in ipv6.remove }}
  \{
    priority: {entry.priority},
    kind: "{entry.kind}",
    class: "{entry.class}",
    range: "{entry.range}",
    is_ipv4: false,
    is_ipv6: true,
  },
{{- endfor }}
]

ipv6_insert: [
{{- for entry in ipv6.insert }}
  \{
    priority: {entry.priority},
    kind: "{entry.kind}",
    class: "{entry.class}",
    range: "{entry.range}",
    is_ipv4: false,
    is_ipv6: true,
  },
{{- endfor }}
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
            core_threads: None,
            max_threads: None,

            bootstrap: Templates {
                input: PathBuf::default(),
                output: "".to_string(),
            },
            diff: ChunkedTemplates {
                templates: Templates {
                    input: PathBuf::from(&template_path),
                    output: format!("{}/diff.out", path.display()),
                },
                max_ranges_per_file: None,
            },

            downloads: HashMap::new(),
            ipv4: HashMap::new(),
            ipv6: HashMap::new(),
        }
    }

    fn netvec<'a, T: Net>(nets: &[(&str, &str, usize)]) -> Vec<Entry<T>>
    where
        T: Debug + Ord + FromStr<Err = AddrParseError>,
    {
        let mut vec = Vec::with_capacity(nets.len());
        let is_ipv4 = T::version() == 4;
        let is_ipv6 = T::version() == 6;
        for (net, class, priority) in nets {
            let range = net.parse::<T>().unwrap();
            vec.push(Entry {
                priority: *priority,
                kind: Some("kind".to_string()),
                class: class.to_string(),
                range,
                is_ipv4,
                is_ipv6,
            });
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
        let data = fs::read_to_string(&config.diff.templates.output).await?;
        let diff = serde_yaml::from_str(&data)?;
        Ok(diff)
    }
}
