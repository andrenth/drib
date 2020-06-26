use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::Hash;
use std::path::{Path, PathBuf};

use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpNet;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use tera::{self, Tera};
use tokio::fs;
use tokio::io;

use crate::aggregate::{Aggregate, Entry};
use crate::parser::Net;
use crate::util::safe_write;

#[derive(Debug, Serialize)]
pub struct Bootstrap<'a> {
    pub ipv4: BTreeMap<&'a Option<String>, BTreeSet<&'a Entry<Ipv4Net>>>,
    pub ipv6: BTreeMap<&'a Option<String>, BTreeSet<&'a Entry<Ipv6Net>>>,
}

impl<'a> Bootstrap<'a> {
    pub fn new(aggr4: &'a Aggregate<Ipv4Net>, aggr6: &'a Aggregate<Ipv6Net>) -> Bootstrap<'a> {
        let mut ipv4 = BTreeMap::new();
        for entry in aggr4 {
            let aggrs = ipv4.entry(&entry.kind).or_insert(BTreeSet::new());
            aggrs.insert(entry);
        }

        let mut ipv6 = BTreeMap::new();
        for entry in aggr6 {
            let aggrs = ipv6.entry(&entry.kind).or_insert(BTreeSet::new());
            aggrs.insert(entry);
        }

        Bootstrap { ipv4, ipv6 }
    }

    pub fn ipv4_len(&self) -> usize {
        self.ipv4.iter().fold(0, |n, (_, a)| n + a.len())
    }

    pub fn ipv6_len(&self) -> usize {
        self.ipv6.iter().fold(0, |n, (_, a)| n + a.len())
    }

    pub fn len(&self) -> usize {
        self.ipv4_len() + self.ipv6_len()
    }
}

#[derive(Debug, Serialize)]
pub struct Diff<'a> {
    pub ipv4: Changes<'a, Ipv4Net>,
    pub ipv6: Changes<'a, Ipv6Net>,
}

impl<'a> Diff<'a> {
    pub fn empty() -> Diff<'a> {
        Diff {
            ipv4: Changes::empty(),
            ipv6: Changes::empty(),
        }
    }

    pub fn ipv4(changes: Changes<'a, Ipv4Net>) -> Diff<'a> {
        Diff {
            ipv4: changes,
            ipv6: Changes::empty(),
        }
    }

    pub fn ipv6(changes: Changes<'a, Ipv6Net>) -> Diff<'a> {
        Diff {
            ipv4: Changes::empty(),
            ipv6: changes,
        }
    }

    pub fn len(&self) -> usize {
        self.ipv4.insert.len()
            + self.ipv4.remove.len()
            + self.ipv6.insert.len()
            + self.ipv6.remove.len()
    }

    pub fn chunks(&self, size: usize) -> DiffChunks {
        DiffChunks {
            ipv4: &self.ipv4,
            ipv4_chunks: None,
            ipv4_remain: self.ipv4.len(),

            ipv6: &self.ipv6,
            ipv6_chunks: None,
            ipv6_remain: self.ipv6.len(),

            size,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiffChunks<'a> {
    ipv4: &'a Changes<'a, Ipv4Net>,
    ipv4_chunks: Option<ChangesChunks<'a, Ipv4Net>>,
    ipv4_remain: usize,

    ipv6: &'a Changes<'a, Ipv6Net>,
    ipv6_chunks: Option<ChangesChunks<'a, Ipv6Net>>,
    ipv6_remain: usize,

    size: usize,
}

impl<'a> Iterator for DiffChunks<'a> {
    type Item = DiffSlice<'a>;

    fn next(&mut self) -> Option<DiffSlice<'a>> {
        if self.size == 0 {
            return None;
        }

        let mut ipv4_len = 0;
        let ipv4_chunks = match self.ipv4_chunks {
            Some(ref mut c) => c,
            None => {
                let c = self.ipv4.chunks(self.size);
                self.ipv4_chunks = Some(c);
                self.ipv4_chunks.as_mut().unwrap()
            }
        };
        let ipv4_next = ipv4_chunks.next();
        if let Some(ref s) = ipv4_next {
            ipv4_len = s.len();
            self.ipv4_remain -= ipv4_len;
        }

        if ipv4_len > 0 && ipv4_len < self.size {
            let size = self.size - ipv4_len;
            let ipv6_next = &self.ipv6.slice(0, min(self.ipv6.len(), size));
            self.ipv6_remain -= ipv6_next.len();
            return Some(DiffSlice {
                ipv4: ipv4_next.unwrap_or(ChangesSlice {
                    remove: &[],
                    insert: &[],
                }),
                ipv6: ChangesSlice {
                    remove: ipv6_next.remove,
                    insert: ipv6_next.insert,
                },
            });
        }

        let ipv6_next = if self.ipv4_remain == 0 && self.ipv6_remain > 0 {
            match self.ipv6_chunks {
                Some(ref mut c) => c.next(),
                None => {
                    let i = self.ipv6.len() - self.ipv6_remain;
                    let mut c = self.ipv6.slice_from(i).chunks(self.size);
                    let next = c.next();
                    if let Some(ref s) = next {
                        self.ipv6_remain -= s.len();
                    }
                    self.ipv6_chunks = Some(c);
                    next
                }
            }
        } else {
            None
        };

        match (ipv4_next, ipv6_next) {
            (Some(ipv4), Some(ipv6)) => Some(DiffSlice { ipv4, ipv6 }),
            (Some(ipv4), None) => Some(DiffSlice {
                ipv4,
                ipv6: ChangesSlice::empty(),
            }),
            (None, Some(ipv6)) => Some(DiffSlice {
                ipv4: ChangesSlice::empty(),
                ipv6,
            }),
            (None, None) => None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DiffSlice<'a> {
    ipv4: ChangesSlice<'a, Ipv4Net>,
    ipv6: ChangesSlice<'a, Ipv6Net>,
}

#[derive(Debug, Serialize)]
pub struct Changes<'a, T: 'a> {
    pub insert: Vec<&'a Entry<T>>,
    pub remove: Vec<&'a Entry<T>>,
}

impl<'a, T> Changes<'a, T> {
    pub fn empty() -> Changes<'a, T> {
        Changes {
            insert: Vec::new(),
            remove: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.insert.len() + self.remove.len()
    }

    pub fn chunks(&self, size: usize) -> ChangesChunks<T> {
        ChangesChunks {
            remove: &self.remove,
            remove_remain: self.remove.len(),
            remove_chunks: None,

            insert: &self.insert,
            insert_remain: self.insert.len(),
            insert_chunks: None,

            size,
        }
    }

    fn slice(&'a self, i: usize, j: usize) -> ChangesSlice<'a, T> {
        let remove_len = self.remove.len();
        let insert_len = self.insert.len();
        let total_len = remove_len + insert_len;

        if i <= remove_len && j <= remove_len {
            return ChangesSlice {
                remove: &self.remove[i..j],
                insert: &[],
            };
        }

        if i <= remove_len && j <= total_len {
            let j = j - remove_len;
            return ChangesSlice {
                remove: &self.remove[i..],
                insert: &self.insert[0..j],
            };
        }

        if i > remove_len && i <= total_len && j <= total_len {
            let i = i - remove_len;
            let j = j - remove_len;
            return ChangesSlice {
                remove: &[],
                insert: &self.insert[i..j],
            };
        }

        panic!(format!(
            "invalid bounds ({}, {}) for Changes with lengths {} and {}",
            i, j, remove_len, insert_len
        ));
    }

    fn slice_from(&'a self, i: usize) -> ChangesSlice<'a, T> {
        self.slice(i, self.len())
    }
}

impl<'a, T: Net> Changes<'a, T> {
    pub fn from_aggregates(insert: &'a Aggregate<T>, remove: &'a Aggregate<T>) -> Changes<'a, T> {
        Changes {
            insert: aggregate_to_ranges(insert),
            remove: aggregate_to_ranges(remove),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChangesChunks<'a, T> {
    remove: &'a [&'a Entry<T>],
    remove_chunks: Option<std::slice::Chunks<'a, &'a Entry<T>>>,
    remove_remain: usize,

    insert: &'a [&'a Entry<T>],
    insert_chunks: Option<std::slice::Chunks<'a, &'a Entry<T>>>,
    insert_remain: usize,

    size: usize,
}

impl<'a, T> Iterator for ChangesChunks<'a, T> {
    type Item = ChangesSlice<'a, T>;

    fn next(&mut self) -> Option<ChangesSlice<'a, T>> {
        if self.size == 0 {
            return None;
        }

        let mut remove_len = 0;
        let remove_chunks = match self.remove_chunks {
            Some(ref mut c) => c,
            None => {
                let c = self.remove.chunks(self.size);
                self.remove_chunks = Some(c);
                self.remove_chunks.as_mut().unwrap()
            }
        };
        let remove_next = remove_chunks.next();
        if let Some(c) = remove_next {
            remove_len = c.len();
            self.remove_remain -= remove_len;
        }

        if remove_len > 0 && remove_len < self.size {
            let size = self.size - remove_len;
            let insert_next = &self.insert[0..min(self.insert.len(), size)];
            self.insert_remain -= insert_next.len();
            return Some(ChangesSlice {
                remove: remove_next.unwrap_or(&[]),
                insert: insert_next,
            });
        }

        let insert_next = if self.remove_remain == 0 && self.insert_remain > 0 {
            match self.insert_chunks {
                Some(ref mut c) => c.next(),
                None => {
                    let i = self.insert.len() - self.insert_remain;
                    let mut c = self.insert[i..].chunks(self.size);
                    let next = c.next();
                    if let Some(s) = next {
                        self.insert_remain -= s.len();
                    }
                    self.insert_chunks = Some(c);
                    next
                }
            }
        } else {
            None
        };

        match (remove_next, insert_next) {
            (Some(remove), Some(insert)) => Some(ChangesSlice { remove, insert }),
            (Some(remove), None) => Some(ChangesSlice {
                remove,
                insert: &[],
            }),
            (None, Some(insert)) => Some(ChangesSlice {
                remove: &[],
                insert,
            }),
            (None, None) => None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ChangesSlice<'a, T> {
    remove: &'a [&'a Entry<T>],
    insert: &'a [&'a Entry<T>],
}

impl<'a, T> ChangesSlice<'a, T> {
    fn empty() -> ChangesSlice<'a, T> {
        ChangesSlice {
            remove: &[],
            insert: &[],
        }
    }

    fn len(&self) -> usize {
        self.remove.len() + self.insert.len()
    }

    pub fn chunks(&self, size: usize) -> ChangesChunks<'a, T> {
        ChangesChunks {
            remove: self.remove,
            remove_remain: self.remove.len(),
            remove_chunks: None,

            insert: self.insert,
            insert_remain: self.insert.len(),
            insert_chunks: None,

            size,
        }
    }
}

fn aggregate_to_ranges<'a, T: Net>(aggr: &'a Aggregate<T>) -> Vec<&'a Entry<T>> {
    let mut ranges = Vec::new();
    for entry in aggr {
        ranges.push(entry);
    }
    ranges
}

#[derive(Serialize)]
struct Wrap<'a, T: Ord> {
    ranges: &'a BTreeSet<&'a Entry<T>>,
}

pub async fn render_bootstrap<'a>(
    bootstrap: &Bootstrap<'a>,
    template_path: impl AsRef<Path>,
    output_template: &str,
) -> Result<Vec<PathBuf>, RenderError> {
    render_bootstrap_with_extra(
        bootstrap,
        template_path,
        output_template,
        BTreeMap::<String, String>::new(),
    )
    .await
}

pub async fn render_bootstrap_with_extra<'a>(
    bootstrap: &Bootstrap<'a>,
    template_path: impl AsRef<Path>,
    output_template: &str,
    extra: impl Serialize,
) -> Result<Vec<PathBuf>, RenderError> {
    let mut outputs = Vec::new();

    for (kind, ranges) in &bootstrap.ipv4 {
        let w = Wrap { ranges };
        outputs.push(
            render_aggregate(&template_path, &output_template, &kind, "ipv4", &w, &extra).await?,
        );
    }
    for (kind, ranges) in &bootstrap.ipv6 {
        let w = Wrap { ranges };
        outputs.push(
            render_aggregate(&template_path, &output_template, &kind, "ipv6", &w, &extra).await?,
        );
    }

    Ok(outputs)
}

async fn render_aggregate<'a, T>(
    template_path: impl AsRef<Path>,
    output_template: &str,
    kind: &Option<String>,
    proto: &str,
    aggregate: &Wrap<'a, T>,
    extra: impl Serialize,
) -> Result<PathBuf, RenderError>
where
    T: IpNet + Hash + Serialize,
{
    let kind = kind.as_deref().unwrap_or("");
    let output = PathBuf::from(
        output_template
            .replace("{proto}", proto)
            .replace("{kind}", kind),
    );
    render(template_path, &output, &aggregate, &extra).await?;
    Ok(output)
}

pub async fn render_diff<'a>(
    diff: &Diff<'a>,
    templage_path: impl AsRef<Path>,
    output_template: &str,
    max_ranges_per_file: Option<usize>,
) -> Result<Vec<PathBuf>, RenderError> {
    render_diff_with_extra(
        diff,
        templage_path,
        output_template,
        max_ranges_per_file,
        BTreeMap::<String, String>::new(),
    )
    .await
}

pub async fn render_diff_with_extra<'a>(
    diff: &Diff<'a>,
    template_path: impl AsRef<Path>,
    output_template: &str,
    max_ranges_per_file: Option<usize>,
    extra: impl Serialize,
) -> Result<Vec<PathBuf>, RenderError> {
    let size = max_ranges_per_file.unwrap_or(diff.len());

    if size == 0 {
        let output = chunk_path(&output_template, 0);
        let diff = Diff::empty();
        render(template_path, &output, &diff, &extra).await?;
        return Ok(vec![output]);
    }

    let mut outputs = Vec::new();

    for (i, chunk) in diff.chunks(size).enumerate() {
        let output = chunk_path(&output_template, i);
        render(&template_path, &output, &chunk, &extra).await?;
        outputs.push(output);
    }

    Ok(outputs)
}

async fn render(
    template: impl AsRef<Path>,
    output: impl AsRef<Path>,
    data: impl Serialize,
    extra: impl Serialize,
) -> Result<(), RenderError> {
    use tera::Context;

    let template = fs::read_to_string(&template).await?;
    let mut tera = Tera::default();
    let mut context = Context::from_serialize(&data)?;

    let extra = Context::from_serialize(&extra)?;
    context.extend(extra);

    let res = tera.render_str(&template, &context)?;
    safe_write(&output, res.as_bytes()).await?;
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

#[derive(Debug)]
pub enum RenderError {
    Io(io::Error),
    Template(tera::Error),
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            RenderError::Io(e) => write!(f, "i/o error: {}", e),
            RenderError::Template(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl std::error::Error for RenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RenderError::Io(e) => Some(e),
            RenderError::Template(e) => Some(e),
        }
    }
}

impl From<io::Error> for RenderError {
    fn from(e: io::Error) -> RenderError {
        RenderError::Io(e)
    }
}

impl From<tera::Error> for RenderError {
    fn from(e: tera::Error) -> RenderError {
        RenderError::Template(e)
    }
}

#[cfg(test)]
mod tests {
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
}
