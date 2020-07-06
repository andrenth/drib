use std::collections::BTreeSet;
use std::fmt;
use std::ops::Sub;
use std::path::Path;

use bincode;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io;

use crate::net::Net;
use crate::util::safe_write;

#[derive(Debug, Serialize, Deserialize)]
pub struct Aggregate<T: Ord> {
    pub ranges: BTreeSet<Entry<T>>,
}

impl<T: Ord> Aggregate<T> {
    pub fn new() -> Aggregate<T> {
        Aggregate {
            ranges: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, entry: Entry<T>) -> bool {
        self.ranges.insert(entry)
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn iter(&self) -> AggregateIterator<T> {
        AggregateIterator {
            inner: self.ranges.iter(),
        }
    }
}

impl<T> Sub<&'_ Aggregate<T>> for &'_ Aggregate<T>
where
    T: Net + Clone,
{
    type Output = Aggregate<T>;

    fn sub(self, rhs: &Aggregate<T>) -> Aggregate<T> {
        let ranges = &self.ranges - &rhs.ranges;
        Aggregate { ranges }
    }
}

impl<'a, T> IntoIterator for &'a Aggregate<T>
where
    T: Ord + Net,
{
    type Item = &'a Entry<T>;
    type IntoIter = AggregateIterator<'a, T>;

    fn into_iter(self) -> AggregateIterator<'a, T> {
        self.iter()
    }
}

pub struct AggregateIterator<'a, T> {
    inner: std::collections::btree_set::Iter<'a, Entry<T>>,
}

impl<'a, T> Iterator for AggregateIterator<'a, T> {
    type Item = &'a Entry<T>;

    fn next(&mut self) -> Option<&'a Entry<T>> {
        self.inner.next()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Entry<T> {
    order: i32,
    pub priority: u16,
    pub kind: Option<String>,
    pub class: String,
    pub protocol: String,
    pub range: T,
}

impl<T> Entry<T> {
    pub fn new(
        priority: u16,
        kind: Option<String>,
        class: String,
        protocol: String,
        range: T,
    ) -> Entry<T> {
        let order = i32::from(priority) * -1;
        Entry {
            order,
            priority,
            kind,
            class,
            protocol,
            range,
        }
    }
}

#[derive(Debug)]
pub enum AggregateLoadError {
    Io(io::Error),
    Deserialize(bincode::Error),
}

impl fmt::Display for AggregateLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            AggregateLoadError::Io(e) => write!(f, "load aggregate i/o error: {}", e),
            AggregateLoadError::Deserialize(e) => write!(f, "parse aggregate error: {}", e),
        }
    }
}

impl std::error::Error for AggregateLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AggregateLoadError::Io(e) => Some(e),
            AggregateLoadError::Deserialize(e) => Some(e),
        }
    }
}

impl From<io::Error> for AggregateLoadError {
    fn from(e: io::Error) -> AggregateLoadError {
        AggregateLoadError::Io(e)
    }
}

impl From<bincode::Error> for AggregateLoadError {
    fn from(e: bincode::Error) -> AggregateLoadError {
        AggregateLoadError::Deserialize(e)
    }
}

#[derive(Debug)]
pub enum AggregateSaveError {
    Io(io::Error),
    Serialize(bincode::Error),
}

impl fmt::Display for AggregateSaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            AggregateSaveError::Io(e) => write!(f, "save aggregate i/o error: {}", e),
            AggregateSaveError::Serialize(e) => write!(f, "aggregate serialize error: {}", e),
        }
    }
}

impl std::error::Error for AggregateSaveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AggregateSaveError::Io(e) => Some(e),
            AggregateSaveError::Serialize(e) => Some(e),
        }
    }
}

impl From<io::Error> for AggregateSaveError {
    fn from(e: io::Error) -> AggregateSaveError {
        AggregateSaveError::Io(e)
    }
}

impl From<bincode::Error> for AggregateSaveError {
    fn from(e: bincode::Error) -> AggregateSaveError {
        AggregateSaveError::Serialize(e)
    }
}

pub async fn serialize(
    path: impl AsRef<Path>,
    ipv4: &Aggregate<Ipv4Net>,
    ipv6: &Aggregate<Ipv6Net>,
) -> Result<(), AggregateSaveError> {
    let data = bincode::serialize(&(ipv4, ipv6))?;
    safe_write(&path, &data).await?;
    Ok(())
}

pub async fn deserialize(
    path: impl AsRef<Path>,
) -> Result<(Aggregate<Ipv4Net>, Aggregate<Ipv6Net>), AggregateLoadError> {
    let data = match fs::read(&path).await {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok((Aggregate::new(), Aggregate::new()))
        }
        Err(e) => return Err(e.into()),
    };
    let aggr = bincode::deserialize(&data)?;
    Ok(aggr)
}
