use std::collections::BTreeSet;
use std::fmt;
use std::ops::Sub;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io;

use crate::parser::{Net, ParseError};

#[derive(Debug, Serialize)]
pub struct Aggregate<T: Ord> {
    pub ranges: BTreeSet<Entry<T>>,
}

impl<T: Ord + Net> Aggregate<T> {
    pub fn new() -> Aggregate<T> {
        Aggregate {
            ranges: BTreeSet::new(),
        }
    }

    pub async fn load<P>(path: P) -> Result<Aggregate<T>, AggregateLoadError>
    where
        P: AsRef<Path>,
    {
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
                return Err(ParseError(format!(
                    "malformed line: '{}' ({})",
                    line,
                    path.as_ref().display()
                ))
                .into());
            }
            let range = parts[0].parse().map_err(|e| ParseError::from(e))?;
            let priority = parts[1].parse().map_err(ParseError::from)?;
            let class = parts[2].to_owned();
            let kind = if len == 4 {
                Some(parts[3].to_owned())
            } else {
                None
            };
            let protocol = T::protocol().to_owned();
            let entry = Entry::new(priority, kind, class, protocol, range);
            aggr.insert(entry);
        }

        Ok(aggr)
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
    T: Clone + Ord,
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
    #[serde(skip_serializing)]
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
    Parse(ParseError),
}

impl fmt::Display for AggregateLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            AggregateLoadError::Io(e) => write!(f, "i/o error: {}", e),
            AggregateLoadError::Parse(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl std::error::Error for AggregateLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AggregateLoadError::Io(e) => Some(e),
            AggregateLoadError::Parse(e) => Some(e),
        }
    }
}

impl From<io::Error> for AggregateLoadError {
    fn from(e: io::Error) -> AggregateLoadError {
        AggregateLoadError::Io(e)
    }
}

impl From<ParseError> for AggregateLoadError {
    fn from(e: ParseError) -> AggregateLoadError {
        AggregateLoadError::Parse(e)
    }
}
