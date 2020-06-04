use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Sub;

use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpNet;
use serde::{Deserialize, Serialize};

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
pub struct Changes<'a, T> {
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

impl<'a, T: IpNet> Changes<'a, T> {
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

fn aggregate_to_ranges<'a, T: IpNet>(aggr: &'a Aggregate<T>) -> Vec<&'a Entry<T>> {
    let mut ranges = Vec::new();
    for entry in aggr {
        ranges.push(entry);
    }
    ranges
}

#[derive(Debug, Serialize)]
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
    T: Ord,
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
    pub priority: usize,
    pub kind: Option<String>,
    pub class: String,
    pub range: T,
}
