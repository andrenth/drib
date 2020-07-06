use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::num::ParseIntError;

use serde::Deserialize;

use crate::net::Net;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Parser<T> {
    OnePerLine(OnePerLine<T>),
    Csv(Csv<T>),
    Json(Json<T>),
}

impl<T: Parse + Eq + Hash> Parser<T> {
    pub fn parse(&self, data: &str) -> Result<HashSet<T>, ParseError> {
        let set = match self {
            Parser::OnePerLine(p) => p.parse(data)?,
            Parser::Csv(p) => p.parse(data)?,
            Parser::Json(p) => p.parse(data)?,
        };
        Ok(set)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnePerLine<T> {
    comment: String,

    #[serde(skip)]
    _type: PhantomData<T>,
}

impl<T: Parse> OnePerLine<T> {
    pub fn new(comment: String) -> OnePerLine<T> {
        OnePerLine {
            comment,
            _type: PhantomData,
        }
    }
}

impl<T: Parse + Eq + Hash> OnePerLine<T> {
    fn parse(&self, data: &str) -> Result<HashSet<T>, ParseError> {
        parse(&self.comment, data, |_, line| T::parse(line).map(Some))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Csv<T> {
    comment: String,
    separator: String,
    #[serde(default = "not_true")]
    header: bool,
    columns: Vec<usize>,
    #[serde(default = "empty_string")]
    join: String,

    #[serde(skip)]
    _type: PhantomData<T>,
}

impl<T: Parse + Hash + Eq> Csv<T> {
    fn parse(&self, data: &str) -> Result<HashSet<T>, ParseError> {
        parse(&self.comment, data, |i, line| {
            if self.header && i == 0 {
                return Ok(None);
            }
            let fields: Vec<_> = line.split(&self.separator).collect();
            match extract_fields(&fields, &self.columns) {
                Some(fields) => T::parse(&fields.join(&self.join)).map(Some),
                None => return Err(ParseError(line.to_owned())),
            }
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Json<T> {
    path: String,
    key: Option<String>,
    filter: Option<(String, String)>,

    #[serde(skip)]
    _type: PhantomData<T>,
}

impl<T: Parse + Hash + Eq> Json<T> {
    fn parse(&self, data: &str) -> Result<HashSet<T>, ParseError> {
        let val: serde_json::Value =
            serde_json::from_str(&data).map_err(|e| ParseError(e.to_string()))?;
        if !val.is_object() {
            return Err(ParseError("not an object".to_string()));
        }
        let path = self.path.split('.');
        let res = path
            .fuse()
            .fold(Some(&val), |v, p| v.and_then(|v| v.get(p)));
        if res.is_none() {
            return Err(ParseError("invalid json path".to_string()));
        }
        let res = res.unwrap().as_array();
        if res.is_none() {
            return Err(ParseError("invalid json path".to_string()));
        }

        let mut set = HashSet::new();
        for v in res.unwrap().iter() {
            if !v.is_object() {
                if let Some(s) = v.as_str() {
                    let t = T::parse(s)?;
                    set.insert(t);
                    continue;
                }
                return Err(ParseError(format!("value is not a string: {}", v)));
            }
            if let Some(ref filter) = &self.filter {
                let s = v.get(&filter.0).and_then(|s| s.as_str());
                if s != Some(&filter.1) {
                    // we have a filter and it doesn't match; ignore the value.
                    continue;
                }
            }
            // matching filter or no filter: parse the given field.
            if let Some(ref key) = &self.key {
                let s = v.get(key).and_then(|s| s.as_str());
                if let Some(s) = s {
                    let t = T::parse(s)?;
                    set.insert(t);
                    continue;
                }
                return Err(ParseError(format!(
                    "key '{}' not found or value not a string: {}",
                    key, v
                )));
            }
            return Err(ParseError(format!(
                "value is an object but no key is specified: {}",
                v
            )));
        }

        Ok(set)
    }
}

fn parse<T, F>(comment: &str, data: &str, mut f: F) -> Result<HashSet<T>, ParseError>
where
    T: Parse + Hash + Eq,
    F: FnMut(usize, &str) -> Result<Option<T>, ParseError>,
{
    let mut set = HashSet::new();
    let mut i = 0;

    for line in data.lines() {
        let line = line.split(comment).next().unwrap().trim();
        if line.is_empty() || line.starts_with(comment) {
            continue;
        }
        if let Some(v) = f(i, line)? {
            set.insert(v);
        }
        i += 1;
    }

    Ok(set)
}

pub fn parse_net<N: Net>(s: &str) -> Result<N, ParseError> {
    let net = if s.contains("/") {
        s.parse()?
    } else {
        let s = format!("{}/{}", s, N::max_prefix());
        s.parse()?
    };
    Ok(net)
}

fn extract_fields<T: Clone>(fields: &[T], columns: &[usize]) -> Option<Vec<T>> {
    let len = fields.len();
    match columns.iter().max() {
        Some(max) if len <= *max => return None,
        Some(_) => (),
        None => return None,
    };
    let v: Vec<_> = columns.iter().map(|i| fields[*i].clone()).collect();
    Some(v)
}

fn not_true() -> bool {
    false
}

fn empty_string() -> String {
    "".to_string()
}

#[derive(Debug, Eq, PartialEq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<ipnet::AddrParseError> for ParseError {
    fn from(e: ipnet::AddrParseError) -> ParseError {
        ParseError(format!("{}", e))
    }
}

impl From<std::net::AddrParseError> for ParseError {
    fn from(e: std::net::AddrParseError) -> ParseError {
        ParseError(format!("{}", e))
    }
}

impl From<ParseIntError> for ParseError {
    fn from(e: ParseIntError) -> ParseError {
        ParseError(format!("{}", e))
    }
}

pub trait Parse {
    fn parse(s: &str) -> Result<Self, ParseError>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::marker::PhantomData;

    use ipnet::{Ipv4Net, Ipv6Net};

    use super::*;

    #[test]
    fn test_parse_net_parses_networks_correctly() {
        assert_eq!(
            Ok("10.0.0.0/24".parse().unwrap()),
            parse_net::<Ipv4Net>("10.0.0.0/24")
        );
        assert_eq!(
            Ok("10.0.0.1/32".parse().unwrap()),
            parse_net::<Ipv4Net>("10.0.0.1")
        );
    }

    #[test]
    fn test_parse_net_parses_ips_as_networks() {
        assert_eq!(
            Ok("abcd::/16".parse().unwrap()),
            parse_net::<Ipv6Net>("abcd::/16")
        );
        assert_eq!(
            Ok("abcd::1/128".parse().unwrap()),
            parse_net::<Ipv6Net>("abcd::1")
        );
    }

    #[test]
    fn test_parse_handles_empty_input() {
        assert_eq!(
            Ok(HashSet::<Ipv4Net>::new()),
            parse("", "", |_, _| {
                assert!(false);
                Ok(None)
            })
        );
        assert_eq!(
            Ok(HashSet::<Ipv4Net>::new()),
            parse("", "    \n\n  \n    \n\n\n\n   ", |_, _| {
                assert!(false);
                Ok(None)
            })
        );
        assert_eq!(
            Ok(HashSet::<Ipv4Net>::new()),
            parse("", "    ###\n#\n ###  \n  #  \n\n\n\n # ", |_, _| {
                assert!(false);
                Ok(None)
            })
        );
    }

    #[test]
    fn test_parse_one_per_line() {
        let expected: HashSet<Ipv4Net> = [
            "10.0.0.1/32",
            "10.0.0.0/8",
            "192.168.0.1/32",
            "192.168.0.0/16",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

        let parser: OnePerLine<Ipv4Net> = OnePerLine {
            comment: "#".to_string(),
            _type: PhantomData,
        };
        let actual = parser.parse(
            r#"
            # foo
            # 10.0.0.2
            192.168.0.1
            10.0.0.1/32 # bar

            10.0.0.0/8
            192.168.0.0/16
        "#,
        );
        assert_eq!(Ok(expected), actual);
    }

    #[test]
    fn test_parse_csv() {
        let expected: HashSet<Ipv4Net> = [
            "10.0.0.1/32",
            "10.0.0.0/8",
            "192.168.0.1/32",
            "192.168.0.0/16",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

        let parser: Csv<Ipv4Net> = Csv {
            comment: ";".to_string(),
            separator: ",".to_string(),
            header: false,
            columns: vec![1, 2],
            join: "/".to_string(),
            _type: PhantomData,
        };
        let actual = parser.parse(
            r#"
            ; foo
            ; abc,10.0.0.2,xyz
            abc,192.168.0.1,32,xyz
            abc,10.0.0.1,32,xyz ; bar

            abc,10.0.0.0,8,xyz
            abc,192.168.0.0,16,xyz
        "#,
        );
        assert_eq!(Ok(expected), actual);
    }
    #[test]

    fn test_parse_table() {
        let expected: HashSet<Ipv4Net> = [
            "10.0.0.1/32",
            "10.0.0.0/8",
            "192.168.0.1/32",
            "192.168.0.0/16",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

        let parser: Csv<Ipv4Net> = Csv {
            comment: "//".to_string(),
            separator: "|".to_string(),
            columns: vec![1],
            header: true,
            join: "".to_string(),
            _type: PhantomData,
        };
        let actual = parser.parse(
            r#"
            // foo
            this is the header
            abc|192.168.0.1/32|xyz
            abc|10.0.0.1/32|xyz // bar

            abc|10.0.0.0/8|xyz
            abc|192.168.0.0/16|xyz
        "#,
        );
        assert_eq!(Ok(expected), actual);
    }
}
