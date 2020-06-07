# Drib

## Introduction

Drib is a tool that lets you manage IPv4 and IPv6 address ranges obtained locally or from a remote source.
IP ranges can be classified, merged, prioritized and finally rendered according to provided templates.

## Installation

### Debian or Ubuntu

```sh
$ wget https://
$ sudo dpkg -i ...
```

### From source

Use Rust's package manager, [cargo](https://github.com/rust-lang/cargo), to install Drib from source:

```sh
$ cargo install drib
```

## Running

Drib can be run in two modes: _bootstrap_ and _diff_.
Bootstrap mode will fetch all configured ranges and render them in a file, using the provided template.
Diff mode will also fetch IP ranges but will compare them with the ones fetched in the previous run, rendering the resulting difference (i.e. inserted and removed ranges).

Run in bootstrap mode:

```sh
$ drib bootstrap
```

Run in diff mode:

```sh
$ drib diff
```

The commands above will read the default configuration file, `/etc/drib/drib.yaml`.
To specify an alternative configuration file, use the `-c` or `--config` command line flag:

```sh
$ drib -c /path/to/config/file.yaml bootstrap
$ drib -c /path/to/config/file.yaml diff
```

For further details, run `drib help`.

## Configuration

Drib uses YAML for its configuration file.
The following directives are supported:

#### `state_dir`

The directory where Drib stores downloaded ranges and calculated range aggregates (defaults to `/var/lib/drib`).

#### `log_level`

Drib's log level.
Valid values are `error`, `warn`, `info`, `debug` or `trace` (defaults to `info`).

#### `bootstrap`

This section defines input and output settings for bootstrap mode.
Two subsettings are expected:

* `input` refers to a template file (see the `Templates` section below for details) used to render the bootstrap ranges.
* `output` specifies the path of the rendered file.

The output path is itself a template, so a couple of variables can be used to split the bootstrap output according to protocol (i.e. IPv4 and IPv6), using the `proto` variable, and _kind_ (see the documentation on _groups_ below), using the `kind` variable.
Output path variables are specified inside curly braces (`{proto}` and `{kind}`) and will be replaced accordingly.

Example:

```yaml
bootstrap: {
  input: "/etc/drib/bootstrap.tpl",
  output: "/etc/drib/bootstrap_{proto}_{kind}",
}
```

#### `core_threads`

Sets the number of worker threads in Drib's async runtime's ([Tokio](https://tokio.rs/)) thread pool.
Defaults to the number of cores available to the system.

#### `max_threads`

The maximum number of threads spawned by Drib's async runtime ([Tokio](https://tokio.rs/)).
This number must be greater than the `core_threads` setting.
Defaults to 512.

#### `diff`

This section defines input and output settings for diff mode, as described in the `bootstrap` section.

* `input` refers to a template file (see the Templates section below for details) used to render the bootstrap ranges.
* `output` specifies the path of the rendered file.

The `output` setting differs from the one in the `bootstrap` section in that a single variable is available, `i`, which corresponds to the _index_ of the output file.
This refers to the fact that diff mode also includes the `max_ranges_per_file` setting, which allows you to limit the size of the output files.
Once the number of ranges rendered in the output file reaches the `max_ranges_per_file` value, a new file will be generated, and the `i` variable will be incremented.
This variable supports an integer modifier that indicates how many digits are used for the index, so, for example, `{3i}` will represent the index with 3 digits, padding it with zeros if necessary.

Example:

```yaml
diff: {
  input: "/etc/drib/policy_update.lua.tpl",
  output: "/etc/drib/policy_update.{2i}",
  max_ranges_per_file: 1800,
}
```

#### `downloads`

The `downloads` section allows you to specify range sources to be downloaded for later use in the `ipv4` and `ipv6` sections (see below).
This is useful because a number of public IP lists include both IPv4 and IPv6 addresses, while in Drib you must specify those protocols separately.
By using the `downloads` section, you can avoid downloading the same file twice.
For details on how to refer to a downloaded range, see the groups documentation below.

Each entry in the `downloads` section defines a download with a given name and two settings:

* `url`: the URL pointing to the file to be downloaded (only HTTP and HTTPS URLs are supported).
* `check_interval`: how often to download this file.

The `check_interval` setting is specified with a suffix that indicates the time unit, i.e. _s_ for seconds, _m_ for minutes or _h_ for hours.
Downloads are also subject to the `Last-Modified` HTTP header, so a file won't be downloaded after `check_interval` if it hasn't been modified since its last download.

Example:

```yaml
downloads: {
  amazon: {
    url: "https://ip-ranges.amazonaws.com/ip-ranges.json",
    check_interval: "1d",
  },
  fastly: {
    url: "https://api.fastly.com/public-ip-list",
    check_interval: "1d",
  },
}
```

#### Groups (`ipv4` and `ipv6` sections)

The core of Drib's configuration is in the groups specification.
Two group lists are supported, `ipv4` and `ipv6`.
Each group in a list contains a number of IP range feeds (containing addresses of the approriate protocol version) and two additional settings:

* `priority`: the priority of this group.
* `kind`: an arbitrary string to be associated with ranges in this group.

Any IP range intersection between two groups is removed from the group with the higher value in its priority field.
In other words, precedence is given to groups with lower priority values.
This allows the implementation of IP white and blacklists.
For example, by creating a group of ranges with priority 1 and another group with priority 2, intersecting ranges among them will be removed from the latter, so the first group effectively works as a whitelist, while second works as a blacklist.

The `kind` parameter can be used to associate a property with the group's ranges.
An example would be specifying if those ranges are to be handled as source or destination addresses.

Feeds are specified by a name, a _source_ and a _class_.
The source indicates how this feed's IP ranges are obtained.
A number of sources is supported:

* `range`: a literal IP range or domain specified as a string.
* `file`: a local file containing IP ranges or domains.
* `remote`: a remote range to be obtained via HTTP or HTTPS.
* `download`: a reference to a downloaded file in the `downloads` section of the configuration file.

A `range` feed takes no extra parameters.
A `file` feed takes a `path` parameter, the path to the file containing the ranges, and a `parser` parameter that specifies how the file is interpreted (see the _Parsers_ section below).
A `remote` feed takes an `url` and a `check_interval`, in the same way as entries in the `downloads` section, and also a `parser` parameter, as in `file` feeds.
Finally, `download` feeds take a `name` parameter that must match the name of a download entry in the `downloads` section of the configuration file.

The _class_ of feed is given by the `class` parameter.
This is an arbitrary string that can be used to group IP ranges from different feeds.
Within a group, two feeds with different classes cannot have a non-empty intersection.

Example:

```yaml
ipv4: {
  whitelist: {
    priority: 10,
    kind: "src",

    static: {
      file: {
        path: "/etc/drib/whitelist",
        parser: {ranges: {one_per_line: {comment: "#"}}},
      },
      class: "1",
    },

    my_ip: {
      range: "1.2.3.4/32"
      class: "2",
    },

    cloudflare: {
      remote: {
        url: "https://www.cloudflare.com/ips-v4",
        check_interval: "1d",
        parser: {ranges: {one_per_line: {comment: "#"}}},
      },
      class: "3",
    },
  },

  blacklist: {
    priority: 20,
    kind: "src",

    fullbogons: {
      remote: {
        url: "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt",
        check_interval: "1d",
        parser: {ranges: {one_per_line: {comment: "#"}}},
      },
      class: "0",
    },
  },
}
```

### Parsers

For feeds of types `file`, `remote` and `download`, Drib requires a parser to be specified so that it can extract IP ranges from each given source.
The first step is to specify if the source contains IP ranges or domain names, by using either `ranges` or `domains` keywords.
Then the parser itself must be declared.
The following parsers are currently supported:

#### One Per Line

This is a parser with a single element (either IP range or domain) per line.
Its only parameter is the `comment` string.

Example:

```yaml
parser: {
  ranges: {
    one_per_line: {
      comment: "#",
    },
  },
},
```

#### CSV

This is a parser for tabular data. It accepts the following parameters:

* `comment`: the comment string.
* `header`: set as `true` if the data contains a header, `false` otherwise.
* `columns`: indices of columns from which data is extracted in each row of the table.
* `join`: the string with which the fields extracted from the `columns` setting are joined to form the final IP range or domain.

Example:

```yaml
parser: {
  ranges: {
    csv: {
      comment: "#",
      header: true,
      separator: ",",
      columns: [0, 2],
      join: "/",
    },
  },
},
```

#### JSON

This is a parser for JSON data.
The parser expects a path to an array of IP ranges or domains.
If those are listed in an array of JSON objects, the parser also point to the key that contains the actual data we're interested in.

* `path`: the JSON path pointing to the array containing the ranges or domains.
* `key`: if the array pointed to by `path` contains JSON objects, this specifies the key whose value is the range or domain.
* `filter`: if the array pointed to by path contains JSON objects, ignore elements that don't match the given filter.

The filter above is a two-element array containing a key name and a value.
If the value associated to the given key in an array element doesn't match the given value, the element is ignored.

Example:

Given the JSON document below:

```json
{
  "ipv4": {
    "prefixes": [
      {
        "type": "foo",
        "prefix": "1.2.3.4/32"
      },
      {
        "type": "foo",
        "prefix": "1.2.3.5/32"
      },
      {
        "type": "bar",
        "prefix": "1.2.3.6/32"
      }
    ]
  }
}
```

The following parser would extract the ranges `1.2.3.4/32` and `1.2.3.5/32` from it:

```yaml
parser: {
  ranges: {
    json: {
      path: "ipv4.prefixes",
      key: "prefix",
      filter: ["type", "foo"],
    },
  },
},
```

### Templates

Drib uses the Rust crate [TinyTemplate](https://docs.rs/tinytemplate/1.1.0/tinytemplate/index.html) for its templating, which has a simple and intuitive [syntax](https://docs.rs/tinytemplate/1.1.0/tinytemplate/syntax/index.html).

When running in bootstrap mode, Drib provides a global `ranges` object which is an array of `entry` elements.
The `entry` elements contain information about each range in the following fields:

* `priority`: the priority associated to the range, taken from the definition of the group it comes from.
* `kind`: the kind associated to the range, also taken from the group definition.
* `class`: the class associated to the range, taken from the definition of the feed it belongs to.
* `is_ipv4`: a boolean field that is true if the range's protocol is IPv4.
* `is_ipv6`: a boolean field that is true if the range's protocol is IPv6.

The example below creates [iptables](https://www.netfilter.org/) rules blocking ranges in bootstrap mode:

```
{{ for entry in ranges -}}
{{ if entry.is_ipv4 -}}
iptables -I INPUT -s {entry.range} -j DROP
{{ else -}}
ip6tables -I INPUT -s {entry.range} -j DROP
{{ endif -}}
{{ endfor -}}
```

When running in diff mode, two global objects are provided to the template: `ipv4` and `ipv6`.
Both contain two fields, `remove` and `insert`, which are arrays of `entry` elements as described above.

The example below manages iptables rules in diff mode:

```
{{ for entry in ipv4.remove -}}
iptables -D INPUT -s {entry.range} -j DROP
{{ endfor -}}

{{ for entry in ipv4.insert -}}
iptables -I INPUT -s {entry.range} -j DROP
{{ endfor -}}

{{ for entry in ipv6.remove -}}
ip6tables -D INPUT -s {entry.range} -j DROP
{{ endfor -}}

{{ for entry in ipv6.insert -}}
ip6tables -I INPUT -s {entry.range} -j DROP
{{ endfor -}}
```
