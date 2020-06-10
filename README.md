# Drib

## Introduction

Drib is a tool that lets you manage IPv4 and IPv6 address ranges obtained locally or from a remote source.
IP ranges can be classified, merged, prioritized and finally rendered according to provided templates.

Possible uses include:

* Firewall rule generation from public IP range lists;
* Policy script generation for [Gatekeeper](https://github.com/AltraMayor/gatekeeper).

## Installation

### Debian or Ubuntu

*Debian packages will be provided with the first Drib release*

```sh
$ wget https://
$ sudo dpkg -i ...
```

### From source

*Drib will be added to crates.io on its first release*

Use Rust's package manager, [cargo](https://github.com/rust-lang/cargo), to install Drib from source:

```sh
$ cargo install --git https://github.com/andrenth/drib
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

#### `core_threads`

Sets the number of worker threads in Drib's async runtime's ([Tokio](https://tokio.rs/)) thread pool.
Defaults to the number of cores available to the system.

#### `max_threads`

The maximum number of threads spawned by Drib's async runtime ([Tokio](https://tokio.rs/)).
This includes `core_threads`, so setting `max_threads` lower than this value is a configuration error.
Defaults to 512.

#### `bootstrap`

This section defines input and output settings for bootstrap mode.
Two subsettings are expected:

* `input` refers to a template file (see the `Templates` section below for details) used to render the bootstrap ranges.
* `output` specifies the path of the rendered file.

The output path is itself a template, so a couple of variables can be used to split the bootstrap output according to protocol (i.e. IPv4 and IPv6), using the `{proto}` variable, and _kind_ (see the documentation on _groups_ below), using the `{kind}` variable.

The bootstrap template is rendered multiple times, for each possible protocol and _kind_ combination.
For example, if your groups configuration defines three different _kinds_, a total of six bootstrap files will be generated (three for IPv4 and three for IPv6).
This means that if the `{proto}` and `{kind}` variables are not used in the `output` setting, a given rendered file may overwrite a previously generated one.

Example:

```yaml
bootstrap: {
  input: "/etc/drib/bootstrap.tpl",
  output: "/etc/drib/bootstrap_{proto}_{kind}",
}
```

#### `diff`

This section defines input and output settings for diff mode, as described in the `bootstrap` section.

* `input` refers to a template file (see the Templates section below for details) used to render the bootstrap ranges.
* `output` specifies the path of the rendered file.
* `max_ranges_per_file` limits the number of ranges rendered in a single output file.

The `output` setting differs from the one in the `bootstrap` section in that a single variable is available, `{i}`, which corresponds to the *i*th output file.
This refers to the fact that diff mode also includes the `max_ranges_per_file` setting, which allows you to limit the size of the output files.
Once the number of ranges rendered in the output file reaches the `max_ranges_per_file` value, a new file will be generated, and the `i` variable will be incremented.
This variable supports an integer modifier that indicates how many digits are used for the index, so, for example, `{3i}` will represent the index with 3 digits, padding it with zeros if necessary.

Example:

```yaml
diff: {
  input: "/etc/drib/policy_update.lua.tpl",
  output: "/etc/drib/policy_update.{2i}",
  max_ranges_per_file: 1000,
}
```

#### `downloads`

The `downloads` section allows you to specify range sources to be downloaded for later use in the `ipv4` and `ipv6` sections (see below).
This is useful because a number of public IP lists include both IPv4 and IPv6 addresses, while in Drib you must specify sources separately by protocol.
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

Precedence is given to groups according to their configured `priority` setting: higher priority groups will always "own" any ranges that intersect with lower priority ones.
In other words, range intersections between groups causes the intersection to be removed from the lower priority group.

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
A `file` feed takes a `path` parameter, indicating the file that contains the ranges, and a `parser` parameter that specifies how the file is interpreted (see the _Parsers_ section below).
A `remote` feed takes an `url` and a `check_interval`, in the same way as entries in the `downloads` section, and also a `parser` parameter, as in `file` feeds.
Finally, `download` feeds takes a `name` parameter that must match the name of a download entry in the `downloads` section of the configuration file, along with a `parser`.

The _class_ of a feed is given by its `class` parameter.
This is an arbitrary string that can be used to group IP ranges from different feeds.
Within a group, two feeds with different classes cannot have a non-empty intersection.

Group priorities allow the implementation of groups that work as white or blacklists.
To do this, use a group's `kind` or a feed's `class` attribute in the templates in a way that allows the tool in charge of processing Drib's output to identify their appropriate roles.
For a concrete example of this, see the use case described below in the "Full example" section.

Example:

```yaml
ipv4: {
  my_group: {
    priority: 10,
    kind: "source",

    # A literal range
    my_ip: {
      range: "1.2.3.4/32"
      class: "1",
    },

    # Domains loaded from a file
    static: {
      file: {
        path: "/etc/drib/domain_whitelist",
        parser: {domains: {one_per_line: {comment: "#"}}},
      },
      class: "2",
    },

    # Ranges loaded from a remote range
    cloudflare: {
      remote: {
        url: "https://www.cloudflare.com/ips-v4",
        check_interval: "1d",
        parser: {ranges: {one_per_line: {comment: "#"}}},
      },
      class: "3",
    },
  },

  # Reference to a downloaded source
  fastly: {
    download: {
      name: "fastly",
      parser: {ranges: {json: {path: "addresses"}}},
    },
    class: "4",
  },
}
```

### Parsers

For feeds of types `file`, `remote` and `download`, Drib requires a parser to be specified so that it can extract IP ranges from each given source.
The first step is to specify if the source contains IP ranges or domain names, by using either `ranges` or `domains` keywords.
Then the parser itself must be declared, according to one of the suported parsers described below.

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

This is a parser for tabular data.
It accepts the following parameters:

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

Drib uses the Rust crate [Tera](https://tera.netlify.app/docs) for its templating, which has a simple and intuitive [syntax](https://tera.netlify.app/docs/#templates) similar do Django templates.

When running in bootstrap mode, Drib provides a global `ranges` object which is an array of `entry` elements.
The `entry` elements contain information about each range in the following fields:

* `priority`: the priority associated to the range, taken from the definition of the group it comes from.
* `kind`: the kind associated to the range, also taken from the group definition.
* `class`: the class associated to the range, taken from the definition of the feed it belongs to.
* `protocol`: the protocol associated to the range, as a string (either `"ipv4"` or `"ipv6"`).
* `range`: the IP range itself.

The example below creates [iptables](https://www.netfilter.org/) rules blocking ranges in bootstrap mode:

```
{% for entry in ranges -%}
{% if entry.protocol == "ipv4" -%}
{% set command = "iptables" -%}
{% else -%}
{% set command = "ip6tables" -%}
{% endif -%}
{{command}} -I INPUT -s {{entry.range}} -j DROP
{% endfor -%}
```

When running in diff mode, two global objects are provided to the template: `ipv4` and `ipv6`.
Both contain two fields, `remove` and `insert`, which are arrays of `entry` elements as described above.

The example below manages iptables rules in diff mode:

```
{% for entry in ipv4.remove -%}
{% if entry.kind == "src" -%}
{% set param = "-s" -%}
{% else -%}
{% set param = "-d" -%}
{% endif -%}
iptables -D INPUT {{param}} {{entry.range}} -j DROP
{% endfor -%}

{% for entry in ipv4.insert -%}
{% if entry.kind == "src" -%}
{% set param = "-s" -%}
{% else -%}
{% set param = "-d" -%}
{% endif -%}
iptables -I INPUT {{param}} {{entry.range}} -j DROP
{% endfor -%}

{% for entry in ipv6.remove -%}
{% if entry.kind == "src" -%}
{% set param = "-s" -%}
{% else -%}
{% set param = "-d" -%}
{% endif -%}
ip6tables -D INPUT {{param}} {{entry.range}} -j DROP
{% endfor -%}

{% for entry in ipv6.insert -%}
{% if entry.kind == "src" -%}
{% set param = "-s" -%}
{% else -%}
{% set param = "-d" -%}
{% endif -%}
ip6tables -I INPUT {{param}} {{entry.range}} -j DROP
{% endfor -%}
```

## Full example

For clarity, a full usage example is provided.
The idea is to manage firewall rules by obtaining IP ranges from public blacklist sources such as Spamhaus' [DROP](https://www.spamhaus.org/drop/) or Team Cymru's [Bogons](https://team-cymru.com/community-services/bogon-reference/bogon-reference-http/).

Given the large amount of ranges, the example will use Netfilter's [ipset](http://ipset.netfilter.org/) feature to avoid a linear search of matching firewall rules.

### Initial setup

Before running Drib, we'll setup IP sets where ranges will be inserted, for allowed and blocked IPv4 and IPv6 ranges.
Run the following commands:

```sh
$ sudo ipset create drib-ipv4-allow  hash:net family inet
$ sudo ipset create drib-ipv4-reject hash:net family inet

$ sudo ipset create drib-ipv6-allow  hash:net family inet6
$ sudo ipset create drib-ipv6-reject hash:net family inet6
```

Then create the respective `iptables` rules matching the above sets:

```sh
$ sudo iptables -I INPUT -m set --match-set drib-ipv4-allow  src -j ACCEPT
$ sudo iptables -I INPUT -m set --match-set drib-ipv4-reject src -j DROP

$ sudo ip6tables -I INPUT -m set --match-set drib-ipv6-allow  src -j ACCEPT
$ sudo ip6tables -I INPUT -m set --match-set drib-ipv6-reject src -j DROP
```

### Drib configuration

We'll configure Drib to fetch IP ranges from the above mentioned blacklists.
We'll also block access coming from the IP addresses of the `www.spammers-r-us.com` domain.
Finally, we'll allow connections from our office's IP address, and from major CDN providers (Cloudflare, Cloudfront and Fastly), regardless of any of them being listed in any of the blacklists.
If, for whatever reasons, an IP from one of the CDN providers ends up in one of the blacklists, it will not be blocked, because the `whitelist` group has a higher value in its `priority` field, and therefore any intersection with the ranges from the `blacklist` group will be removed from the latter.

Create `/etc/drib/drib.yaml` as below (default settings are ommited):

```yaml
bootstrap: {
  input: "/etc/drib/insert_ranges.sh.tpl",
  output: "/etc/drib/insert_{proto}_{kind}_ranges.sh",
}

diff: {
  input: "/etc/drib/manage_ranges.sh.tpl",
  output: "/etc/drib/manage_ranges.{3i}.sh",
  max_ranges_per_file: 1000,
}

# Amazon and Fastly provide their IP ranges in the same source, so we
# download them here and reference them later.
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

# Parser definitions: these parsers are used by multiple feeds, so we
# use YAML's anchors and aliases feature to avoid repetition.

.one_range_per_line_hash_comments: &one_range_per_line_hash_comments {
  ranges: {
    one_per_line: {
      comment: "#",
    },
  },
}

.one_range_per_line_semicolon_comments: &one_range_per_line_semicolon_comments {
  ranges: {
    one_per_line: {
      comment: ";",
    },
  },
}

#
# IPv4 groups
#

ipv4: {
  whitelist: {
    priority: 20,
    kind: "src",

    office: {
      range: "1.2.3.4/32",
      class: "allow",
    },

    cloudflare: {
      remote: {
        url: "https://www.cloudflare.com/ips-v4",
        check_interval: "1d",
        parser: *one_range_per_line_hash_comments,
      },
      class: "allow",
    },

    fastly: {
      download: {
        name: "fastly",
        parser: {ranges: {json: {path: "addresses"}}},
      },
      class: "allow",
    },

    cloudfront: {
      download: {
        name: "amazon",
        parser: {
          ranges: {
            json: {
              path: "prefixes",
              key: "ip_prefix",
              filter: ["service", "CLOUDFRONT"],
            },
          },
        },
      },
      class: "allow",
    },
  },

  # The blacklist group has a lower priority than the whitelist group
  # above (10 vs 20), so any intersection will be kept in the whitelist
  # and removed from the blacklist.
  blacklist: {
    priority: 10,
    kind: "src",

    fullbogons: {
      remote: {
        url: "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt",
        check_interval: "1d",
        parser: *one_range_per_line_hash_comments,
      },
      class: "reject",
    },

    spamhaus_drop: {
      remote: {
        url: "https://www.spamhaus.org/drop/drop.txt",
        check_interval: "12h",
        parser: *one_range_per_line_semicolon_comments,
      },
      class: "reject",
    },
  },
}

#
# IPv6 groups
#

ipv6: {
  whitelist: {
    priority: 20,
    kind: "src",

    office: {
      range: "a:b:c:d::/64",
      class: "allow",
    },

    cloudflare: {
      remote: {
        url: "https://www.cloudflare.com/ips-v6",
        check_interval: "1d",
        parser: *one_range_per_line_hash_comments,
      },
      class: "allow",
    },

    fastly: {
      download: {
        name: "fastly",
        parser: {ranges: {json: {path: "ipv6_addresses"}}},
      },
      class: "allow",
    },

    cloudfront: {
      download: {
        name: "amazon",
        parser: {
          ranges: {
            json: {
              path: "ipv6_prefixes",
              key: "ipv6_prefix",
              filter: ["service", "CLOUDFRONT"],
            },
          },
        },
      },
      class: "allow",
    },
  },

  blacklist: {
    priority: 10,
    kind: "src",

    fullbogons: {
      remote: {
        url: "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt",
        check_interval: "1d",
        parser: *one_range_per_line_hash_comments,
      },
      class: "reject",
    },

    spamhaus_drop: {
      remote: {
        url: "https://www.spamhaus.org/drop/dropv6.txt",
        check_interval: "12h",
        parser: *one_range_per_line_semicolon_comments,
      },
      class: "reject",
    },
  },
}
```

Now we proceed to create the bootstrap and diff templates.
They will call the `ipset` command to insert or remove ranges from the sets created in the section above.

For the bootstrap template, create `/etc/drib/insert_ranges.sh.tpl` with the following content:

```
#!/bin/sh

{% for entry in ranges -%}
ipset add drib-{{entry.protocol}}-{{entry.class}} {{entry.range}}
{% endfor -%}
```

For the diff template, create `/etc/drib/manage_ranges.sh.tpl` with the content below.

```
#!/bin/sh

{% for entry in ipv4.remove -%}
ipset del drib-ipv4-{{entry.class}} {{entry.range}}
{% endfor -%}

{% for entry in ipv4.insert -%}
ipset add drib-ipv4-{{entry.class}} {{entry.range}}
{% endfor -%}

{% for entry in ipv6.remove -%}
ipset add drib-ipv6-{{entry.class}} {{entry.range}}
{% endfor -%}

{% for entry in ipv6.insert -%}
ipset del drib-ipv6-{{entry.class}} {{entry.range}}
{% endfor -%}
```

### Running Drib

We can finally run Drib.
Run the command below to generate the bootstrap scripts.

```sh
$ sudo drib bootstrap
```

This will generate two scripts, `/etc/drib/insert_ipv4_src_ranges.sh` and `/etc/drib/insert_ipv6_src_ranges.sh`, which can be used to populate the appropriate IP sets.

From this point on, the IP sets can be managed by Drib running on diff mode:

```sh
$ sudo drib diff
```

This will create a number of scripts, depending on the number of updates computed by Drib.
In the configuration above, we have limited the output to 1000 ranges per file, so Drib will generate as many files as necessary following the specified output naming pattern, i.e., `/etc/drib/manage_ranges.00.sh`, `/etc/drib/manage_ranges.01.sh` and so on.
