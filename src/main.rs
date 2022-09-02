use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::prelude::*;
use std::net::IpAddr;
use std::collections::HashMap;

use strfmt;
use clap::Parser;
use regex::Regex;
use dns_lookup::lookup_addr;
use anyhow::{ Context, Result, bail };


type Stats = HashMap<String, u32>;

fn process_file(file: &mut impl Read, stats: &mut Stats, pattern: &Regex, key: usize, pedantic: bool, fixed_ips: bool) -> Result<()> {
    let mut line = String::new();
    let mut reader = BufReader::new(file);
    let key = key - 1;

    loop {
        match reader.read_line(&mut line).context("Reading next line")? {
            0 => { break }
            _bytes_read => {
                // Either use the line almost as-is, or apply the pattern to exract IPs
                let m = if fixed_ips {
                    Some(line.trim())
                } else if let Some(m) = pattern.find_iter(&line).nth(key) {
                    Some(m.as_str())
                } else {
                    None
                };

                // Either increment the counter for the IP or bail out if none was found and we are
                // running in pedantic mode.
                // We also Strip ::ffff: from the start of the collected IP since it is used to
                // express mappable addresses like ::ffff:192.168.1.1, which only seem to properly
                // resolve when the prefix is stripped, since we accept a custom regex we cannot
                // rely on the regex matching things the right way, so we always make sure we
                // strip that off the match
                if let Some(m) = m {
                    stats.entry(
                        m.to_string()
                            .strip_prefix("::ffff:")
                            .unwrap_or(&m.to_string())
                            .into()
                    )
                    .and_modify(|counter| *counter += 1)
                    .or_insert(1);
                } else if pedantic {
                    bail!("Could not extract IP from line: {:?}", line);
                }

                line.clear();
            }
        };
    }
    Ok(())
}

fn print_stats(stats: Stats, max_results: Option<usize>, numeric: bool, threshold: Option<u32>, format: &str) -> Result<()> {
    // If a threshold is passed, drop all values below threshold
    let mut sorted: Vec<_> = if let Some(threshold) = threshold {
        stats.iter().filter(|v| v.1 > &threshold).collect()
    } else {
        stats.iter().collect()
    };

    // Sort by count
    sorted.sort_by_key(|n| n.1);

    // Apply limit if `max_results` is passed, not sure what is the
    // best method here, but since `take` seems to express what
    // we actually want to do, we need to `rev` the vec twice
    // to cut off the correct portion of elements, there is probably
    // a better when if you know what you're doing. :-(
    let sorted: Vec<_> = if let Some(max_results) = max_results {
        sorted.iter().rev().take(max_results).rev().collect()
    } else {
        sorted.iter().collect()
    };

    // Runtime format print all elements, optionally lookup the hostnames
    for (key, value) in sorted.iter() {
        let mut vars: HashMap<String, String> = HashMap::new();
        vars.insert("cnt".to_string(), value.to_string());
        vars.insert("ip".to_string(), key.to_string());
        if ! numeric {
            let ip: IpAddr = key.parse().with_context(|| format!("Could not parse IP: {key}"))?;
            let host = lookup_addr(&ip).with_context(|| format!("Could not lookup host for IP: {key}"))?;
            vars.insert("host".to_string(), host.clone());
        }
        println!("{}", strfmt::strfmt(&format, &vars).context("Error while formatting record")?);
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Files to scan for IPs, otherwise stdin is used
    files: Vec<String>,

    /// Limit the number of results to show
    #[clap(long, short)]
    max_results: Option<usize>,

    /// Do not do any host lookups
    #[clap(long, short)]
    numeric: bool,

    /// If multiple IPs per line are found, use the Nth hit, starts at 1
    #[clap(long, short, default_value_t = 1)]
    key: usize,

    /// Only show IPs with at least this many occurences
    #[clap(long, short)]
    threshold: Option<u32>,

    /// Bail out as soon as we hit a line without any IP in it
    #[clap(long)]
    pedantic: bool,

    /// Provide a custom regex pattern to match the IP
    #[clap(long, short)]
    pattern: Option<String>,

    /// Assume the line contains a single IP without anything else in it
    #[clap(long)]
    fixed_ips: bool,

    /// Custom format to use for printing statistics, used once per IP, may contain {host}, {ip} and {cnt}
    #[clap(long, short)]
    format: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let pattern = Regex::new(
        &args.pattern.unwrap_or(
            String::from(r"((::ffff:)(?:[0-9]{1,3}\.){3}[0-9]{1,3})|((([0-9a-f]{1,4}:){7}([0-9a-f]{1,4}|:))|(([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9a-f]{1,4}:){5}(((:[0-9a-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9a-f]{1,4}:){4}(((:[0-9a-f]{1,4}){1,3})|((:[0-9a-f]{1,4})?:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9a-f]{1,4}:){3}(((:[0-9a-f]{1,4}){1,4})|((:[0-9a-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9a-f]{1,4}:){2}(((:[0-9a-f]{1,4}){1,5})|((:[0-9a-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9a-f]{1,4}:){1}(((:[0-9a-f]{1,4}){1,6})|((:[0-9a-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(:(((:[0-9a-f]{1,4}){1,7})|((:[0-9a-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)))(%.+)?"),
        )
    ).context("Could not compile regex")?;

    let format = if let Some(format) = args.format {
        // Since formatting may use {host} with more formatting prarameters, our check should probably be a bit smarter
        if args.numeric && format.contains("{host}") {
            bail!("You cannot use {{host}} in the format string and pass --numeric at the same time")
        }
        format
    } else if args.numeric {
        String::from("{cnt} {ip}")
    } else {
        String::from("{cnt} {host} ({ip})")
    };

    let mut stats = Stats::new();

    if args.files.is_empty() {
        process_file(
            &mut io::stdin(),
            &mut stats,
            &pattern,
            args.key,
            args.pedantic,
            args.fixed_ips,
        ).context("Failed processing stdin")?;

        print_stats(
            stats,
            args.max_results,
            args.numeric,
            args.threshold,
            &format,
        ).context("Failed printing stats")?;
    } else {
        for path in args.files {
            let mut file = File::open(&path).context(format!("Could not open file: {path}"))?;
            process_file(
                &mut file,
                &mut stats,
                &pattern,
                args.key,
                args.pedantic,
                args.fixed_ips,
            ).context(format!("Failed processing file: {path}"))?;

        }

        print_stats(
            stats,
            args.max_results,
            args.numeric,
            args.threshold,
            &format,
        ).context("Failed printing stats")?;
    }
    Ok(())
}
