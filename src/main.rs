#![recursion_limit = "1024"]

extern crate reqwest;
extern crate url;
extern crate chrono;
extern crate uuid;
extern crate clap;
extern crate base64;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate hmacsha1;
extern crate scoped_pool;
extern crate num_cpus;
#[macro_use]
extern crate prettytable;
extern crate statsd;
#[macro_use]
extern crate error_chain;

mod errors;
mod rep;

use std::io::Read;
use std::env;
use std::sync::{Arc, Mutex};
use std::process::Command;
use std::collections::HashMap;
use std::iter::FromIterator;
use url::Url;
use url::percent_encoding::{utf8_percent_encode, USERINFO_ENCODE_SET};
use chrono::prelude::*;
use uuid::Uuid;
use hmacsha1::hmac_sha1;
use clap::{Arg, App};
use scoped_pool::Pool as ThreadPool;
use prettytable::Table;
use prettytable::row::Row;
use prettytable::cell::Cell;
use statsd::Client as StatsdClient;

use errors::*;

static ALIYUN_API: &'static str = "http://ecs-cn-hangzhou.aliyuncs.com";
static TIME_FORMAT: &'static str = "%Y-%m-%dT%H:%M:%SZ";
static HTTP_GET: &'static str = "GET";

fn notify_on_slack(message: &str) -> Result<()> {
    if let Ok(slack_webhook_url) = env::var("SLACK_WEBHOOK_URL") {
        let body: HashMap<&str, &str> = [("text", message)].iter().cloned().collect();
        let client = reqwest::Client::new()?;
        let _ = client.post(&slack_webhook_url)
            .json(&body)
            .send()
            .map_err(|_| ErrorKind::StatsdError)?;
    }
    Ok(())
}

fn signature(api_params: Vec<(String, String)>) -> Vec<(String, String)> {
    /*
    Aliyun API basic params sample:
    http://ecs.aliyuncs.com/?
    TimeStamp=2016-02-23T12:46:24Z
    Format=XML
    AccessKeyId=testid
    Action=DescribeRegions
    SignatureMethod=HMAC-SHA1
    SignatureNonce=3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf
    Version=2014-05-26
    SignatureVersion=1.0
     */
    let uuid_str: &str = &Uuid::new_v4().hyphenated().to_string();
    let ts: &str = &UTC::now().format(TIME_FORMAT).to_string();
    let access_key_id: &str = &env::var("ALIYUN_ACCESS_KEY_ID").expect("No ALIYUN_ACCESS_KEY_ID env var");
    let mut params: Vec<(String, String)> = vec![("Timestamp", ts),
                                                 ("Format", "json"),
                                                 ("AccessKeyId", access_key_id),
                                                 ("SignatureMethod", "HMAC-SHA1"),
                                                 ("SignatureNonce", uuid_str),
                                                 ("Version", "2014-05-26"),
                                                 ("SignatureVersion", "1.0")]
            .iter()
            .map(|x| (x.0.to_string(), x.1.to_string()))
            .collect();
    params.extend(api_params);
    params.sort();
    let mut sign_params: Vec<String> = Vec::with_capacity(params.len());
    sign_params.extend(params
                           .iter()
                           .map(|param| vec![param.0.clone(), "=".to_string(), param.1.clone()].join("")));
    let string_to_sign = sign_params.join("&");
    let mut string_to_sign_percent_encoded = String::new();
    string_to_sign_percent_encoded.extend(utf8_percent_encode(&string_to_sign, USERINFO_ENCODE_SET));
    let sign_bytes = vec![HTTP_GET.to_string(),
                          "&%2F&".to_string(),
                          string_to_sign_percent_encoded
                              .replace("*", "%2A")
                              .replace("+", "%20")
                              .replace("%7E", "~")
                              .replace("&", "%26")
                              .replace("%3A", "%253A")]
            .join("")
            .into_bytes();
    let secret_bytes = vec![env::var("ALIYUN_SECRET").expect("No ALIYUN_SECRET env var"), "&".to_string()]
        .join("")
        .into_bytes();
    let signed = base64::encode(&hmac_sha1(&secret_bytes, &sign_bytes));
    let mut signed_params: Vec<(String, String)> = params
        .iter()
        .map(|x| (x.0.to_string(), x.1.to_string()))
        .collect();
    signed_params.push(("Signature".to_string(), signed));
    signed_params
}

fn describe_monitor_data_by_instance(instance_id: &str, start_time: &str, end_time: &str) -> Result<rep::MonitorData> {
    let mut url = Url::parse(ALIYUN_API)?;
    let params = signature(vec![
        ("Action".to_string(), "DescribeInstanceMonitorData".to_string()),
        ("InstanceId".to_string(), instance_id.to_string()),
        ("StartTime".to_string(), start_time.to_string()),
        ("EndTime".to_string(), end_time.to_string())]);
    url.query_pairs_mut().extend_pairs(params.into_iter());
    let client = reqwest::Client::new()?;
    let response = client.get(url)
        .send()?
        .json::<rep::MonitorResponse>();
    response.map(|obj| obj.monitor_data.last().expect("No monitor data").clone())
        .chain_err(|| "error describing instance monitor data")
}

fn send_statsd_metrics(monitor_info: &[(String, rep::MonitorData)]) -> Result<()> {
    //TODO: Only IP address supported in STATSD_URL
    if let Ok(statsd_url) = env::var("STATSD_URL") {
        let mut client = StatsdClient::new(&statsd_url, "aliyun.monitor")?;
        let mut pipe = client.pipeline();
        for info in monitor_info.iter() {
            let ip = info.0.replace(".", "_");
            pipe.gauge(&format!("{}.cpu", ip), info.1.cpu as f64);
            pipe.gauge(&format!("{}.internet_rx", ip), info.1.internet_rx as f64);
            pipe.gauge(&format!("{}.internet_tx", ip), info.1.internet_tx as f64);
            pipe.gauge(&format!("{}.internet_bandwidth", ip), info.1.internet_bandwidth as f64);
            pipe.gauge(&format!("{}.intranet_rx", ip), info.1.intranet_rx as f64);
            pipe.gauge(&format!("{}.intranet_tx", ip), info.1.intranet_tx as f64);
            pipe.gauge(&format!("{}.intranet_bandwidth", ip), info.1.intranet_bandwidth as f64);
            pipe.gauge(&format!("{}.iops_read", ip), info.1.iops_read as f64);
            pipe.gauge(&format!("{}.iops_write", ip), info.1.iops_write as f64);
            pipe.gauge(&format!("{}.bps_read", ip), info.1.bps_read as f64);
            pipe.gauge(&format!("{}.bps_write", ip), info.1.bps_write as f64);
        }
        pipe.send(&mut client);
    }
    Ok(())
}

fn show_monitor_data_table(monitor_info: &[(String, rep::MonitorData)]) {
    let mut table = Table::new();
    table.add_row(row!["IP", "ID", "CPU(%)", "InternetRX(kb)", "InternetTX(kb)", "InternetBandwidth(kb/s)", "IOPSRead/s", "IOPSWrite/s"]);
    for info in monitor_info.iter() {
        table.add_row(
            Row::new(vec![Cell::new(&info.0),
                          Cell::new(&info.1.instance_id),
                          Cell::new(&info.1.cpu.to_string()),
                          Cell::new(&info.1.internet_rx.to_string()),
                          Cell::new(&info.1.internet_tx.to_string()),
                          Cell::new(&info.1.internet_bandwidth.to_string()),
                          Cell::new(&info.1.iops_read.to_string()),
                          Cell::new(&info.1.iops_write.to_string()),
            ]));
    }
    table.printstd();
}

fn describe_monitor_data() -> Result<()> {
    let current_time = UTC::now();
    let end_time = NaiveDateTime::from_timestamp(current_time.timestamp() - 30, 0);
    let start_time = NaiveDateTime::from_timestamp(current_time.timestamp() - 150, 0);
    let monitor_info = Arc::new(Mutex::new(Vec::new()));
    let pool = ThreadPool::new(num_cpus::get() * 5);
    let instances = get_instances()?;
    pool.scoped(|scope| {
        for instance in &instances {
            let monitor_info = monitor_info.clone();
            scope.execute(move || {
                let monitor_data = describe_monitor_data_by_instance(
                    &instance.id,
                    &start_time.format(TIME_FORMAT).to_string(),
                    &end_time.format(TIME_FORMAT).to_string());
                if monitor_data.is_ok() {
                    let mut monitor_info = monitor_info.lock().unwrap();
                    monitor_info.push((instance.ip().to_string(), monitor_data.unwrap()));
                }
            });
        }
    });
    let monitor_info = monitor_info.clone();
    let monitor_info = monitor_info.lock().unwrap();
    let monitor_info_list = Vec::from_iter(monitor_info.clone().into_iter());
    // TODO need sort by a certain key (IP/CPU/IO)
    show_monitor_data_table(&monitor_info_list);
    send_statsd_metrics(&monitor_info_list)?;
    Ok(())
}

fn describe_regions() -> Result<()> {
    let mut url = Url::parse(ALIYUN_API)?;
    let params = signature(vec![
        ("Action".to_string(), "DescribeRegions".to_string()),
        ("RegionId".to_string(), "cn-hangzhou".to_string())]);
    url.query_pairs_mut().extend_pairs(params.into_iter());
    let client = reqwest::Client::new()?;
    let response = client.get(url)
        .send()?
        .json::<rep::Regions>()?;
    for region in &response.regions {
        println!("{}\t{}", region.id, region.name);
    }
    Ok(())
}

fn ping_ok(ip: &str) -> bool {
    let output = Command::new("ping")
        .arg(ip)
        .arg("-c 3")
        .arg("-i 1")
        .arg("-W 1")
        .output()
        .expect("failed to execute ping");
    let result = String::from_utf8_lossy(&output.stdout);
    // TODO: OS & ping version awareness
    if result.find("100% packet loss").is_some() {
        return false;
    }
    true
}

fn is_ssh_timeout(ip: &str) -> bool {
    let output = Command::new("ssh")
        .arg(ip)
        .arg("-o ConnectTimeout=5")
        .arg("-T")
        .output()
        .expect("failed to execute ping");

    let result = String::from_utf8_lossy(&output.stderr);
    if result.find("Connection timed out").is_some() {
        return false;
    }
    true
}

fn get_instances() -> Result<Vec<rep::Instance>> {
    let mut url = Url::parse(ALIYUN_API)?;
    let params = signature(vec![("Action".to_string(), "DescribeInstances".to_string()),
                                // TODO: max return size is 100, need pagination if we use 100+ instances.
                                ("PageSize".to_string(), "100".to_string()),
                                ("RegionId".to_string(), "cn-beijing".to_string())]);
    url.query_pairs_mut().extend_pairs(params.into_iter());
    let client = reqwest::Client::new()?;
    let response = client
        .get(url)
        .send()?
        .json::<rep::Instances>()?;
    Ok(response.instances)
}

fn reboot_instance(instance_id: &str) -> Result<bool> {
    let mut url = Url::parse(ALIYUN_API)?;
    let params = signature(vec![("Action".to_string(), "RebootInstance".to_string()),
                                ("InstanceId".to_string(), instance_id.to_string()),
                                ("ForceStop".to_string(), "true".to_string())]);
    url.query_pairs_mut().extend_pairs(params.into_iter());
    let client = reqwest::Client::new()?;
    let mut response_body = String::new();
    let mut res = client.get(url).send()?;
    res.read_to_string(&mut response_body)?;
    if *res.status() == reqwest::StatusCode::Ok {
        println!("Reboot request to {} sended!", instance_id);
        return Ok(true);
    } else {
        println!("Reboot request fail with status {:?}", res.status());
    }
    Ok(false)
}

fn reboot_unresponded_instances<F>(check_func: &F) -> Result<()>
    where F: Fn(&str) -> bool,
          F: Sync + Send
{
    let instance_info = get_instances()?;
    let cnt = instance_info.len();
    let rebooted_instances = Arc::new(Mutex::new(Vec::new()));
    let pool = ThreadPool::new(num_cpus::get() * 5);
    pool.scoped(|scope| {
        for instance in instance_info {
            let rebooted_instances = rebooted_instances.clone();
            scope.execute(move || {
                let ip = instance.ip();
                if !check_func(ip) {
                    println!("{} no ping/ssh respond, sending reboot(force) request.", ip);
                    let request_sended = reboot_instance(&instance.id).unwrap_or(false);
                    if request_sended {
                        let mut rebooted_instances = rebooted_instances.lock().unwrap();
                        rebooted_instances.push(ip.to_string());
                    }
                } else {
                    println!("{} is OK.", ip);
                }
            });
        }
    });
    let rebooted_instances = rebooted_instances.clone();
    let rebooted_instances = rebooted_instances.lock().unwrap();
    let mut msg = format!("{} instance(s) checked, {} rebooted.", cnt, rebooted_instances.len());
    println!("{}", msg);
    if rebooted_instances.len() > 0 {
        msg = vec![msg, "Rebooted:".to_string(), rebooted_instances.join("\n")].join("\n");
        notify_on_slack(&msg)?;
    }
    Ok(())
}

fn reboot_all() -> Result<()> {
    let instance_info = get_instances()?;
    let cnt = instance_info.len();
    let pool = ThreadPool::new(num_cpus::get() * 5);
    pool.scoped(|scope| {
        for instance in instance_info {
            scope.execute(move || {
                reboot_instance(&instance.id).unwrap_or(false);
            });
        }
    });
    let msg = format!("{} instance(s) reboot(force) request sended!", cnt);
    println!("{}", msg);
    notify_on_slack(&msg)?;
    Ok(())
}

fn reboot_single(target_ip: &str) -> Result<()> {
    for instance in get_instances()? {
        if instance.ip() == target_ip {
            let request_sended = reboot_instance(&instance.id).unwrap_or(false);
            if request_sended {
                notify_on_slack(&format!("reboot request for {} sended!", instance.ip()))?;
            }
            break;
        }
    }
    println!("Instance with IP {} not found.", target_ip);
    Ok(())
}

fn main() {
    let matches = App::new("Aliyun ECS Controller")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A cli tool for control(rebool only for now) Aliyun ECS instances.")
        .arg(Arg::with_name("COMMAND")
                 .help("command to run, choices: reboot/rebootall/list/regions/monitor")
                 .required(true)
                 .index(1))
        .arg(Arg::with_name("checker")
                 .short("c")
                 .long("checker")
                 .value_name("checker")
                 .help("Method use to check instance availability, choices: ssh/ping")
                 .takes_value(true))
        .arg(Arg::with_name("ip")
                 .long("ip")
                 .value_name("ip")
                 .help("Specify single instance IP to reboot")
                 .takes_value(true))
        .get_matches();
    let cmd = matches.value_of("COMMAND").unwrap();
    match cmd {
        "reboot" => {
            let checker = matches.value_of("checker").unwrap_or("ssh");
            let ip = matches.value_of("ip").unwrap_or("");
            if ip == "" {
                match checker {
                    "ssh" => reboot_unresponded_instances(&is_ssh_timeout).expect("Reboot unresponded instances failed"),
                    "ping" => reboot_unresponded_instances(&ping_ok).expect("Reboot unresponded instances failed"),
                    _ => { println!("Unknown checker."); },
                }
            } else {
                reboot_single(ip).expect("Reboot instance failed");
            }
        }
        "rebootall" => {
            println!("Start reboot all nodes!");
            reboot_all().expect("Reboot all nodes failed");
        }
        "list" => {
            for instance in &get_instances().expect("Get instances failed") {
                println!("Id: {} Name: {} Public IP: {}",
                            instance.id,
                            instance.name,
                            instance.ip()
                );
            }
        }
        "regions" => {
            describe_regions().expect("Describe regions failed");
        }
        "monitor" => {
            describe_monitor_data().expect("Describe monitor data failed");
        }
        _ => {
            println!("Unknown command.");
        },
    }
}
