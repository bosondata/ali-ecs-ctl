#![feature(lookup_host)]
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

use std::env;
use std::sync::{Arc, Mutex};
use std::process::Command;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::net::lookup_host;
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

struct AliyunECSController {
    access_key_id: String,
    secret: String,
    slack_webhook_url: Option<String>,
    statsd_url: Option<String>,
    client: reqwest::Client,
}

impl AliyunECSController {
    fn new(access_key_id: String,
           secret: String,
           slack_webhook_url: Option<String>,
           statsd_url: Option<String>)
           -> AliyunECSController {
        AliyunECSController {
            access_key_id: access_key_id,
            secret: secret,
            slack_webhook_url: slack_webhook_url,
            statsd_url: statsd_url,
            client: reqwest::Client::new().expect("Failed to init http client"),
        }
    }

    fn from_envvar() -> AliyunECSController {
        let access_key_id = env::var("ALIYUN_ACCESS_KEY_ID").expect("No ALIYUN_ACCESS_KEY_ID in env var");
        let secret = env::var("ALIYUN_SECRET").expect("No ALIYUN_SECRET in env var");
        let slack_webhook_url = env::var("SLACK_WEBHOOK_URL").ok();
        let statsd_url = env::var("STATSD_URL").ok();
        Self::new(access_key_id, secret, slack_webhook_url, statsd_url)
    }

    fn notify_on_slack(&self, message: &str) -> Result<()> {
        if let Some(ref slack_webhook_url) = self.slack_webhook_url {
            let body: HashMap<&str, &str> = [("text", message)].iter().cloned().collect();
            let _ = self.client
                .post(slack_webhook_url)?
                .json(&body)?
                .send()?;
        }
        Ok(())
    }

    fn send_statsd_metrics(&self, monitor_info: &[(String, rep::MonitorData)]) -> Result<()> {
        if let Some(ref statsd_url) = self.statsd_url {
            let parts: Vec<&str> = statsd_url.splitn(2, ":").collect();
            let hostname = parts[0];
            let port = parts[1];
            let mut first_addr = lookup_host(hostname)?.next().expect("DNS resolve failed");
            first_addr.set_port(u16::from_str_radix(port, 10)?);
            let mut client = StatsdClient::new(first_addr, "aliyun.monitor")?;
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

    fn signature<T>(&self, api_params: Vec<(T, T)>) -> Vec<(String, String)>
        where T: Into<String>
    {
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
        let ts: &str = &Utc::now().format(TIME_FORMAT).to_string();
        let mut params: Vec<(String, String)> = vec![("Timestamp", ts),
                                                     ("Format", "json"),
                                                     ("AccessKeyId", &self.access_key_id),
                                                     ("SignatureMethod", "HMAC-SHA1"),
                                                     ("SignatureNonce", uuid_str),
                                                     ("Version", "2014-05-26"),
                                                     ("SignatureVersion", "1.0")]
                .iter()
                .map(|x| (x.0.to_string(), x.1.to_string()))
                .collect();
        params.extend(api_params.into_iter().map(|x| (x.0.into(), x.1.into())));
        params.sort();
        let mut sign_params: Vec<String> = Vec::with_capacity(params.len());
        sign_params.extend(params
                               .iter()
                               .map(|param| vec![param.0.clone(), "=".to_string(), param.1.clone()].join("")));
        let string_to_sign = sign_params.join("&");
        let string_to_sign_percent_encoded = String::from_iter(utf8_percent_encode(&string_to_sign, USERINFO_ENCODE_SET));
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
        let secret_bytes = vec![self.secret.clone(), "&".to_string()]
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

    fn describe_monitor_data_by_instance(&self,
                                         instance_id: &str,
                                         start_time: &str,
                                         end_time: &str)
                                         -> Result<rep::MonitorData> {
        let mut url = Url::parse(ALIYUN_API)?;
        let params = self.signature(vec![("Action", "DescribeInstanceMonitorData"),
                                         ("InstanceId", instance_id),
                                         ("StartTime", start_time),
                                         ("EndTime", end_time)]);
        url.query_pairs_mut().extend_pairs(params.into_iter());
        let response = self.client
            .get(url)?
            .send()?
            .json::<rep::MonitorResponse>();
        response
            .map(|obj| obj.monitor_data.last().expect("No monitor data").clone())
            .chain_err(|| "error describing instance monitor data")
    }

    fn describe_monitor_data(&self) -> Result<()> {
        let current_time = Utc::now();
        let end_time = NaiveDateTime::from_timestamp(current_time.timestamp() - 30, 0);
        let start_time = NaiveDateTime::from_timestamp(current_time.timestamp() - 150, 0);
        let monitor_info = Arc::new(Mutex::new(Vec::new()));
        let pool = ThreadPool::new(num_cpus::get() * 5);
        let instances = self.get_instances()?;
        pool.scoped(|scope| {
            for instance in &instances {
                let monitor_info = monitor_info.clone();
                scope.execute(move || {
                    let monitor_data =
                        self.describe_monitor_data_by_instance(&instance.id,
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
        self.send_statsd_metrics(&monitor_info_list)?;
        Ok(())
    }

    fn describe_regions(&self) -> Result<()> {
        let mut url = Url::parse(ALIYUN_API)?;
        let params = self.signature(vec![("Action", "DescribeRegions"),
                                         ("RegionId", "cn-hangzhou")]);
        url.query_pairs_mut().extend_pairs(params.into_iter());
        let response = self.client.get(url)?.send()?.json::<rep::Regions>()?;
        for region in &response.regions {
            println!("{}\t{}", region.id, region.name);
        }
        Ok(())
    }

    fn get_instances(&self) -> Result<Vec<rep::Instance>> {
        let mut url = Url::parse(ALIYUN_API)?;
        let params = self.signature(vec![("Action", "DescribeInstances"),
                                         // TODO: max return size is 100, need pagination if we use 100+ instances.
                                         ("PageSize", "100"),
                                         ("RegionId", "cn-beijing")]);
        url.query_pairs_mut().extend_pairs(params.into_iter());
        let response = self.client
            .get(url)?
            .send()?
            .json::<rep::Instances>()?;
        Ok(response.instances)
    }

    fn get_instance_status(&self) -> Result<Vec<rep::InstanceStatus>> {
        let mut instance_statuses: Vec<rep::InstanceStatus> = Vec::new();
        let mut page = 1;
        loop {
            let mut url = Url::parse(ALIYUN_API)?;
            let page_str = page.to_string();
            let params = self.signature(vec![("Action", "DescribeInstanceStatus"),
                                             ("PageNumber", &page_str),
                                             ("PageSize", "50"),
                                             ("RegionId", "cn-beijing")]);
            url.query_pairs_mut().extend_pairs(params.into_iter());
            let partial_response = self.client
                .get(url)?
                .send()?
                .json::<rep::InstanceStatuses>()?;
            if partial_response.instance_statuses.is_empty() {
                break;
            }
            page += 1;
            instance_statuses.extend(partial_response.instance_statuses);
        }
        Ok(instance_statuses)
    }

    fn boot_instance(&self, instance_id: &str) -> Result<bool> {
        let mut url = Url::parse(ALIYUN_API)?;
        let params = self.signature(vec![("Action", "StartInstance"),
                                         ("InstanceId", instance_id)]);
        url.query_pairs_mut().extend_pairs(params.into_iter());
        let res = self.client.get(url)?.send()?;
        if res.status() == reqwest::StatusCode::Ok {
            println!("Boot request to {} sended!", instance_id);
            return Ok(true);
        } else {
            println!("Boot request fail with status {:?}", res.status());
        }
        Ok(false)
    }

    fn reboot_instance(&self, instance_id: &str) -> Result<bool> {
        let mut url = Url::parse(ALIYUN_API)?;
        let params = self.signature(vec![("Action", "RebootInstance"),
                                         ("InstanceId", instance_id),
                                         ("ForceStop", "true")]);
        url.query_pairs_mut().extend_pairs(params.into_iter());
        let res = self.client.get(url)?.send()?;
        if res.status() == reqwest::StatusCode::Ok {
            println!("Reboot request to {} sended!", instance_id);
            return Ok(true);
        } else {
            println!("Reboot request fail with status {:?}", res.status());
        }
        Ok(false)
    }

    fn reboot_unresponded_instances<F>(&self, check_func: &F, exclude_ips: HashSet<&str>) -> Result<()>
        where F: Fn(&str) -> bool,
              F: Sync + Send
    {
        let instance_info = self.get_instances()?;
        let cnt = instance_info.len();
        let rebooted_instances = Arc::new(Mutex::new(Vec::new()));
        let pool = ThreadPool::new(num_cpus::get() * 5);
        pool.scoped(|scope| {
            for instance in instance_info {
                let rebooted_instances = rebooted_instances.clone();
                let exclude_ips = exclude_ips.clone();
                scope.execute(move || {
                    let ip = instance.ip();
                    if exclude_ips.contains(ip) {
                        println!("Ignore {} because it's in exclude IPs", ip);
                    } else if !check_func(ip) {
                        println!("{} no ping/ssh respond, sending reboot(force) request.", ip);
                        let request_sended = self.reboot_instance(&instance.id).unwrap_or(false);
                        if request_sended {
                            let mut rebooted_instances = rebooted_instances.lock().unwrap();
                            rebooted_instances.push(ip.to_string());
                        } else {
                            println!("reboot failed, trying booting the instance {}", ip);
                            let boot_request_sended = self.boot_instance(&instance.id).unwrap_or(false);
                            if boot_request_sended {
                                let mut rebooted_instances = rebooted_instances.lock().unwrap();
                                rebooted_instances.push(ip.to_string());
                            }
                        }
                    } else {
                        println!("{} is OK.", ip);
                    }
                });
            }
        });
        let rebooted_instances = rebooted_instances.clone();
        let rebooted_instances = rebooted_instances.lock().unwrap();
        let mut msg = format!("{} instance(s) checked, {} (re)booted.",
                              cnt,
                              rebooted_instances.len());
        println!("{}", msg);
        if rebooted_instances.len() > 0 {
            msg = vec![msg, "Rebooted:".to_string(), rebooted_instances.join("\n")].join("\n");
            self.notify_on_slack(&msg)?;
        }
        Ok(())
    }

    fn reboot_all(&self) -> Result<()> {
        let instance_info = self.get_instances()?;
        let cnt = instance_info.len();
        let pool = ThreadPool::new(num_cpus::get() * 5);
        pool.scoped(|scope| {
            for instance in instance_info {
                scope.execute(move || { self.reboot_instance(&instance.id).unwrap_or(false); });
            }
        });
        let msg = format!("{} instance(s) reboot(force) request sended!", cnt);
        println!("{}", msg);
        self.notify_on_slack(&msg)?;
        Ok(())
    }

    fn reboot_single(&self, target_ip: &str) -> Result<()> {
        for instance in self.get_instances()? {
            if instance.ip() == target_ip {
                let request_sended = self.reboot_instance(&instance.id).unwrap_or(false);
                if request_sended {
                    self.notify_on_slack(&format!("reboot request for {} sended!", instance.ip()))?;
                }
                break;
            }
        }
        println!("Instance with IP {} not found.", target_ip);
        Ok(())
    }

    fn boot_single(&self, target_ip: &str) -> Result<()> {
        for instance in self.get_instances()? {
            if instance.ip() == target_ip {
                let request_sended = self.boot_instance(&instance.id).unwrap_or(false);
                if request_sended {
                    self.notify_on_slack(&format!("boot request for {} sended!", instance.ip()))?;
                }
                break;
            }
        }
        println!("Instance with IP {} not found.", target_ip);
        Ok(())
    }

}

fn show_monitor_data_table(monitor_info: &[(String, rep::MonitorData)]) {
    let mut table = Table::new();
    table.add_row(row!["IP",
                       "ID",
                       "CPU(%)",
                       "InternetRX(kb)",
                       "InternetTX(kb)",
                       "InternetBandwidth(kb/s)",
                       "IOPSRead/s",
                       "IOPSWrite/s"]);
    for info in monitor_info.iter() {
        table.add_row(Row::new(vec![Cell::new(&info.0),
                                    Cell::new(&info.1.instance_id),
                                    Cell::new(&info.1.cpu.to_string()),
                                    Cell::new(&info.1.internet_rx.to_string()),
                                    Cell::new(&info.1.internet_tx.to_string()),
                                    Cell::new(&info.1.internet_bandwidth.to_string()),
                                    Cell::new(&info.1.iops_read.to_string()),
                                    Cell::new(&info.1.iops_write.to_string())]));
    }
    table.printstd();
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
    result.find("100% packet loss").is_none()
}

fn is_ssh_ok(ip: &str) -> bool {
    let output = Command::new("ssh")
        .arg(ip)
        .arg("-o ConnectTimeout=5")
        .arg("-T")
        .output()
        .expect("failed to execute ssh");

    let result = String::from_utf8_lossy(&output.stderr);
    result.find("Connection timed out").is_none()
}

fn main() {
    let matches = App::new("Aliyun ECS Controller")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A cli tool for control(rebool only for now) Aliyun ECS instances.")
        .arg(Arg::with_name("COMMAND")
                 .help("command to run, choices: boot/reboot/rebootall/list/regions/monitor")
                 .required(true)
                 .index(1))
        .arg(Arg::with_name("checker")
                 .short("c")
                 .long("checker")
                 .value_name("checker")
                 .help("Method use to check instance availability, choices: ssh/ping")
                 .takes_value(true))
        .arg(Arg::with_name("exclude")
                 .short("x")
                 .long("exclude")
                 .value_name("exclude_ip")
                 .help("IP addresses which do not check availability, separate with comma")
                 .use_delimiter(true)
                 .takes_value(true))
        .arg(Arg::with_name("ip")
                 .long("ip")
                 .value_name("ip")
                 .help("Specify single instance IP to reboot")
                 .takes_value(true))
        .get_matches();
    let cmd = matches.value_of("COMMAND").unwrap();
    let ecs_ctl = AliyunECSController::from_envvar();
    match cmd {
        "boot" => {
            let ip = matches.value_of("ip").unwrap_or("");
            if ip != "" {
                ecs_ctl
                    .boot_single(ip)
                    .expect("Boot instance failed");
            } else {
                println!("Please provide instance IP.");
            }
        }
        "reboot" => {
            let checker = matches.value_of("checker").unwrap_or("ssh");
            let ip = matches.value_of("ip").unwrap_or("");
            let exclude_ips: HashSet<&str> = if matches.is_present("exclude") {
                HashSet::from_iter(
                    matches
                        .values_of("exclude")
                        .unwrap()
                        .collect::<Vec<&str>>()
                        .into_iter()
                )
            } else {
                HashSet::new()
            };
            if ip == "" {
                match checker {
                    "ssh" => {
                        ecs_ctl
                            .reboot_unresponded_instances(&is_ssh_ok, exclude_ips)
                            .expect("Reboot unresponded instances failed")
                    }
                    "ping" => {
                        ecs_ctl
                            .reboot_unresponded_instances(&ping_ok, exclude_ips)
                            .expect("Reboot unresponded instances failed")
                    }
                    _ => {
                        println!("Unknown checker.");
                    }
                }
            } else {
                ecs_ctl
                    .reboot_single(ip)
                    .expect("Reboot instance failed");
            }
        }
        "rebootall" => {
            println!("Start reboot all nodes!");
            ecs_ctl.reboot_all().expect("Reboot all nodes failed");
        }
        "list" => {
            let instance_status: HashMap<String, String> = ecs_ctl.get_instance_status().expect("Get instance status failed")
                .iter()
                .map(|instance| (instance.id.to_string(), instance.status.to_string()))
                .collect();
            for instance in &ecs_ctl.get_instances().expect("Get instances failed") {
                println!("Id: {} Name: {} Public IP: {} Status: {}",
                         instance.id,
                         instance.name,
                         instance.ip(),
                         instance_status.get(&instance.id.to_string()).unwrap_or(&"UNKNOWN".to_string()));
            }
        }
        "regions" => {
            ecs_ctl
                .describe_regions()
                .expect("Describe regions failed");
        }
        "monitor" => {
            ecs_ctl
                .describe_monitor_data()
                .expect("Describe monitor data failed");
        }
        _ => {
            println!("Unknown command.");
        }
    }
}
