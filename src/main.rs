extern crate reqwest;
extern crate rustc_serialize;
extern crate url;
extern crate chrono;
extern crate uuid;
extern crate clap;

mod hmac_sha1;

use std::io::Read;
use std::env;
use std::process::Command;
use rustc_serialize::json::Json;
use rustc_serialize::base64::{self, ToBase64};
use url::Url;
use url::percent_encoding::{utf8_percent_encode, USERINFO_ENCODE_SET};
use chrono::prelude::*;
use uuid::Uuid;
use hmac_sha1::hmac_sha1;
use clap::{Arg, App};

static ALIYUN_API: &'static str = "http://ecs-cn-hangzhou.aliyuncs.com";
static HTTP_GET: &'static str = "GET";

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
    let ts: &str = &UTC::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let access_key_id: &str = &env::var("ALIYUN_ACCESS_KEY_ID").unwrap();
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
    let secret_bytes = vec![env::var("ALIYUN_SECRET").unwrap(), "&".to_string()]
        .join("")
        .into_bytes();
    let signed = hmac_sha1(&secret_bytes, &sign_bytes).to_base64(base64::STANDARD);
    let mut signed_params: Vec<(String, String)> = params
        .iter()
        .map(|x| (x.0.to_string(), x.1.to_string()))
        .collect();
    signed_params.push(("Signature".to_string(), signed));
    return signed_params;
}

/*
fn describe_region() {
    let mut url = Url::parse(ALIYUN_API).unwrap();
    let params = signature(vec![
        ("Action".to_string(), "DescribeRegions".to_string()),
        ("RegionId".to_string(), "cn-hangzhou".to_string())]);
    url.query_pairs_mut().extend_pairs(params.into_iter());
    let client = reqwest::Client::new().unwrap();
    let mut text = String::new();
    let res = client.get(url)
        .send()
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    let data = Json::from_str(&text).unwrap();
    println!("{}", data);
}
 */

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
    return true;
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
    return true;
}

fn get_instances(verbose: bool) -> Vec<(String, String)> {
    let mut url = Url::parse(ALIYUN_API).unwrap();
    let params = signature(vec![("Action".to_string(), "DescribeInstances".to_string()),
                                // TODO: max return size is 100, need pagination if we use 100+ instances.
                                ("PageSize".to_string(), "100".to_string()),
                                ("RegionId".to_string(), "cn-beijing".to_string())]);
    url.query_pairs_mut().extend_pairs(params.into_iter());
    let client = reqwest::Client::new().unwrap();
    let mut text = String::new();
    client
        .get(url)
        .send()
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    let response = Json::from_str(&text).unwrap();
    let mut instance_info = vec![];
    let response_obj = response.as_object().unwrap();
    for instances in response_obj
            .get("Instances")
            .unwrap()
            .as_object()
            .unwrap()
            .get("Instance")
            .unwrap()
            .as_array()
            .iter() {
        for instance in instances.iter() {
            let instance_id = instance
                .as_object()
                .unwrap()
                .get("InstanceId")
                .unwrap()
                .as_string()
                .unwrap();
            let instance_name = instance
                .as_object()
                .unwrap()
                .get("InstanceName")
                .unwrap()
                .as_string()
                .unwrap();
            let instance_ip = instance
                .as_object()
                .unwrap()
                .get("PublicIpAddress")
                .unwrap()
                .as_object()
                .unwrap()
                .get("IpAddress")
                .unwrap()
                .as_array()
                .unwrap()
                .first()
                .unwrap()
                .as_string()
                .unwrap();
            if verbose == true {
                println!("Id: {} Name: {} Public IP: {}",
                         instance_id,
                         instance_name,
                         instance_ip,
                );
            }
            instance_info.push((instance_id.to_string(), instance_ip.to_string()));
        }
    }
    return instance_info;
}

fn reboot_instance(instance_id: &str) {
    let mut url = Url::parse(ALIYUN_API).unwrap();
    let params = signature(vec![("Action".to_string(), "RebootInstance".to_string()),
                                ("InstanceId".to_string(), instance_id.to_string()),
                                ("ForceStop".to_string(), "true".to_string())]);
    url.query_pairs_mut().extend_pairs(params.into_iter());
    let client = reqwest::Client::new().unwrap();
    let mut response_body = String::new();
    let mut res = client.get(url).send().unwrap();
    res.read_to_string(&mut response_body).unwrap();
    if res.status() == &reqwest::StatusCode::Ok {
        println!("Reboot request to {} sended!", instance_id);
    } else {
        println!("Reboot request fail with status {:?}", res.status());
    }
}

fn reboot_unresponded_instances(check_func: &Fn(&str) -> bool) {
    let instance_info = get_instances(false);
    let cnt = instance_info.len();
    let mut reboot_cnt = 0;
    for instance in instance_info {
        let (id, ip) = instance;
        if !check_func(&ip) {
            println!("{} no ping/ssh respond, sending reboot(force) request.", ip);
            reboot_instance(&id);
            reboot_cnt += 1;
        } else {
            println!("{} is OK.", ip);
        }
    }
    println!("{} instance(s) checked, {} rebooted.", cnt, reboot_cnt);
}

fn reboot_all() {
    let instance_info = get_instances(false);
    let cnt = instance_info.len();
    for instance in instance_info {
        let (id, _) = instance;
        reboot_instance(&id);
    }
    println!("{} instance(s) reboot(force) request sended!", cnt);
}

fn reboot_single(target_ip: &str) {
    for instance in get_instances(false) {
        let (id, ip) = instance;
        if ip == target_ip {
            reboot_instance(&id);
            return;
        }
    }
    println!("Instance with IP {} not found.", target_ip);
}

fn main() {
    let matches = App::new("Aliyun ECS Controller")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A cli tool for control(rebool only for now) Aliyun ECS instances.")
        .arg(Arg::with_name("COMMAND")
                 .help("command to run, choices: reboot/rebootall/list")
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
                    "ssh" => reboot_unresponded_instances(&is_ssh_timeout),
                    "ping" => reboot_unresponded_instances(&ping_ok),
                    _ => println!("Unknown checker."),
                }
            } else {
                reboot_single(ip);
            }
        }
        "rebootall" => {
            println!("Start reboot all nodes!");
            reboot_all()
        }
        "list" => {
            let _ = get_instances(true);
        }
        _ => println!("Unknown command."),
    }
}
