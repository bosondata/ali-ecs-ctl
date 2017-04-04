
#[derive(Debug, Deserialize, Clone)]
pub struct IpAddressSet {
    #[serde(rename = "IpAddress")]
    pub ip_address: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Instance {
    #[serde(rename = "InstanceId")]
    pub id: String,
    #[serde(rename = "InstanceName")]
    pub name: String,
    #[serde(rename = "PublicIpAddress")]
    pub public_ip_address: IpAddressSet,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InstanceMap {
    #[serde(rename = "Instance")]
    pub instance: Vec<Instance>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Instances {
    #[serde(rename = "Instances")]
    pub instances: InstanceMap,
    #[serde(rename = "TotalCount")]
    pub total: usize,
    #[serde(rename = "PageNumber")]
    pub page: usize,
    #[serde(rename = "PageSize")]
    pub size: usize,
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_deserialize_instances() {
        let json = r#"{
  "Instances": {
    "Instance": [
      {
        "CreationTime": "2015-07-27T07:08Z",
        "DeviceAvailable": true,
        "EipAddress": {},
        "ExpiredTime": "2011-09-08T16:00Z",
        "HostName": "iZ94t3s0jxkZ",
        "ImageId": "centos6u5_64_20G_aliaegis_20150130.vhd",
        "InnerIpAddress": {
          "IpAddress": [
            "10.170.106.80"
          ]
        },
        "InstanceChargeType": "PostPaid",
        "InstanceId": "i-94t3s0jxk",
        "InstanceName": "dd\u6027\u80fd\u6d4b\u8bd5",
        "InstanceNetworkType": "classic",
        "InstanceType": "ecs.s2.large",
        "InternetChargeType": "PayByTraffic",
        "InternetMaxBandwidthIn": -1,
        "InternetMaxBandwidthOut": 1,
        "IoOptimized": false,
        "OperationLocks": {
          "LockReason": []
        },
        "PublicIpAddress": {
          "IpAddress": [
            "120.25.13.106"
          ]
        },
        "RegionId": "cn-shenzhen",
        "SecurityGroupIds": {
          "SecurityGroupId": [
            "sg-94kd0cyg0"
          ]
        },
        "SerialNumber": "51d1353b-22bf-4567-a176-8b3e12e43135",
        "Status": "Running",
        "VpcAttributes": {
          "PrivateIpAddress": {
            "IpAddress": []
          }
        },
        "ZoneId": "cn-shenzhen-a"
      }
    ]
  },
  "PageNumber": 1,
  "PageSize": 10,
  "RequestId": "14A07460-EBE7-47CA-9757-12CC4761D47A",
  "TotalCount": 1
}"#;
        let instances = ::serde_json::from_str::<super::Instances>(json).unwrap();
        assert_eq!(instances.page, 1);
        assert_eq!(instances.size, 10);
        assert_eq!(instances.total, 1);
        assert_eq!(instances.instances.instance.len(), 1);
    }
}
