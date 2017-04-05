use std::fmt;
use std::marker::PhantomData;
use serde::de::{self, Deserialize, Deserializer};

#[derive(Debug, Deserialize, Clone)]
pub struct Instance {
    #[serde(rename = "InstanceId")]
    pub id: String,
    #[serde(rename = "InstanceName")]
    pub name: String,
    #[serde(deserialize_with = "deserialize_single_key_map")]
    #[serde(rename = "PublicIpAddress")]
    pub public_ip_address: Vec<String>,
}

impl Instance {
    pub fn ip(&self) -> &str {
        &self.public_ip_address[0]
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Instances {
    #[serde(deserialize_with = "deserialize_single_key_map")]
    #[serde(rename = "Instances")]
    pub instances: Vec<Instance>,
    #[serde(rename = "TotalCount")]
    pub total: usize,
    #[serde(rename = "PageNumber")]
    pub page: usize,
    #[serde(rename = "PageSize")]
    pub size: usize,
}

fn deserialize_single_key_map<V, D>(d: D) -> Result<V, D::Error>
    where D: Deserializer,
          V: Deserialize
{
    struct SingleKeyMapToVecVisitor<V: Deserialize>(PhantomData<V>);

    impl<V> de::Visitor for SingleKeyMapToVecVisitor<V>
        where V: Deserialize
    {
        type Value = V;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map")
        }

        #[inline]
        fn visit_map<T>(self, mut visitor: T) -> Result<V, T::Error>
            where T: de::MapVisitor
        {
            let item: Option<(String, V)> = visitor.visit()?;
            if let Some((_, value)) = item {
                return Ok(value);
            }
            Err(de::Error::custom("No single key value in map"))
        }
    }
    d.deserialize_map(SingleKeyMapToVecVisitor(PhantomData))
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
        assert_eq!(instances.instances.len(), 1);
        let instance = &instances.instances[0];
        assert_eq!(instance.id, "i-94t3s0jxk");
        assert_eq!(instance.ip(), "120.25.13.106");
    }
}
