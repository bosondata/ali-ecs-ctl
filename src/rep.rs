
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
pub struct Instances {
    #[serde(rename = "Instances")]
    pub instances: Vec<Instance>,
    #[serde(rename = "TotalCount")]
    pub total: usize,
    #[serde(rename = "PageNumber")]
    pub page: usize,
    #[serde(rename = "PageSize")]
    pub size: usize,
}
