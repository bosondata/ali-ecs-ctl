use serde_json;
use reqwest;
use url;
use statsd;

error_chain! {
    errors {
        NoMonitorData(instance_id: String) {
            description("no monitor data")
            display("no monitor data for: '{}'", instance_id)
        }
    }

    foreign_links {
        Io(::std::io::Error);
        Json(serde_json::Error);
        Http(reqwest::Error);
        Url(url::ParseError);
        Statsd(statsd::client::StatsdError);
        ParseIntError(::std::num::ParseIntError);
    }
}
