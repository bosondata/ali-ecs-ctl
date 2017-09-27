use serde_json;
use reqwest;
use url;
use statsd;

error_chain! {
    foreign_links {
        Io(::std::io::Error);
        Json(serde_json::Error);
        Http(reqwest::Error);
        Url(url::ParseError);
        Statsd(statsd::client::StatsdError);
        ParseIntError(::std::num::ParseIntError);
    }
}
