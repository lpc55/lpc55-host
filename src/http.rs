use core::convert::TryFrom;
use std::io;

use tiny_http as http;

use crate::bootloader;
use crate::error::Error;


#[derive(Clone, Debug)]
pub struct HttpConfig {
    pub addr: String,
    pub port: u16,
    pub timeout_ms: u64,
}

pub const DEFAULT_TIMEOUT_MILLISECONDS: u64 = 5000;

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_owned(),
            port: 2020,
            timeout_ms: DEFAULT_TIMEOUT_MILLISECONDS,
        }
    }
}

pub struct Server {
    config: HttpConfig,
    server: http::Server,
    bootloader: bootloader::Bootloader,
}

impl Server {

    pub fn new(config: &HttpConfig, bootloader: bootloader::Bootloader) -> Result<Server, Error> {

        let server = http::Server::http(format!("{}:{}", &config.addr, config.port))
            .map_err(|e| anyhow::format_err!("couldn't create HTTP server: {}", e))?;

        Ok(Self {
            config: config.clone(),
            server,
            bootloader,
        })

    }

    pub fn run(&self) -> Result<(), Error> {
        info!("Server({:?}) run", &self.config);
        loop {
            self.handle_request()?;
        }
    }

    pub fn handle_request(&self) -> Result<(), Error> {
        let /*mut*/ request = self.server.recv()?;

        let response = match *request.method() {
            http::Method::Get => match request.url() {
                "/" => Some(self.status()?),
                "/pfr" => Some(self.pfr()?),
                "/status" => Some(self.status()?),
                _ => None,
            }
            http::Method::Post => match request.url() {
                // "/api" => Some(self.api(&mut request)?),
                _ => None,
            }
            _ => None,
        }
        .unwrap_or_else(|| {
            http::Response::new(
                http::StatusCode::from(404),
                vec![],
                io::Cursor::new(vec![]),
                None,
                None,
            )
        });

        request.respond(response)?;
        Ok(())
    }

    fn pfr(&self) -> Result<http::Response<io::Cursor<Vec<u8>>>, Error> {
        info!("lpc55::http[{:04x}:{:04x}, {}:{}]: GET /pfr",
            &self.bootloader.vid, &self.bootloader.pid,
            &self.config.addr, &self.config.port,
        );
        let data = self.bootloader.read_memory(0x9_DE00, 7*512);
        let pfr = crate::pfr::ProtectedFlash::try_from(&data[..]).unwrap();
        let json = serde_json::to_string_pretty(&pfr).unwrap();

        Ok(http::Response::from_string(json))
    }

    fn status(&self) -> Result<http::Response<io::Cursor<Vec<u8>>>, Error> {
        info!("lpc55::http[{:04x}:{:04x}, {}:{}]: GET /status",
            &self.bootloader.vid, &self.bootloader.pid,
            &self.config.addr, &self.config.port,
        );

        let status = [
            ("status", "OK"),
            ("address", &self.config.addr),
            ("port", &self.config.port.to_string()),
            ("vid", &self.bootloader.vid.to_string()),
            ("pid", &self.bootloader.pid.to_string()),
        ];

        let body = status
            .iter()
            .map(|(k, v)| [*k, *v].join("\n"))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(http::Response::from_string(body))
    }
}
