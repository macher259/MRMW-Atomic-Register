use std::sync::Arc;

use log::info;
use tokio::{net::TcpStream, sync::mpsc};

use crate::{
    serialize_register_command, Broadcast, RegisterClient, RegisterCommand, Send as MsgSend,
    SystemRegisterCommand,
};

pub async fn build_register_client(
    tcp_locations: Vec<(String, u16)>,
    self_rank: u8,
    hmac_system_key: [u8; 64],
    self_system_queues: Vec<mpsc::UnboundedSender<SystemRegisterCommand>>,
) -> Arc<dyn RegisterClient> {
    Arc::new(
        TCPBasedRegisterClient::new(
            tcp_locations,
            self_rank,
            hmac_system_key,
            self_system_queues,
        )
        .await,
    )
}

struct TCPBasedRegisterClient {
    tcp_locations: Vec<(String, u16)>,
    self_rank: u8,
    hmac_system_key: [u8; 64],
    self_system_queues: Vec<mpsc::UnboundedSender<SystemRegisterCommand>>,
}

#[async_trait::async_trait]
impl RegisterClient for TCPBasedRegisterClient {
    async fn send(&self, msg: MsgSend) {
        let target = msg.target - 1;

        if msg.target != self.self_rank {
            let stream = TcpStream::connect(&self.tcp_locations[target as usize]).await;
            if stream.is_err() {
                return;
            }
            let mut stream = stream.unwrap();

            let rv = serialize_register_command(
                &RegisterCommand::System((*msg.cmd).clone()),
                &mut stream,
                &self.hmac_system_key,
            )
            .await;
            if rv.is_err() {
                info!("Send error: {:?}", rv.unwrap_err());
            }
        } else {
            let n = self.self_system_queues.len();
            let sector_idx = msg.cmd.header.sector_idx as usize;
            self.self_system_queues[sector_idx % n]
                .send((*msg.cmd).clone())
                .unwrap();
        }
    }

    async fn broadcast(&self, msg: Broadcast) {
        for (i, _) in self.tcp_locations.iter().enumerate() {
            self.send(MsgSend {
                target: i as u8 + 1,
                cmd: msg.cmd.clone(),
            })
            .await;
        }
    }
}

impl TCPBasedRegisterClient {
    async fn new(
        tcp_locations: Vec<(String, u16)>,
        self_rank: u8,
        hmac_system_key: [u8; 64],
        self_system_queues: Vec<mpsc::UnboundedSender<SystemRegisterCommand>>,
    ) -> Self {
        Self {
            tcp_locations,
            self_rank,
            hmac_system_key,
            self_system_queues,
        }
    }
}
