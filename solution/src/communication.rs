use bytes::BufMut;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::Result;
use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

use crate::ClientCommandHeader;
use crate::ClientRegisterCommandContent;
use crate::OperationReturn;
use crate::ReadReturn;
use crate::SectorIdx;
use crate::StatusCode;
use crate::{SectorVec, SystemCommandHeader, SystemRegisterCommandContent, MAGIC_NUMBER};

type BinaryBuffer = Vec<u8>;
type HmacSha256 = Hmac<Sha256>;

const REGISTER_SIZE: usize = 4096;

fn calculate_hmac_tag(message: &BinaryBuffer, secret_key: &[u8]) -> [u8; 32] {
    // Initialize a new MAC instance from the secret key:
    let mut mac = HmacSha256::new_from_slice(secret_key).unwrap();

    // Calculate MAC for the data (one can provide it in multiple portions):
    mac.update(message);

    // Finalize the computations of MAC and obtain the resulting tag:
    let tag = mac.finalize().into_bytes();

    tag.into()
}

fn verify_hmac_tag(tag: &[u8], message: &[u8], secret_key: &[u8]) -> bool {
    // Initialize a new MAC instance from the secret key:
    let mut mac = HmacSha256::new_from_slice(secret_key).unwrap();

    // Calculate MAC for the data (one can provide it in multiple portions):
    mac.update(message);

    // Verify the tag:
    mac.verify_slice(tag).is_ok()
}

pub enum ClientMsgType {
    Read,
    Write,
}

pub enum SystemMsgType {
    ReadProc(u8),
    Value(u8),
    WriteProc(u8),
    Ack(u8),
}

pub enum MsgType {
    Client(ClientMsgType),
    System(SystemMsgType),
}

pub struct Encoder {
    buffer: BinaryBuffer,
}

impl Encoder {
    const INITIAL_CAPACITY: usize = 128;

    #[inline]
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(Self::INITIAL_CAPACITY),
        }
    }

    #[inline]
    pub fn add_magic_numbers(&mut self) {
        self.buffer.extend_from_slice(&MAGIC_NUMBER);
    }

    #[inline]
    fn get_client_msg_type(content: &ClientRegisterCommandContent) -> u8 {
        match content {
            ClientRegisterCommandContent::Read => 0x01,
            ClientRegisterCommandContent::Write { .. } => 0x02,
        }
    }

    #[inline]
    pub fn add_client_msg_type(&mut self, content: &ClientRegisterCommandContent) {
        const PADDING: [u8; 3] = [0; 3];
        self.buffer.extend(PADDING);
        self.buffer.put_u8(Self::get_client_msg_type(content));
    }

    #[inline]
    fn get_system_msg_type(content: &SystemRegisterCommandContent) -> u8 {
        match content {
            SystemRegisterCommandContent::ReadProc => 0x03,
            SystemRegisterCommandContent::Value { .. } => 0x04,
            SystemRegisterCommandContent::WriteProc { .. } => 0x05,
            SystemRegisterCommandContent::Ack => 0x06,
        }
    }

    #[inline]
    pub fn add_client_request_number(&mut self, header: &ClientCommandHeader) {
        self.buffer.extend(header.request_identifier.to_be_bytes());
    }

    #[inline]
    pub fn add_client_sector_index(&mut self, header: &ClientCommandHeader) {
        self.buffer.extend(header.sector_idx.to_be_bytes());
    }

    #[inline]
    pub fn add_client_content(&mut self, content: &ClientRegisterCommandContent) {
        match content {
            ClientRegisterCommandContent::Read => {}
            ClientRegisterCommandContent::Write {
                data: SectorVec(content),
            } => {
                self.buffer.extend(content);
            }
        }
    }

    #[inline]
    pub fn add_system_msg_type(&mut self, rank: u8, content: &SystemRegisterCommandContent) {
        const PADDING: [u8; 2] = [0; 2];
        self.buffer.extend_from_slice(&PADDING);
        self.buffer.push(rank);
        self.buffer.push(Self::get_system_msg_type(content));
    }

    #[inline]
    pub fn add_system_msg_ident(&mut self, header: &SystemCommandHeader) {
        self.buffer.extend_from_slice(header.msg_ident.as_bytes());
    }

    #[inline]
    pub fn add_system_read_ident(&mut self, header: &SystemCommandHeader) {
        self.buffer.extend(header.read_ident.to_be_bytes());
    }

    #[inline]
    pub fn add_system_sector_index(&mut self, header: &SystemCommandHeader) {
        self.buffer.extend(header.sector_idx.to_be_bytes());
    }

    #[inline]
    pub fn add_system_msg_content(&mut self, content: &SystemRegisterCommandContent) {
        match content {
            SystemRegisterCommandContent::Value {
                timestamp,
                write_rank,
                sector_data: SectorVec(data),
            } => {
                self.buffer.extend(timestamp.to_be_bytes());
                self.buffer.extend(vec![0u8; 7]);
                self.buffer.push(*write_rank);
                self.buffer.extend_from_slice(data);
            }
            SystemRegisterCommandContent::WriteProc {
                timestamp,
                write_rank,
                data_to_write: SectorVec(data),
            } => {
                self.buffer.extend(timestamp.to_be_bytes());
                self.buffer.extend(vec![0u8; 7]);
                self.buffer.push(*write_rank);
                self.buffer.extend_from_slice(data);
            }
            _ => {}
        }
    }

    #[inline]
    pub fn add_hmac_tag(&mut self, system_key: &[u8]) {
        let hmac = calculate_hmac_tag(&self.buffer, system_key);
        self.buffer.extend(hmac);
    }

    #[inline]
    pub fn add_reply_status_code(&mut self, status_code: StatusCode) {
        self.buffer.extend([0u8; 2]);
        self.buffer.put_u8(status_code as u8);
    }

    #[inline]
    pub fn add_reply_msg_type(&mut self, op: &OperationReturn) {
        self.buffer.put_u8(match op {
            OperationReturn::Read(_) => 0x41,
            OperationReturn::Write => 0x42,
        });
    }

    #[inline]
    pub fn add_reply_request_number(&mut self, request_num: u64) {
        self.buffer.put_u64(request_num);
    }

    #[inline]
    pub fn add_reply_content(&mut self, op: OperationReturn) {
        match op {
            OperationReturn::Read(ReadReturn {
                read_data: SectorVec(data),
            }) => self.buffer.extend(data),
            OperationReturn::Write => {}
        }
    }

    #[inline]
    pub fn build(self) -> BinaryBuffer {
        self.buffer
    }
}

pub struct Decoder<'a> {
    data: &'a mut (dyn AsyncRead + Send + Unpin),
    buffer: BinaryBuffer,
}

impl<'a> Decoder<'a> {
    #[inline]
    pub fn new(data: &'a mut (dyn AsyncRead + Send + Unpin)) -> Self {
        const INITIAL_CAPACITY: usize = 256;
        Self {
            data,
            buffer: BinaryBuffer::with_capacity(INITIAL_CAPACITY),
        }
    }

    #[inline]
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
    }

    #[inline]
    pub async fn read_magic_numbers(&mut self) -> Result<()> {
        let mut n_bytes_matched = 0;
        let mut buffer = [0u8; 4];

        while n_bytes_matched != MAGIC_NUMBER.len() {
            self.data.read_exact(&mut buffer[n_bytes_matched..]).await?;
            for byte in &buffer {
                if *byte == MAGIC_NUMBER[n_bytes_matched] {
                    n_bytes_matched += 1;
                } else {
                    n_bytes_matched = 0;
                    break;
                }
            }
        }

        self.buffer.extend_from_slice(&MAGIC_NUMBER);

        Ok(())
    }

    #[inline]
    pub async fn read_request_number(&mut self) -> Result<u64> {
        let request_num = self.data.read_u64().await?;
        self.buffer.put_u64(request_num);

        Ok(request_num)
    }

    #[inline]
    pub async fn read_sector_index(&mut self) -> Result<SectorIdx> {
        let sector_index = self.data.read_u64().await?;
        self.buffer.put_u64(sector_index);

        Ok(sector_index)
    }

    #[inline]
    pub async fn read_client_message_content(
        &mut self,
        msg_type: ClientMsgType,
    ) -> Result<ClientRegisterCommandContent> {
        let content = match msg_type {
            ClientMsgType::Read => ClientRegisterCommandContent::Read,
            ClientMsgType::Write => {
                let mut buffer = vec![0u8; REGISTER_SIZE];
                self.data.read_exact(&mut buffer).await?;
                self.buffer.extend_from_slice(&buffer);
                ClientRegisterCommandContent::Write {
                    data: SectorVec(buffer),
                }
            }
        };

        Ok(content)
    }

    #[inline]
    pub async fn validate_hmac_tag(&mut self, secret_key: &[u8]) -> Result<bool> {
        let mut buffer = [0u8; 32];
        self.data.read_exact(&mut buffer).await?;

        let is_valid = verify_hmac_tag(&buffer, &self.buffer, secret_key);
        Ok(is_valid)
    }

    #[inline]
    pub async fn read_msg_type(&mut self) -> Result<Option<MsgType>> {
        let mut buffer = [0u8; 4];
        self.data.read_exact(&mut buffer).await?;

        let msg_type_byte = buffer[3];
        let eventual_pr = buffer[2];

        let msg_type = match msg_type_byte {
            0x01 => Some(MsgType::Client(ClientMsgType::Read)),
            0x02 => Some(MsgType::Client(ClientMsgType::Write)),
            0x03 => Some(MsgType::System(SystemMsgType::ReadProc(eventual_pr))),
            0x04 => Some(MsgType::System(SystemMsgType::Value(eventual_pr))),
            0x05 => Some(MsgType::System(SystemMsgType::WriteProc(eventual_pr))),
            0x06 => Some(MsgType::System(SystemMsgType::Ack(eventual_pr))),
            _ => None,
        };

        self.buffer.extend(buffer);
        Ok(msg_type)
    }

    #[inline]
    pub async fn read_system_msg_ident(&mut self) -> Result<Uuid> {
        let mut buffer = [0u8; 16];
        self.data.read_exact(&mut buffer).await?;
        self.buffer.extend_from_slice(&buffer);

        Ok(Uuid::from_bytes(buffer))
    }

    #[inline]
    pub async fn read_system_read_ident(&mut self) -> Result<u64> {
        let read_ident = self.data.read_u64().await?;
        self.buffer.put_u64(read_ident);

        Ok(read_ident)
    }

    #[inline]
    pub async fn read_system_msg_content(
        &mut self,
        msg_type: SystemMsgType,
    ) -> Result<SystemRegisterCommandContent> {
        let content = match msg_type {
            SystemMsgType::ReadProc(_) => SystemRegisterCommandContent::ReadProc,
            SystemMsgType::Value(_) => {
                let timestamp = self.data.read_u64().await?;
                self.buffer.put_u64(timestamp);
                let mut padding = [0u8; 7];
                self.data.read_exact(&mut padding).await?;
                self.buffer.extend(padding);
                let write_rank = self.data.read_u8().await?;
                self.buffer.put_u8(write_rank);
                let mut buffer = [0u8; REGISTER_SIZE];
                self.data.read_exact(&mut buffer).await?;
                self.buffer.extend_from_slice(&buffer);
                SystemRegisterCommandContent::Value {
                    timestamp,
                    write_rank,
                    sector_data: SectorVec(buffer.to_vec()),
                }
            }
            SystemMsgType::WriteProc(_) => {
                let timestamp = self.data.read_u64().await?;
                self.buffer.put_u64(timestamp);
                let mut padding = [0u8; 7];
                self.data.read_exact(&mut padding).await?;
                self.buffer.extend(padding);
                let write_rank = self.data.read_u8().await?;
                self.buffer.put_u8(write_rank);
                let mut buffer = [0u8; REGISTER_SIZE];
                self.data.read_exact(&mut buffer).await?;
                self.buffer.extend_from_slice(&buffer);
                SystemRegisterCommandContent::WriteProc {
                    timestamp,
                    write_rank,
                    data_to_write: SectorVec(buffer.to_vec()),
                }
            }
            SystemMsgType::Ack(_) => SystemRegisterCommandContent::Ack,
        };

        Ok(content)
    }
}
