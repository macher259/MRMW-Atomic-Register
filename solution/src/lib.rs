mod atomic_register;
mod communication;
mod domain;
mod register_client;
mod sectors;
mod stable_storage;

use std::sync::Arc;

pub use crate::domain::*;
pub use atomic_register_public::*;
use communication::Encoder;
use log::error;
use register_client::build_register_client;
pub use register_client_public::*;
pub use sectors_manager_public::*;
use stable_storage::build_stable_storage;
pub use stable_storage_public::*;
use tokio::{
    fs::create_dir_all,
    io::{AsyncWrite, AsyncWriteExt},
    net::{tcp::OwnedWriteHalf, TcpListener},
    spawn,
    sync::{mpsc, Mutex, Notify},
};
pub use transfer_public::*;

const MAX_NUM_OF_REGISTERS: usize = 256;

#[derive(Debug)]
struct ClientReply {
    op_return: OperationReturn,
    status_code: StatusCode,
    request_number: u64,
}

pub async fn run_register_process(config: Configuration) {
    let register_num = std::cmp::min(
        MAX_NUM_OF_REGISTERS,
        std::cmp::max(1, config.public.n_sectors as usize / 20),
    );
    let self_address = &config.public.tcp_locations[config.public.self_rank as usize - 1];
    let listener = TcpListener::bind(self_address)
        .await
        .expect("Couldn't bind self address");

    let base_path = &config.public.storage_dir;
    let sectors_path = base_path.join("sectors");
    create_dir_all(&sectors_path).await.unwrap();

    let mut system_senders = Vec::with_capacity(register_num);
    let mut system_receivers = Vec::with_capacity(register_num);
    for _i in 0..register_num {
        let (system_sender, system_receiver) = mpsc::unbounded_channel();
        system_senders.push(system_sender);
        system_receivers.push(system_receiver);
    }

    let sectors_manager = build_sectors_manager(sectors_path.clone()).await;
    let register_client = build_register_client(
        config.public.tcp_locations.clone(),
        config.public.self_rank,
        config.hmac_system_key,
        system_senders.clone(),
    )
    .await;

    let mut client_senders = Vec::with_capacity(register_num);

    let metadata_path = config.public.storage_dir.join("metadata");
    create_dir_all(&metadata_path).await.unwrap();
    for system_receiver in system_receivers {
        let stable_storage = build_stable_storage(metadata_path.clone()).await;

        let register = build_atomic_register(
            config.public.self_rank,
            stable_storage,
            register_client.clone(),
            sectors_manager.clone(),
            config.public.tcp_locations.len() as u8,
        )
        .await;
        let (client_sender, client_receiver) = mpsc::unbounded_channel();
        client_senders.push(client_sender);

        let register = Arc::new(Mutex::const_new(register));
        spawn(process_system_messages(system_receiver, register.clone()));
        spawn(process_client_messages(client_receiver, register.clone()));
    }

    listen_for_connections(
        listener,
        config.hmac_system_key,
        config.hmac_client_key,
        register_num,
        client_senders,
        system_senders,
        config.public.n_sectors,
    )
    .await;
}

async fn listen_for_connections(
    listener: TcpListener,
    hmac_system_key: [u8; 64],
    hmac_client_key: [u8; 32],
    register_num: usize,
    client_queue: Vec<
        mpsc::UnboundedSender<(
            ClientRegisterCommand,
            Arc<mpsc::UnboundedSender<ClientReply>>,
        )>,
    >,
    system_queue: Vec<mpsc::UnboundedSender<SystemRegisterCommand>>,
    n_sectors: u64,
) {
    let client_queue_arc = Arc::new(client_queue);
    let system_queue_arc = Arc::new(system_queue);
    loop {
        let cq = client_queue_arc.clone();
        let sq = system_queue_arc.clone();
        let (stream, _address) = listener.accept().await.unwrap();
        let (mut read, write) = stream.into_split();

        let (tx, rx) = mpsc::unbounded_channel();
        spawn(reply_to_client_messages(
            write,
            rx,
            hmac_client_key.to_vec(),
        ));

        let tx = Arc::new(tx);

        spawn(async move {
            loop {
                let msg =
                    deserialize_register_command(&mut read, &hmac_system_key, &hmac_client_key)
                        .await;
                if msg.is_err() {
                    return;
                }
                let (cmd, is_hmac_valid) = msg.unwrap();

                match cmd {
                    RegisterCommand::Client(cmd) if is_hmac_valid => {
                        if cmd.header.sector_idx >= n_sectors {
                            let op_return = match cmd.content {
                                ClientRegisterCommandContent::Read => {
                                    OperationReturn::Read(ReadReturn {
                                        read_data: SectorVec(Vec::new()),
                                    })
                                }
                                ClientRegisterCommandContent::Write { .. } => {
                                    OperationReturn::Write
                                }
                            };
                            let _ = tx.send(ClientReply {
                                op_return,
                                status_code: StatusCode::InvalidSectorIndex,
                                request_number: cmd.header.request_identifier,
                            });
                        } else {
                            let rank = cmd.header.sector_idx as usize % register_num;
                            let sender = &cq[rank];
                            sender.send((cmd, tx.clone())).unwrap();
                        }
                    }
                    RegisterCommand::Client(cmd) => {
                        // Invalid hmac
                        let op_return = match cmd.content {
                            ClientRegisterCommandContent::Read => {
                                OperationReturn::Read(ReadReturn {
                                    read_data: SectorVec(Vec::new()),
                                })
                            }
                            ClientRegisterCommandContent::Write { .. } => OperationReturn::Write,
                        };
                        let _ = tx.send(ClientReply {
                            op_return,
                            status_code: StatusCode::AuthFailure,
                            request_number: cmd.header.request_identifier,
                        });
                    }
                    RegisterCommand::System(cmd) if is_hmac_valid => {
                        let rank = cmd.header.sector_idx as usize % register_num;
                        let sender = &sq[rank];
                        sender.send(cmd).unwrap();
                    }
                    _ => {}
                }
            }
        });
    }
}

async fn reply_to_client_messages(
    mut write: OwnedWriteHalf,
    mut receiver: mpsc::UnboundedReceiver<ClientReply>,
    hmac_client_key: Vec<u8>,
) {
    loop {
        let reply = receiver.recv().await;
        if reply.is_none() {
            return;
        }
        let reply = reply.unwrap();

        let ClientReply {
            op_return,
            status_code,
            request_number,
        } = reply;

        send_reply(
            op_return,
            status_code,
            request_number,
            &mut write,
            hmac_client_key.clone(),
        )
        .await;
    }
}

async fn process_system_messages(
    mut system_queue: mpsc::UnboundedReceiver<SystemRegisterCommand>,
    register: Arc<Mutex<Box<dyn AtomicRegister>>>,
) {
    loop {
        let cmd = system_queue.recv().await;
        if cmd.is_none() {
            return;
        }

        let cmd = cmd.unwrap();
        let mut register_lock = register.lock().await;
        register_lock.system_command(cmd).await;
    }
}

async fn process_client_messages(
    mut client_queue: mpsc::UnboundedReceiver<(
        ClientRegisterCommand,
        Arc<mpsc::UnboundedSender<ClientReply>>,
    )>,
    register: Arc<Mutex<Box<dyn AtomicRegister>>>,
) {
    loop {
        let val = client_queue.recv().await;
        if val.is_none() {
            return;
        }
        let (cmd, sender) = val.unwrap();

        let mut register_lock = register.lock().await;
        let notifier = Arc::new(Notify::const_new());
        let notifier_clone = notifier.clone();
        register_lock
            .client_command(
                cmd,
                Box::new(|op| {
                    let reply = ClientReply {
                        op_return: op.op_return,
                        status_code: StatusCode::Ok,
                        request_number: op.request_identifier,
                    };
                    Box::pin(async move {
                        let x = sender.send(reply);
                        if x.is_err() {
                            error!("{}", x.unwrap_err());
                        }
                        notifier_clone.notify_one();
                    })
                }),
            )
            .await;
        drop(register_lock);
        notifier.notified().await;
    }
}

async fn send_reply(
    op_return: OperationReturn,
    status_code: StatusCode,
    reguest_number: u64,
    mut stream: (impl AsyncWrite + std::marker::Send + Unpin),
    hmac_client_key: Vec<u8>,
) {
    let mut encoder = Encoder::new();
    encoder.add_magic_numbers();
    encoder.add_reply_status_code(status_code);
    encoder.add_reply_msg_type(&op_return);
    encoder.add_reply_request_number(reguest_number);
    encoder.add_reply_content(op_return);
    encoder.add_hmac_tag(&hmac_client_key);

    let msg = encoder.build();
    let x = stream.write_all(&msg).await;
    if x.is_err() {
        error!("SEND REPLY ERROR: {:?}", x);
    }
}

pub mod atomic_register_public {
    use crate::atomic_register::MRMWAtomicRegister;
    use crate::{
        ClientRegisterCommand, OperationSuccess, RegisterClient, SectorsManager, StableStorage,
        SystemRegisterCommand,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    #[async_trait::async_trait]
    pub trait AtomicRegister: Send + Sync {
        /// Handle a client command. After the command is completed, we expect
        /// callback to be called. Note that completion of client command happens after
        /// delivery of multiple system commands to the register, as the algorithm specifies.
        ///
        /// This function corresponds to the handlers of Read and Write events in the
        /// (N,N)-AtomicRegister algorithm.
        async fn client_command(
            &mut self,
            cmd: ClientRegisterCommand,
            success_callback: Box<
                dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output = ()> + Send>>
                    + Send
                    + Sync,
            >,
        );

        /// Handle a system command.
        ///
        /// This function corresponds to the handlers of READ_PROC, VALUE, WRITE_PROC
        /// and ACK messages in the (N,N)-AtomicRegister algorithm.
        async fn system_command(&mut self, cmd: SystemRegisterCommand);
    }

    /// Idents are numbered starting at 1 (up to the number of processes in the system).
    /// Storage for atomic register algorithm data is separated into StableStorage.
    /// Communication with other processes of the system is to be done by register_client.
    /// And sectors must be stored in the sectors_manager instance.
    ///
    /// This function corresponds to the handlers of Init and Recovery events in the
    /// (N,N)-AtomicRegister algorithm.
    pub async fn build_atomic_register(
        self_ident: u8,
        metadata: Box<dyn StableStorage>,
        register_client: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        processes_count: u8,
    ) -> Box<dyn AtomicRegister> {
        Box::new(
            MRMWAtomicRegister::new(
                self_ident,
                metadata,
                register_client,
                sectors_manager,
                processes_count,
            )
            .await,
        )
    }
}

pub mod sectors_manager_public {
    use crate::sectors::FileBasedSectorsManager;
    use crate::{SectorIdx, SectorVec};
    use std::path::PathBuf;
    use std::sync::Arc;

    #[async_trait::async_trait]
    pub trait SectorsManager: Send + Sync {
        /// Returns 4096 bytes of sector data by index.
        async fn read_data(&self, idx: SectorIdx) -> SectorVec;

        /// Returns timestamp and write rank of the process which has saved this data.
        /// Timestamps and ranks are relevant for atomic register algorithm, and are described
        /// there.
        async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8);

        /// Writes a new data, along with timestamp and write rank to some sector.
        async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8));
    }

    /// Path parameter points to a directory to which this method has exclusive access.
    pub async fn build_sectors_manager(path: PathBuf) -> Arc<dyn SectorsManager> {
        Arc::new(FileBasedSectorsManager::new(path).await)
    }
}

pub mod transfer_public {
    use crate::communication::*;
    use crate::{
        ClientCommandHeader, ClientRegisterCommand, RegisterCommand, SystemCommandHeader,
        SystemRegisterCommand,
    };
    use std::io::Error;
    use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

    #[inline]
    async fn deserialize_client_command<'a>(
        decoder: &mut Decoder<'a>,
        msg_type: ClientMsgType,
        hmac_client_key: &[u8; 32],
    ) -> io::Result<(ClientRegisterCommand, bool)> {
        let request_number = decoder.read_request_number().await?;
        let sector_index = decoder.read_sector_index().await?;
        let content = decoder.read_client_message_content(msg_type).await?;

        let is_tag_valid = decoder.validate_hmac_tag(hmac_client_key).await?;

        let header = ClientCommandHeader {
            request_identifier: request_number,
            sector_idx: sector_index,
        };
        let client_command = ClientRegisterCommand { header, content };
        Ok((client_command, is_tag_valid))
    }

    #[inline]
    async fn deserialize_system_command<'a>(
        decoder: &mut Decoder<'a>,
        msg_type: SystemMsgType,
        hmac_system_key: &[u8; 64],
    ) -> io::Result<(SystemRegisterCommand, bool)> {
        let process_rank = match msg_type {
            SystemMsgType::ReadProc(pr) => pr,
            SystemMsgType::Value(pr) => pr,
            SystemMsgType::WriteProc(pr) => pr,
            SystemMsgType::Ack(pr) => pr,
        };
        let msg_ident = decoder.read_system_msg_ident().await?;
        let read_ident = decoder.read_system_read_ident().await?;
        let sectod_index = decoder.read_sector_index().await?;

        let header = SystemCommandHeader {
            process_identifier: process_rank,
            msg_ident,
            read_ident,
            sector_idx: sectod_index,
        };
        let content = decoder.read_system_msg_content(msg_type).await?;

        let is_tag_valid = decoder.validate_hmac_tag(hmac_system_key).await?;
        Ok((SystemRegisterCommand { header, content }, is_tag_valid))
    }

    pub async fn deserialize_register_command(
        data: &mut (dyn AsyncRead + Send + Unpin),
        hmac_system_key: &[u8; 64],
        hmac_client_key: &[u8; 32],
    ) -> Result<(RegisterCommand, bool), Error> {
        let mut decoder = Decoder::new(data);
        let mut msg_type = None;

        while msg_type.is_none() {
            decoder.clear_buffer();
            decoder.read_magic_numbers().await?;
            msg_type = decoder.read_msg_type().await?;
        }

        let result = match msg_type.unwrap() {
            MsgType::Client(msg_type) => {
                let (client_command, is_tag_valid) =
                    deserialize_client_command(&mut decoder, msg_type, hmac_client_key).await?;
                (RegisterCommand::Client(client_command), is_tag_valid)
            }
            MsgType::System(msg_type) => {
                let (system_command, is_tag_valid) =
                    deserialize_system_command(&mut decoder, msg_type, hmac_system_key).await?;
                (RegisterCommand::System(system_command), is_tag_valid)
            }
        };

        Ok(result)
    }

    #[inline]
    fn serialize_client_command(cmd: &ClientRegisterCommand, encoder: &mut Encoder) {
        let ClientRegisterCommand { header, content } = cmd;
        encoder.add_client_msg_type(content);
        encoder.add_client_request_number(header);
        encoder.add_client_sector_index(header);
        encoder.add_client_content(content);
    }

    #[inline]
    fn serialize_system_command(cmd: &SystemRegisterCommand, encoder: &mut Encoder) {
        let SystemRegisterCommand { header, content } = cmd;
        encoder.add_system_msg_type(header.process_identifier, content);
        encoder.add_system_msg_ident(header);
        encoder.add_system_read_ident(header);
        encoder.add_system_sector_index(header);
        encoder.add_system_msg_content(content);
    }

    pub async fn serialize_register_command(
        cmd: &RegisterCommand,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
        hmac_key: &[u8],
    ) -> Result<(), Error> {
        let mut encoder = Encoder::new();
        encoder.add_magic_numbers();

        match cmd {
            RegisterCommand::Client(cmd) => serialize_client_command(cmd, &mut encoder),
            RegisterCommand::System(cmd) => serialize_system_command(cmd, &mut encoder),
        };

        encoder.add_hmac_tag(hmac_key);

        writer.write_all(&encoder.build()).await?;

        Ok(())
    }
}

pub mod register_client_public {
    use crate::SystemRegisterCommand;
    use std::sync::Arc;

    #[async_trait::async_trait]
    /// We do not need any public implementation of this trait. It is there for use
    /// in AtomicRegister. In our opinion it is a safe bet to say some structure of
    /// this kind must appear in your solution.
    pub trait RegisterClient: core::marker::Send + core::marker::Sync {
        /// Sends a system message to a single process.
        async fn send(&self, msg: Send);

        /// Broadcasts a system message to all processes in the system, including self.
        async fn broadcast(&self, msg: Broadcast);
    }

    #[derive(Clone)]
    pub struct Broadcast {
        pub cmd: Arc<SystemRegisterCommand>,
    }

    pub struct Send {
        pub cmd: Arc<SystemRegisterCommand>,
        /// Identifier of the target process. Those start at 1.
        pub target: u8,
    }
}

pub mod stable_storage_public {
    #[async_trait::async_trait]
    /// A helper trait for small amount of durable metadata needed by the register algorithm
    /// itself. Again, it is only for AtomicRegister definition. StableStorage in unit tests
    /// is durable, as one could expect.
    pub trait StableStorage: Send + Sync {
        async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String>;

        async fn get(&self, key: &str) -> Option<Vec<u8>>;

        async fn remove(&mut self, key: &str) -> bool;
    }
}
