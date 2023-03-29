use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use log::trace;
use tokio::{join, spawn, sync::Mutex, time::sleep};
use uuid::Uuid;

use crate::{
    AtomicRegister, Broadcast, ClientCommandHeader, ClientRegisterCommand,
    ClientRegisterCommandContent, OperationReturn, OperationSuccess, ReadReturn, RegisterClient,
    SectorVec, SectorsManager, Send as MsgSend, StableStorage, SystemCommandHeader,
    SystemRegisterCommand, SystemRegisterCommandContent,
};

type ClientCallback =
    Box<dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

#[derive(PartialEq, Eq)]
enum ClientOperation {
    Reading,
    Writing,
}
pub struct MRMWAtomicRegister {
    uuid: Uuid,     // Id of this object to avoid conflicts for metadata
    self_ident: u8, // Id of process
    metadata: Box<dyn StableStorage>,
    register_client: Arc<dyn RegisterClient>,
    sectors_manager: Arc<dyn SectorsManager>,
    processes_count: u8,
    current_client_callback: Option<ClientCallback>,
    current_client_identifier: Option<u64>,
    read_id: u64,
    operation: Option<ClientOperation>,
    read_list: Vec<Option<()>>,
    ack_list: Vec<Option<()>>,
    write_phase: bool,
    write_val: Option<SectorVec>,
    read_val: Option<SectorVec>,
    max_metadata: Option<(u64, u8)>, // highest pair (timestamp, rank)
    last_broadcast: Arc<Mutex<Option<Broadcast>>>,
}

#[async_trait::async_trait]
impl AtomicRegister for MRMWAtomicRegister {
    async fn client_command(
        &mut self,
        cmd: ClientRegisterCommand,
        success_callback: Box<
            dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
        >,
    ) {
        let ClientRegisterCommand { header, content } = &cmd;

        self.current_client_callback = Some(success_callback);
        self.current_client_identifier = Some(header.request_identifier);
        self.read_list.fill_with(Default::default);
        self.ack_list.fill_with(Default::default);
        self.max_metadata = None;

        self.update_state().await;

        self.handle_client_msg(header).await;

        match content {
            ClientRegisterCommandContent::Read => self.operation = Some(ClientOperation::Reading),
            ClientRegisterCommandContent::Write { data } => {
                self.write_val = Some(data.clone());
                self.operation = Some(ClientOperation::Writing)
            }
        };
    }

    async fn system_command(&mut self, cmd: SystemRegisterCommand) {
        let SystemRegisterCommand { header, content } = cmd;
        match content {
            SystemRegisterCommandContent::ReadProc => {
                trace!("{} READ_PROC: {:?}", self.self_ident, &header);
                self.handle_system_read_proc(&header).await;
            }
            SystemRegisterCommandContent::Value {
                timestamp,
                write_rank,
                sector_data,
            } => {
                trace!("{} VALUE: {:?}", self.self_ident, &header);
                self.handle_system_value(&header, timestamp, write_rank, sector_data)
                    .await;
            }
            SystemRegisterCommandContent::WriteProc {
                timestamp,
                write_rank,
                data_to_write,
            } => {
                trace!("{} WRITE_PROC: {:?}", self.self_ident, &header);
                self.handle_write_proc(header, timestamp, write_rank, data_to_write)
                    .await;
            }
            SystemRegisterCommandContent::Ack => {
                trace!("{} ACK: {:?}", self.self_ident, &header);
                self.handle_ack(&header).await;
            }
        };
    }
}

impl MRMWAtomicRegister {
    #[inline]
    pub async fn new(
        self_ident: u8,
        metadata: Box<dyn StableStorage>,
        register_client: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        processes_count: u8,
    ) -> Self {
        let n = processes_count as usize;
        let last_broadcast = Arc::new(Mutex::const_new(None));
        spawn(Self::rebroadcast(
            last_broadcast.clone(),
            register_client.clone(),
        ));
        let mut register = Self {
            uuid: Uuid::new_v4(),
            self_ident,
            metadata,
            register_client,
            sectors_manager,
            processes_count,
            read_id: 0,
            current_client_callback: None,
            current_client_identifier: None,
            operation: None,
            read_list: vec![None; n],
            ack_list: vec![None; n],
            write_phase: false,
            write_val: None,
            max_metadata: None,
            read_val: None,
            last_broadcast,
        };

        let rid = register.retrieve_state().await;
        register.read_id = rid;

        register
    }

    async fn rebroadcast(
        last_broadcast: Arc<Mutex<Option<Broadcast>>>,
        register_client: Arc<dyn RegisterClient>,
    ) {
        loop {
            sleep(Duration::from_secs(2)).await;
            let lock = last_broadcast.lock().await;
            if let Some(msg) = lock.clone() {
                register_client.broadcast(msg).await;
            }
        }
    }
    #[inline(always)]
    fn construct_new_system_header(&self, header: &SystemCommandHeader) -> SystemCommandHeader {
        SystemCommandHeader {
            process_identifier: self.self_ident,
            msg_ident: header.msg_ident,
            read_ident: header.read_ident,
            sector_idx: header.sector_idx,
        }
    }

    #[inline(always)]
    fn get_rid_key(&self) -> String {
        format!("{:X}_{}_{}", self.uuid, self.self_ident, self.read_id)
    }

    #[inline]
    async fn update_state(&mut self) {
        let old_rid_key = self.get_rid_key();
        self.read_id += 1;
        let rid_key = self.get_rid_key();

        self.metadata
            .put(&rid_key, &self.read_id.to_be_bytes())
            .await
            .unwrap();

        self.metadata.remove(&old_rid_key).await;
    }

    #[inline]
    async fn retrieve_state(&mut self) -> u64 {
        let rid_key = self.get_rid_key();

        let value = self
            .metadata
            .get(&rid_key)
            .await
            .map(|val| u64::from_be_bytes(val.as_slice().try_into().unwrap()));

        value.unwrap_or_default()
    }

    #[inline]
    async fn handle_client_msg(&mut self, client_header: &ClientCommandHeader) {
        let header = SystemCommandHeader {
            process_identifier: self.self_ident,
            msg_ident: Uuid::new_v4(),
            read_ident: self.read_id,
            sector_idx: client_header.sector_idx,
        };
        let content = SystemRegisterCommandContent::ReadProc;
        let cmd = Arc::new(SystemRegisterCommand { header, content });
        let broadcast = Broadcast { cmd };
        let mut lock = self.last_broadcast.lock().await;
        *lock = Some(broadcast.clone());
        drop(lock);
        self.register_client.broadcast(broadcast).await;
    }

    #[inline]
    async fn handle_system_read_proc(&mut self, msg_header: &SystemCommandHeader) {
        let target = msg_header.process_identifier;

        let header = self.construct_new_system_header(msg_header);

        let ((timestamp, write_rank), sector_data) = join!(
            self.sectors_manager.read_metadata(msg_header.sector_idx),
            self.sectors_manager.read_data(msg_header.sector_idx)
        );

        let content = SystemRegisterCommandContent::Value {
            timestamp,
            write_rank,
            sector_data,
        };

        let cmd = Arc::new(SystemRegisterCommand { header, content });
        self.register_client.send(MsgSend { cmd, target }).await;
    }

    #[inline]
    async fn handle_system_value(
        &mut self,
        msg_header: &SystemCommandHeader,
        timestamp: u64,
        write_rank: u8,
        sector_data: SectorVec,
    ) {
        if self.read_id == msg_header.read_ident && !self.write_phase {
            let q = msg_header.process_identifier as usize - 1;

            if self.read_list[q].is_none() {
                self.read_list[q] = Some(());
            }

            if self
                .max_metadata
                .filter(|x| *x > (timestamp, write_rank))
                .is_none()
            {
                self.max_metadata = Some((timestamp, write_rank));
                self.read_val = Some(sector_data);
            }

            if self.read_list.iter().flatten().count() as u8 > self.processes_count / 2
                && self.operation.is_some()
            {
                let local_metadata = self
                    .sectors_manager
                    .read_metadata(msg_header.sector_idx)
                    .await;

                if self.max_metadata.filter(|x| *x < local_metadata).is_some() {
                    self.max_metadata = Some(local_metadata);

                    self.read_val =
                        Some(self.sectors_manager.read_data(msg_header.sector_idx).await);
                }

                let mut lock = self.last_broadcast.lock().await;
                if self.operation == Some(ClientOperation::Reading) {
                    let data = self.read_val.clone().unwrap_or(SectorVec(Vec::new()));

                    let header = self.construct_new_system_header(msg_header);

                    let content = SystemRegisterCommandContent::WriteProc {
                        timestamp,
                        write_rank,
                        data_to_write: data,
                    };
                    let cmd = Arc::new(SystemRegisterCommand { header, content });
                    let broadcast = Broadcast { cmd };
                    self.register_client.broadcast(broadcast.clone()).await;
                    *lock = Some(broadcast);
                } else {
                    let write_data = self.write_val.take().unwrap_or(SectorVec(Vec::new()));

                    self.sectors_manager
                        .write(
                            msg_header.sector_idx,
                            &(write_data.clone(), timestamp + 1, self.self_ident),
                        )
                        .await;
                    let header = self.construct_new_system_header(msg_header);
                    let content = SystemRegisterCommandContent::WriteProc {
                        timestamp: timestamp + 1,
                        write_rank: self.self_ident,
                        data_to_write: write_data,
                    };
                    let cmd = Arc::new(SystemRegisterCommand { header, content });
                    let broadcast = Broadcast { cmd };
                    self.register_client.broadcast(broadcast.clone()).await;
                    *lock = Some(broadcast);
                }

                self.write_phase = true;
            }
        }
    }

    #[inline]
    async fn handle_write_proc(
        &mut self,
        msg_header: SystemCommandHeader,
        timestamp: u64,
        write_rank: u8,
        data_to_write: SectorVec,
    ) {
        let sector_idx = msg_header.sector_idx;

        let (ts, wr) = self.sectors_manager.read_metadata(sector_idx).await;

        if (timestamp, write_rank) > (ts, wr) {
            self.sectors_manager
                .write(sector_idx, &(data_to_write, timestamp, write_rank))
                .await;
        }

        let header = self.construct_new_system_header(&msg_header);

        let content = SystemRegisterCommandContent::Ack;
        let cmd = Arc::new(SystemRegisterCommand { header, content });
        self.register_client
            .send(MsgSend {
                cmd,
                target: msg_header.process_identifier,
            })
            .await;
    }

    #[inline]
    async fn handle_ack(&mut self, msg_header: &SystemCommandHeader) {
        if self.read_id == msg_header.read_ident && self.write_phase {
            let q = msg_header.process_identifier as usize - 1;
            self.ack_list[q] = Some(());

            if 2 * self.ack_list.iter().filter(|x| x.is_some()).count()
                > self.processes_count as usize
            {
                self.ack_list.fill_with(Default::default);
                self.write_phase = false;
                let request_identifier = self.current_client_identifier;
                if self.operation == Some(ClientOperation::Reading) {
                    self.operation = None;
                    let op_return = OperationReturn::Read(ReadReturn {
                        read_data: self.read_val.take().unwrap_or(SectorVec(Vec::new())),
                    });

                    if let Some(cb) = self.current_client_callback.take() {
                        cb(OperationSuccess {
                            request_identifier: request_identifier.unwrap(),
                            op_return,
                        })
                        .await
                    }
                } else {
                    self.operation = None;
                    let op_return = OperationReturn::Write;
                    let cb = self.current_client_callback.take().unwrap();
                    cb(OperationSuccess {
                        request_identifier: request_identifier.unwrap(),
                        op_return,
                    })
                    .await;
                }
            }
        }
    }
}
