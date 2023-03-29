use std::path::PathBuf;

use sha2::{Digest, Sha256};
use tokio::{
    fs::{remove_file, rename, File},
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::StableStorage;

/// Creates a new instance of stable storage.
pub async fn build_stable_storage(root_storage_dir: PathBuf) -> Box<dyn StableStorage> {
    Box::new(FileBasedStableStorage {
        root_dir: root_storage_dir,
    })
}

struct FileBasedStableStorage {
    root_dir: PathBuf,
}

enum TargetFile {
    Temporary,
    Final,
}

#[async_trait::async_trait]
impl StableStorage for FileBasedStableStorage {
    async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        if key.as_bytes().len() > Self::MAX_KEY_LEN || value.len() > Self::MAX_VAL_LEN {
            return Err("Nah".to_string());
        }
        let path = self.get_key_path(key, TargetFile::Temporary);

        let maybe_file_handle = File::create(path.clone()).await;

        let mut file_handle = maybe_file_handle.expect("Couldn't create file.");
        let _ = file_handle.write_all(value).await.unwrap();
        file_handle.sync_data().await.unwrap();
        let root_dir = File::open(self.root_dir.clone())
            .await
            .expect("Couldn't open parent dir.");
        rename(path, self.get_key_path(key, TargetFile::Final))
            .await
            .unwrap();
        root_dir.sync_data().await.unwrap();

        Ok(())
    }

    async fn get(&self, key: &str) -> Option<Vec<u8>> {
        let path = self.get_key_path(key, TargetFile::Final);

        let maybe_file_handle = File::open(path).await;

        if let Ok(file_handle) = maybe_file_handle {
            let contents = Self::read_file_contents(file_handle).await;
            Some(contents)
        } else {
            let err = maybe_file_handle.unwrap_err();

            match err.kind() {
                std::io::ErrorKind::NotFound => None,
                e => panic!("{}", e),
            }
        }
    }

    async fn remove(&mut self, key: &str) -> bool {
        let path = self.get_key_path(key, TargetFile::Final);

        let rv = remove_file(path).await;

        let root_dir = File::open(self.root_dir.clone()).await;

        if root_dir.is_err() || root_dir.unwrap().sync_data().await.is_err() {
            return false;
        }

        if let Err(err) = rv {
            match err.kind() {
                std::io::ErrorKind::NotFound => false,
                e => panic!("{}", e),
            }
        } else {
            true
        }
    }
}

impl FileBasedStableStorage {
    const MAX_KEY_LEN: usize = 255;
    const MAX_VAL_LEN: usize = 65535;
    const INITIAL_CONTENT_CAPACITY: usize = 256;

    fn get_key_path(&self, key: &str, target: TargetFile) -> PathBuf {
        let mut path = self.root_dir.clone();

        let file = match target {
            TargetFile::Temporary => format!("{}_tmp_file.tmp", key),
            TargetFile::Final => {
                let mut hasher = Sha256::new();
                hasher.update(key);
                format!("{:X}", hasher.finalize())
            }
        };

        path.push(file);

        path
    }

    async fn read_file_contents(mut file_handle: File) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(Self::INITIAL_CONTENT_CAPACITY);

        match file_handle.read_to_end(&mut buffer).await {
            Ok(_) => buffer,
            Err(error) => {
                panic!("{}", error)
            }
        }
    }
}
