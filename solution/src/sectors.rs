use log::{debug, trace, warn};
use std::io::ErrorKind;
use std::sync::Arc;
use std::{collections::HashMap, path::PathBuf};
use tokio::fs::{read_dir, remove_file, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Error, Result};
use tokio::sync::RwLock;

use crate::{sectors_manager_public::SectorsManager, SectorIdx, SectorVec};

type SectorFile = (PathBuf, u64, u8);
pub struct FileBasedSectorsManager {
    path: PathBuf, // Path to exclusive access directory.
    sector_mapping: Arc<RwLock<HashMap<SectorIdx, RwLock<SectorFile>>>>,
}

#[async_trait::async_trait]
impl SectorsManager for FileBasedSectorsManager {
    async fn read_data(&self, idx: SectorIdx) -> SectorVec {
        SectorVec(
            self.try_read_data(idx)
                .await
                .unwrap_or_else(|_| vec![0u8; 4096]),
        )
    }

    async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8) {
        let map_lock = self.sector_mapping.read().await;
        let maybe_cached_values = (*map_lock).get(&idx);

        if let Some(cached_values) = maybe_cached_values {
            let (_, ts, pr) = *cached_values.read().await;
            (ts, pr)
        } else {
            (0, 0)
        }
    }

    async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8)) {
        let rv = self.try_write(idx, sector).await;
        if rv.is_err() {
            warn!(target: "sectors", "{}", rv.unwrap_err());
        }
    }
}

impl FileBasedSectorsManager {
    const META_DELIMITER: char = '_';
    pub async fn new(path: PathBuf) -> Self {
        let mut cache = HashMap::new();
        Self::try_recover(&path, &mut cache)
            .await
            .expect("Couldn't recover SectorsManager");

        Self {
            path,
            sector_mapping: Arc::new(RwLock::const_new(cache)),
        }
    }

    async fn try_recover(
        path: &PathBuf,
        cache: &mut HashMap<SectorIdx, RwLock<SectorFile>>,
    ) -> Result<()> {
        let mut dir_entry = read_dir(path).await?;

        while let Some(file) = dir_entry.next_entry().await? {
            let file_name = file.file_name();
            let meta: Vec<&str> = file_name
                .to_str()
                .unwrap()
                .split(Self::META_DELIMITER)
                .collect();
            let path = file.path();
            let index = meta[0].parse::<u64>().unwrap();
            let ts = meta[1].parse::<u64>().unwrap();
            let pr = meta[2].parse::<u8>().unwrap();
            cache.insert(index, RwLock::const_new((path, ts, pr)));
        }

        Ok(())
    }

    async fn try_read_data(&self, idx: SectorIdx) -> Result<Vec<u8>> {
        let lock = self.sector_mapping.read().await;
        let sector_lock = lock
            .get(&idx)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "mapping not found in cache"))?;
        let file_path = sector_lock.read().await;
        let mut file = File::open(&file_path.0).await?;

        let mut sector_data = vec![0u8; 4096];
        file.read_exact(&mut sector_data).await?;
        Ok(sector_data)
    }

    async fn try_write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8)) -> Result<()> {
        let (new_sector_data, new_ts, new_pr) = sector;
        let cache_read_lock = self.sector_mapping.read().await;

        if let Some(local_lock) = cache_read_lock.get(&idx) {
            // Most of the cases we will be writing to already created sector.
            let mut cached_value = local_lock.write().await;
            let (path, ts, pr) = &mut *cached_value;
            if (new_ts, new_pr) > (ts, pr) {
                let new_path = self.path.join(format!("{}_{}_{}", idx, new_ts, new_pr));
                let mut file = File::create(&new_path).await?;
                trace!("NEW REGISTER {:?}", &new_path);
                file.write_all(&new_sector_data.0).await?;
                file.sync_data().await?;
                trace!("REMOVING SECTOR {:?}", &path);
                remove_file(path).await?;
                *cached_value = (new_path, *new_ts, *new_pr);
            } else {
                debug!("(new_ts, new_pr) <= (ts, pr)");
            }
        } else {
            drop(cache_read_lock); // We can't convert out read lock to write one, so we have to reclaim it with stronger contract.
            let new_path = self.path.join(format!(
                "{}{delimiter}{}{delimiter}{}",
                idx,
                new_ts,
                new_pr,
                delimiter = Self::META_DELIMITER
            ));
            let mut file = File::create(&new_path).await?;
            trace!("NEW REGISTER {:?}", &new_path);
            file.write_all(&new_sector_data.0).await?;
            file.sync_data().await?;

            let mut exclusive_lock = self.sector_mapping.write().await;
            exclusive_lock.insert(idx, RwLock::const_new((new_path, *new_ts, *new_pr)));
        }

        Ok(())
    }
}
