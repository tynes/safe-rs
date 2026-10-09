//! A Safe's owner changes, read from its event logs.
//!
//! The owner list only shows who owns the Safe now. The logs also show every
//! key that ever did, which is what rebuilding lost rotation state needs:
//! each of those keys has signed, so none may be handed out again.

use alloy::network::AnyNetwork;
use alloy::primitives::{Address, Log, B256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;

use crate::contracts::ISafe;
use crate::error::{Error, Result};

/// How an address entered or left the owner list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerEventKind {
    /// An initial owner, from `SafeSetup`
    Setup,
    /// `AddedOwner`
    Added,
    /// `RemovedOwner`
    Removed,
}

/// One owner change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerEvent {
    /// What happened
    pub kind: OwnerEventKind,
    /// The owner it happened to
    pub owner: Address,
    /// Block of the log
    pub block: Option<u64>,
    /// Transaction of the log
    pub tx_hash: Option<B256>,
}

/// Decodes the owner changes in one log emitted by a Safe.
///
/// `AddedOwner` and `RemovedOwner` index the owner from Safe v1.4.0 on and
/// carry it in the data before that; both layouts share a topic and are
/// accepted, since a Safe may have been upgraded.
pub fn decode_owner_log(log: &Log) -> Vec<(OwnerEventKind, Address)> {
    let topics = log.topics();
    let Some(topic0) = topics.first() else {
        return Vec::new();
    };
    let kind = if *topic0 == ISafe::AddedOwner::SIGNATURE_HASH {
        OwnerEventKind::Added
    } else if *topic0 == ISafe::RemovedOwner::SIGNATURE_HASH {
        OwnerEventKind::Removed
    } else if *topic0 == ISafe::SafeSetup::SIGNATURE_HASH {
        return ISafe::SafeSetup::decode_log(log).map_or_else(
            |_| Vec::new(),
            |setup| {
                setup
                    .owners
                    .iter()
                    .map(|owner| (OwnerEventKind::Setup, *owner))
                    .collect()
            },
        );
    } else {
        return Vec::new();
    };
    let word = match topics.get(1) {
        Some(topic) => topic.as_slice(),
        None => &log.data.data,
    };
    if word.len() != 32 {
        return Vec::new();
    }
    vec![(kind, Address::from_slice(&word[12..]))]
}

/// Reads every owner change of `safe` in `from_block..=to_block`, oldest first.
///
/// The range is fetched `chunk` blocks at a time, since most providers limit
/// how many blocks one `eth_getLogs` request may span. Start at or before the
/// block the Safe was deployed in to see its initial owners.
pub async fn owner_history<P: Provider<AnyNetwork>>(
    provider: &P,
    safe: Address,
    from_block: u64,
    to_block: u64,
    chunk: u64,
) -> Result<Vec<OwnerEvent>> {
    let chunk = chunk.max(1);
    let topics = vec![
        ISafe::SafeSetup::SIGNATURE_HASH,
        ISafe::AddedOwner::SIGNATURE_HASH,
        ISafe::RemovedOwner::SIGNATURE_HASH,
    ];
    let mut events = Vec::new();
    let mut start = from_block;
    while start <= to_block {
        let end = start.saturating_add(chunk - 1).min(to_block);
        let filter = Filter::new()
            .address(safe)
            .event_signature(topics.clone())
            .from_block(start)
            .to_block(end);
        let logs = provider.get_logs(&filter).await.map_err(|e| Error::Fetch {
            what: "owner events",
            reason: format!("blocks {start}..={end}: {e}"),
        })?;
        for log in logs {
            for (kind, owner) in decode_owner_log(&log.inner) {
                events.push(OwnerEvent {
                    kind,
                    owner,
                    block: log.block_number,
                    tx_hash: log.transaction_hash,
                });
            }
        }
        let Some(next) = end.checked_add(1) else {
            break;
        };
        start = next;
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, LogData, U256};
    use alloy::sol_types::SolValue;

    const SAFE: Address = Address::repeat_byte(0x5A);

    fn word(address: Address) -> B256 {
        address.into_word()
    }

    fn log(topics: Vec<B256>, data: Bytes) -> Log {
        Log {
            address: SAFE,
            data: LogData::new_unchecked(topics, data),
        }
    }

    #[test]
    fn indexed_and_unindexed_owner_events_decode_alike() {
        let owner = Address::repeat_byte(0x11);
        // v1.4.1: the owner is a topic.
        let indexed = log(
            vec![ISafe::AddedOwner::SIGNATURE_HASH, word(owner)],
            Bytes::new(),
        );
        // v1.3.0: the owner is the data.
        let unindexed = log(
            vec![ISafe::RemovedOwner::SIGNATURE_HASH],
            Bytes::copy_from_slice(word(owner).as_slice()),
        );
        assert_eq!(
            decode_owner_log(&indexed),
            vec![(OwnerEventKind::Added, owner)]
        );
        assert_eq!(
            decode_owner_log(&unindexed),
            vec![(OwnerEventKind::Removed, owner)]
        );
    }

    #[test]
    fn safe_setup_lists_every_initial_owner() {
        let owners = vec![Address::repeat_byte(0x21), Address::repeat_byte(0x22)];
        let data = (
            owners.clone(),
            U256::from(1),
            Address::ZERO,
            Address::repeat_byte(0xFA),
        )
            .abi_encode_params();
        let setup = log(
            vec![
                ISafe::SafeSetup::SIGNATURE_HASH,
                word(Address::repeat_byte(0xF0)),
            ],
            data.into(),
        );
        assert_eq!(
            decode_owner_log(&setup),
            vec![
                (OwnerEventKind::Setup, owners[0]),
                (OwnerEventKind::Setup, owners[1])
            ]
        );
    }

    #[test]
    fn other_or_malformed_logs_are_ignored() {
        assert!(decode_owner_log(&log(Vec::new(), Bytes::new())).is_empty());
        assert!(decode_owner_log(&log(
            vec![ISafe::ExecutionSuccess::SIGNATURE_HASH, B256::ZERO],
            Bytes::new()
        ))
        .is_empty());
        // An owner event with neither a topic nor a full word of data.
        assert!(decode_owner_log(&log(
            vec![ISafe::AddedOwner::SIGNATURE_HASH],
            Bytes::from_static(&[1, 2, 3])
        ))
        .is_empty());
    }
}
