use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DiscoveryState {
    Idle,
    LoadConfig,
    SendPing,
    GetPeers,
    ReceiveCandidate,
    WaitBackoff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConnectionState {
    Candidate,
    Dialing,
    TunnelHandshake,
    Identify,
    ShareBind,
    Ready,
    Degraded,
    ReconnectBackoff,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MergeState {
    InitStorage,
    LocalScan,
    PeerReady,
    RootCompare,
    NodeDiff,
    FileMetadataDiff,
    PieceCompare,
    TransferRequired,
    CancelStaleMerge,
    FileTransfer,
    Verify,
    PostWork,
    Steady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransferState {
    NotLoaded,
    LoadMeta,
    Loaded,
    Seed,
    RemoteMetadataOnly,
    CreateTransfer,
    Download,
    AllDataReceived,
    VerifyData,
    PostDownloadWork,
    FilePresent,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Event {
    Start,
    ConfigLoaded,
    PingSent,
    CandidateReceived,
    CandidateRejected,
    SocketReady,
    TunnelReady,
    Identified,
    ShareMatched,
    RootEqual,
    RootDifferent,
    MetadataReady,
    PiecesReady,
    TransferNeeded,
    TransferComplete,
    Verified,
    Applied,
    StateNotified,
    TunnelLost,
    Retry,
    Stop,
}

pub fn connection_transition(state: ConnectionState, event: Event) -> ConnectionState {
    use ConnectionState::*;
    use Event::*;
    match (state, event) {
        (Candidate, SocketReady) => Dialing,
        (Dialing, TunnelReady) => TunnelHandshake,
        (TunnelHandshake, Identified) => Identify,
        (Identify, ShareMatched) => ShareBind,
        (ShareBind, SocketReady) => Ready,
        (Ready, TunnelLost) => Degraded,
        (Degraded, TunnelReady) => Ready,
        (Degraded | ReconnectBackoff, Retry) => Dialing,
        (_, Stop) => Closed,
        (state, _) => state,
    }
}

pub fn merge_transition(state: MergeState, event: Event) -> MergeState {
    use Event::*;
    use MergeState::*;
    match (state, event) {
        (InitStorage, Start) => LocalScan,
        (LocalScan, StateNotified) => PeerReady,
        (PeerReady, CandidateReceived) => RootCompare,
        (RootCompare, RootEqual) => PieceCompare,
        (RootCompare, RootDifferent) => NodeDiff,
        (NodeDiff, MetadataReady) => FileMetadataDiff,
        (FileMetadataDiff, PiecesReady) => PieceCompare,
        (PieceCompare, TransferNeeded) => TransferRequired,
        (TransferRequired, Start) => FileTransfer,
        (FileTransfer, TransferComplete) => Verify,
        (Verify, Verified) => PostWork,
        (PostWork, Applied) => Steady,
        (_, RootDifferent) => CancelStaleMerge,
        (CancelStaleMerge, Retry) => RootCompare,
        (state, _) => state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_and_merge_paths_are_explicit() {
        let mut connection = ConnectionState::Candidate;
        for event in [
            Event::SocketReady,
            Event::TunnelReady,
            Event::Identified,
            Event::ShareMatched,
            Event::SocketReady,
        ] {
            connection = connection_transition(connection, event);
        }
        assert_eq!(connection, ConnectionState::Ready);

        let mut merge = MergeState::InitStorage;
        for event in [
            Event::Start,
            Event::StateNotified,
            Event::CandidateReceived,
            Event::RootDifferent,
            Event::MetadataReady,
            Event::PiecesReady,
            Event::TransferNeeded,
            Event::Start,
            Event::TransferComplete,
            Event::Verified,
            Event::Applied,
        ] {
            merge = merge_transition(merge, event);
        }
        assert_eq!(merge, MergeState::Steady);
    }
}
