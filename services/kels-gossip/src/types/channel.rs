//! Gossip layer event and command types.

use super::kel::KelAnnouncement;
use super::sad::SadAnnouncement;

/// Events emitted by the gossip layer to the sync layer
#[derive(Debug)]
pub enum GossipEvent {
    /// Received a KEL announcement from a peer
    KelAnnouncementReceived { announcement: KelAnnouncement },
    /// Received a SAD announcement from a peer
    SadAnnouncementReceived { announcement: SadAnnouncement },
    /// New peer connected
    PeerConnected(String),
    /// Peer disconnected
    PeerDisconnected(String),
}

/// Commands sent from sync layer to gossip layer
#[derive(Debug)]
pub enum GossipCommand {
    /// Broadcast a KEL announcement to the network
    AnnounceKel(KelAnnouncement),
    /// Broadcast a SAD announcement to the network
    AnnounceSad(SadAnnouncement),
}
