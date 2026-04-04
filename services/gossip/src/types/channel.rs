//! Gossip layer event and command types.

use kels_exchange::MailAnnouncement;

use super::kel::KelAnnouncement;
use super::sad::SadAnnouncement;

/// Events emitted by the gossip layer to the sync layer
#[derive(Debug)]
pub(crate) enum GossipEvent {
    /// Received a KEL announcement from a peer
    KelAnnouncementReceived { announcement: KelAnnouncement },
    /// Received a SAD announcement from a peer
    SadAnnouncementReceived { announcement: SadAnnouncement },
    /// Received a mail announcement from a peer
    MailAnnouncementReceived { announcement: MailAnnouncement },
    /// New peer connected
    PeerConnected(String),
    /// Peer disconnected
    PeerDisconnected(String),
}

/// Commands sent from sync layer to gossip layer
#[derive(Debug)]
pub(crate) enum GossipCommand {
    /// Broadcast a KEL announcement to the network
    Kel(KelAnnouncement),
    /// Broadcast a SAD announcement to the network
    Sad(SadAnnouncement),
    /// Broadcast a mail announcement to the network
    Mail(MailAnnouncement),
}
