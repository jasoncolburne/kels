//! Gossip layer event and command types.

use kels_exchange::MailAnnouncement;

use super::iel::IelAnnouncement;
use super::kel::KelAnnouncement;
use super::sad::SadAnnouncement;

/// Events emitted by the gossip layer to the sync layer
#[derive(Debug)]
pub(crate) enum GossipEvent {
    /// Received a KEL announcement from a peer
    KelAnnouncementReceived { announcement: KelAnnouncement },
    /// Received a SAD announcement from a peer
    SadAnnouncementReceived { announcement: SadAnnouncement },
    /// Received an IEL announcement from a peer
    IelAnnouncementReceived { announcement: IelAnnouncement },
    /// Received a mail announcement from a peer
    MailAnnouncementReceived { announcement: MailAnnouncement },
    /// New peer connected — carries the peer's identity (IEL prefix).
    PeerConnected(cesr::Digest256),
    /// Peer disconnected — carries the peer's identity (IEL prefix).
    PeerDisconnected(cesr::Digest256),
}

/// Commands sent from sync layer to gossip layer
#[derive(Debug)]
pub(crate) enum GossipCommand {
    /// Broadcast a KEL announcement to the network
    Kel(KelAnnouncement),
    /// Broadcast a SAD announcement to the network
    Sad(SadAnnouncement),
    /// Broadcast an IEL announcement to the network
    Iel(IelAnnouncement),
    /// Broadcast a mail announcement to the network
    Mail(MailAnnouncement),
    /// Retain only the listed peer identities on the gossip transport.
    /// Forwarded to `Gossip::retain_peers`. Used by the sync layer to
    /// enact eager membership teardown when the federation IEL's
    /// `authPolicy` evolves to remove peers.
    RetainPeers(std::collections::HashSet<cesr::Digest256>),
}
