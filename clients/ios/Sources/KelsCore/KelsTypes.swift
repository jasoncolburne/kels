import Foundation
import LibKels

// MARK: - KEL Event

/// Represents a key event result from KELS operations
public struct KelEvent: Identifiable, Equatable, Sendable {
    public let id: String
    public let prefix: String
    public let said: String

    public init(prefix: String, said: String) {
        self.id = said
        self.prefix = prefix
        self.said = said
    }
}

// MARK: - KEL Status

/// Status information for a Key Event Log
public struct KelStatus: Equatable, Sendable {
    public let prefix: String?
    public let eventCount: UInt32
    public let latestSaid: String?
    public let isDivergent: Bool
    public let isContested: Bool
    public let isDecommissioned: Bool
    public let useHardware: Bool

    public init(
        prefix: String?,
        eventCount: UInt32,
        latestSaid: String?,
        isDivergent: Bool,
        isContested: Bool,
        isDecommissioned: Bool,
        useHardware: Bool
    ) {
        self.prefix = prefix
        self.eventCount = eventCount
        self.latestSaid = latestSaid
        self.isDivergent = isDivergent
        self.isContested = isContested
        self.isDecommissioned = isDecommissioned
        self.useHardware = useHardware
    }
}

// MARK: - Recovery Outcome

/// Outcome of a recovery operation
public enum RecoveryOutcome: Int, Sendable {
    case recovered = 0
    case contested = 1
    case failed = 2
}

// MARK: - KELS Error

/// Errors that can occur during KELS operations
public enum KelsClientError: Error, LocalizedError, Sendable {
    case notInitialized
    case divergenceDetected
    case kelNotFound
    case kelFrozen
    case networkError(String?)
    case notIncepted
    case contestRequired
    case unknown(String)

    public var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "KELS context not initialized"
        case .divergenceDetected:
            return "Divergence detected - recovery may be needed"
        case .kelNotFound:
            return "KEL not found"
        case .kelFrozen:
            return "KEL is frozen (contested or decommissioned)"
        case .networkError(let detail):
            if let detail = detail {
                return "Network or server error: \(detail)"
            }
            return "Network or server error"
        case .notIncepted:
            return "KEL has not been incepted yet"
        case .contestRequired:
            return "Contest required: recovery key revealed. Use Contest to freeze KEL."
        case .unknown(let message):
            return message
        }
    }
}

// MARK: - Node Discovery

/// Information about a discovered KELS peer (verified and ready)
public struct RegistryNode: Codable, Identifiable, Sendable {
    public let nodeId: String
    public let baseDomain: String
    public let gossipAddr: String
    public let peerPrefix: String

    public var id: String { nodeId }

    public var displayName: String { nodeId }

    public var kelsUrl: String { "http://kels.\(baseDomain)" }

    public var sadstoreUrl: String { "http://kels-sadstore.\(baseDomain)" }
}

/// FFI response peer (matches FFI's PeerInfoJson with camelCase)
private struct FFIPeer: Codable {
    let nodeId: String
    let baseDomain: String
    let gossipAddr: String
    let peerPrefix: String
}

/// Node discovery from registry using FFI
public struct NodeDiscovery {
    /// Fetch and verify the registry's prefix from its KEL
    /// - Parameter registryUrl: URL of the registry service
    /// - Returns: The verified registry prefix
    public static func fetchRegistryPrefix(registryUrl: String) async throws -> String {
        return try await Task.detached {
            var result = KelsPrefixResult()
            kels_fetch_registry_prefix(registryUrl, &result)
            defer { kels_prefix_result_free(&result) }

            if result.status != KELS_STATUS_OK {
                let errorMsg = result.error.map { String(cString: $0) }
                throw KelsClientError.networkError(errorMsg)
            }

            guard let prefixPtr = result.prefix else {
                throw KelsClientError.unknown("Registry returned no prefix")
            }

            return String(cString: prefixPtr)
        }.value
    }

    /// Discover nodes from registry and test latency
    /// - Parameters:
    ///   - registryUrl: URL of the registry service
    ///   - registryPrefix: Expected registry prefix (trust anchor) - nil to skip verification
    /// - Returns: Array of nodes sorted by latency (fastest first)
    public static func discoverNodes(registryUrl: String, registryPrefix: String? = nil) async throws -> [RegistryNode] {
        // Run FFI call on a background thread since it's blocking
        return try await Task.detached {
            var result = KelsNodesResult()
            kels_discover_nodes(registryUrl, registryPrefix, &result)
            defer { kels_nodes_result_free(&result) }

            if result.status != KELS_STATUS_OK {
                let errorMsg = result.error.map { String(cString: $0) }
                throw KelsClientError.networkError(errorMsg)
            }

            guard let nodesJson = result.nodes_json else {
                return []
            }

            let jsonString = String(cString: nodesJson)
            guard let data = jsonString.data(using: .utf8) else {
                return []
            }

            let ffiPeers = try JSONDecoder().decode([FFIPeer].self, from: data)

            return ffiPeers.map { ffi in
                RegistryNode(
                    nodeId: ffi.nodeId,
                    baseDomain: ffi.baseDomain,
                    gossipAddr: ffi.gossipAddr,
                    peerPrefix: ffi.peerPrefix
                )
            }
        }.value
    }

    /// Get the fastest ready node from registry
    /// - Parameters:
    ///   - registryUrl: URL of the registry service
    ///   - registryPrefix: Expected registry prefix (trust anchor) - nil to skip verification
    /// - Returns: The fastest ready node, or nil if none available
    public static func fastestNode(registryUrl: String, registryPrefix: String? = nil) async throws -> RegistryNode? {
        let nodes = try await discoverNodes(registryUrl: registryUrl, registryPrefix: registryPrefix)
        return nodes.first
    }
}
