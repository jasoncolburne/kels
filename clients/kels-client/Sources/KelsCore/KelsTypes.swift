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
    case recoveryProtected
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
        case .recoveryProtected:
            return "Adversary used recovery key - use Contest to freeze KEL"
        case .unknown(let message):
            return message
        }
    }
}

// MARK: - Node Discovery

/// Node status from registry
public enum RegistryNodeStatus: String, Codable, Sendable {
    case bootstrapping
    case ready
    case unhealthy
}

/// Information about a registered KELS node
public struct RegistryNode: Codable, Identifiable, Sendable {
    public let nodeId: String
    public let kelsUrl: String
    public let gossipMultiaddr: String
    public let status: RegistryNodeStatus
    public var latencyMs: UInt64?

    public var id: String { nodeId }

    public var displayName: String { nodeId }

    public var statusColor: String {
        switch status {
        case .ready: return "green"
        case .bootstrapping: return "yellow"
        case .unhealthy: return "red"
        }
    }
}

/// FFI response node (matches FFI's NodeInfoJson with camelCase)
private struct FFINode: Codable {
    let nodeId: String
    let kelsUrl: String
    let status: String
    let latencyMs: UInt64?
}

/// Node discovery from registry using FFI
public struct NodeDiscovery {
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

            let ffiNodes = try JSONDecoder().decode([FFINode].self, from: data)

            // Convert to RegistryNode
            return ffiNodes.map { ffi in
                var node = RegistryNode(
                    nodeId: ffi.nodeId,
                    kelsUrl: ffi.kelsUrl,
                    gossipMultiaddr: "",  // Not provided by FFI, not needed for UI
                    status: RegistryNodeStatus(rawValue: ffi.status) ?? .unhealthy
                )
                node.latencyMs = ffi.latencyMs
                return node
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
        return nodes.first { $0.status == .ready && $0.latencyMs != nil }
    }
}
