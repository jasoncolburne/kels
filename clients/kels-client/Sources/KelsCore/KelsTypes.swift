import Foundation

// MARK: - KEL Event

/// Represents a key event result from KELS operations
public struct KelEvent: Identifiable, Equatable, Sendable {
    public let id: String
    public let prefix: String
    public let said: String
    public let version: UInt64

    public init(prefix: String, said: String, version: UInt64) {
        self.id = said
        self.prefix = prefix
        self.said = said
        self.version = version
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

// MARK: - KELS Node

/// Available KELS server nodes (static configuration)
public enum KelsNode: String, CaseIterable, Identifiable, Sendable {
    case nodeA = "http://kels.kels-node-a.local"
    case nodeB = "http://kels.kels-node-b.local"

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .nodeA: return "Node A"
        case .nodeB: return "Node B"
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

/// Node discovery from registry
public struct NodeDiscovery {
    /// Discover nodes from registry and test latency
    /// - Parameter registryUrl: URL of the registry service
    /// - Returns: Array of nodes sorted by latency (fastest first)
    public static func discoverNodes(registryUrl: String) async throws -> [RegistryNode] {
        let url = URL(string: "\(registryUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/")))/api/nodes")!

        let (data, response) = try await URLSession.shared.data(from: url)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw KelsClientError.networkError("Failed to fetch nodes from registry")
        }

        var nodes = try JSONDecoder().decode([RegistryNode].self, from: data)

        // Test latency to each ready node
        for i in nodes.indices where nodes[i].status == .ready {
            if let latency = await testLatency(to: nodes[i].kelsUrl) {
                nodes[i].latencyMs = latency
            }
        }

        // Sort by latency (ready nodes with latency first)
        nodes.sort { a, b in
            if a.status == .ready && b.status == .ready {
                switch (a.latencyMs, b.latencyMs) {
                case (let aLat?, let bLat?): return aLat < bLat
                case (.some, .none): return true
                case (.none, .some): return false
                case (.none, .none): return false
                }
            }
            if a.status == .ready { return true }
            if b.status == .ready { return false }
            return false
        }

        return nodes
    }

    /// Test latency to a KELS node
    private static func testLatency(to kelsUrl: String) async -> UInt64? {
        guard let url = URL(string: "\(kelsUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/")))/health") else {
            return nil
        }

        let start = DispatchTime.now()
        do {
            let (_, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else {
                return nil
            }
            let end = DispatchTime.now()
            let nanos = end.uptimeNanoseconds - start.uptimeNanoseconds
            return nanos / 1_000_000 // Convert to milliseconds
        } catch {
            return nil
        }
    }

    /// Get the fastest ready node from registry
    /// - Parameter registryUrl: URL of the registry service
    /// - Returns: The fastest ready node, or nil if none available
    public static func fastestNode(registryUrl: String) async throws -> RegistryNode? {
        let nodes = try await discoverNodes(registryUrl: registryUrl)
        return nodes.first { $0.status == .ready && $0.latencyMs != nil }
    }
}
