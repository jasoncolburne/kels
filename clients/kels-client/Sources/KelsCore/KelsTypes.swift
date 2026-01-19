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

/// Available KELS server nodes
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
