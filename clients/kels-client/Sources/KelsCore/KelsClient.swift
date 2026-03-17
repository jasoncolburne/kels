import Foundation
import LibKels

/// Swift wrapper for the KELS FFI library
public final class KelsClient: @unchecked Sendable {
    private var context: OpaquePointer?
    private let lock = NSLock()

    // MARK: - Initialization

    /// Initialize a new KELS client
    /// - Parameters:
    ///   - kelsURL: URL of the KELS server
    ///   - stateDir: Directory for storing local state (defaults to app documents)
    ///   - keyNamespace: Namespace for Secure Enclave key labels (e.g., "com.myapp.kels")
    ///   - prefix: Optional existing KEL prefix to load
    ///   - signingAlgorithm: Signing algorithm ("secp256r1" or "ml-dsa-65"). Defaults to "secp256r1".
    ///                       Only used in software-only builds; ignored when Secure Enclave is available.
    ///   - recoveryAlgorithm: Recovery key algorithm ("secp256r1" or "ml-dsa-65"). Defaults to "secp256r1".
    ///                        Only used in software-only builds; ignored when Secure Enclave is available.
    public init(kelsURL: String, stateDir: String? = nil, keyNamespace: String, prefix: String? = nil, signingAlgorithm: String? = nil, recoveryAlgorithm: String? = nil) throws {
        let dir = stateDir ?? Self.defaultStateDirectory()

        context = kels_init(kelsURL, dir, keyNamespace, prefix, signingAlgorithm, recoveryAlgorithm)
        if context == nil {
            let error = Self.getLastError()
            throw KelsClientError.unknown(error ?? "Failed to initialize KELS context")
        }
    }

    deinit {
        lock.withLock {
            if let ctx = context {
                kels_free(ctx)
                context = nil
            }
        }
    }

    // MARK: - URL Management

    /// Change the KELS server URL at runtime
    /// - Parameter url: New server URL
    public func setURL(_ url: String) throws {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            let result = kels_set_url(ctx, url)
            if result != 0 {
                let error = Self.getLastError()
                throw KelsClientError.unknown(error ?? "Failed to set URL")
            }
        }
    }

    // MARK: - KEL Operations

    /// Create an inception event (start a new KEL)
    /// - Parameters:
    ///   - signingAlgorithm: Algorithm for signing keys (NULL = keep current from init)
    ///   - recoveryAlgorithm: Algorithm for recovery keys (NULL = keep current from init)
    /// - Returns: The inception event
    public func incept(signingAlgorithm: String? = nil, recoveryAlgorithm: String? = nil) throws -> KelEvent {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            var result = KelsEventResult()
            kels_incept(ctx, signingAlgorithm, recoveryAlgorithm, &result)
            defer { kels_event_result_free(&result) }

            return try parseEventResult(result)
        }
    }

    /// Rotate the signing key
    /// - Parameter signingAlgorithm: Algorithm for the new signing key (nil = keep current)
    /// - Returns: The rotation event
    public func rotate(signingAlgorithm: String? = nil) throws -> KelEvent {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            var result = KelsEventResult()
            kels_rotate(ctx, signingAlgorithm, &result)
            defer { kels_event_result_free(&result) }

            return try parseEventResult(result)
        }
    }

    /// Rotate the recovery key
    /// - Parameter recoveryAlgorithm: Algorithm for the new recovery key (nil = keep current)
    /// - Returns: The recovery rotation event
    public func rotateRecovery(recoveryAlgorithm: String? = nil) throws -> KelEvent {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            var result = KelsEventResult()
            kels_rotate_recovery(ctx, recoveryAlgorithm, &result)
            defer { kels_event_result_free(&result) }

            return try parseEventResult(result)
        }
    }

    /// Create an interaction event (anchor data to KEL)
    /// - Parameter anchor: The data to anchor
    /// - Returns: The interaction event
    public func interact(anchor: String) throws -> KelEvent {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            var result = KelsEventResult()
            kels_interact(ctx, anchor, &result)
            defer { kels_event_result_free(&result) }

            return try parseEventResult(result)
        }
    }

    /// Attempt recovery from divergence or adversary attack
    /// - Parameters:
    ///   - signingAlgorithm: Algorithm for the new signing key (nil = keep current)
    ///   - recoveryAlgorithm: Algorithm for the new recovery key (nil = keep current)
    /// - Returns: The recovery outcome and event
    public func recover(signingAlgorithm: String? = nil, recoveryAlgorithm: String? = nil) throws -> (RecoveryOutcome, KelEvent) {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            var result = KelsRecoveryResult()
            kels_recover(ctx, signingAlgorithm, recoveryAlgorithm, &result)
            defer { kels_recovery_result_free(&result) }

            if result.status != KELS_STATUS_OK {
                throw parseStatus(result.status, error: result.error)
            }

            let outcome = RecoveryOutcome(rawValue: Int(result.outcome.rawValue)) ?? .failed
            let prefix = result.prefix.map { String(cString: $0) } ?? ""
            let said = result.said.map { String(cString: $0) } ?? ""

            return (outcome, KelEvent(prefix: prefix, said: said))
        }
    }

    /// Contest a malicious recovery by submitting a contest event (cnt)
    /// Use this when an adversary has revealed your recovery key.
    /// The KEL will be permanently frozen after contesting.
    /// - Parameters:
    ///   - signingAlgorithm: Algorithm for the new signing key (nil = keep current)
    ///   - recoveryAlgorithm: Algorithm for the new recovery key (nil = keep current)
    /// - Returns: The contest event
    public func contest(signingAlgorithm: String? = nil, recoveryAlgorithm: String? = nil) throws -> KelEvent {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            var result = KelsEventResult()
            kels_contest(ctx, signingAlgorithm, recoveryAlgorithm, &result)
            defer { kels_event_result_free(&result) }

            return try parseEventResult(result)
        }
    }

    /// Decommission a KEL (permanently disable it)
    /// - Parameters:
    ///   - signingAlgorithm: Algorithm for the new signing key (nil = keep current)
    ///   - recoveryAlgorithm: Algorithm for the new recovery key (nil = keep current)
    /// - Returns: The decommission event
    public func decommission(signingAlgorithm: String? = nil, recoveryAlgorithm: String? = nil) throws -> KelEvent {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            var result = KelsEventResult()
            kels_decommission(ctx, signingAlgorithm, recoveryAlgorithm, &result)
            defer { kels_event_result_free(&result) }

            return try parseEventResult(result)
        }
    }

    // MARK: - Query Operations

    /// Get the status of the current KEL
    /// - Parameter prefix: Optional prefix (nil for current context's KEL)
    /// - Returns: KEL status
    public func status(prefix: String? = nil) throws -> KelStatus {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            var result = KelsStatusResult()
            kels_status(ctx, prefix, &result)
            defer { kels_status_result_free(&result) }

            if result.status != KELS_STATUS_OK {
                throw parseStatus(result.status, error: result.error)
            }

            return KelStatus(
                prefix: result.prefix.map { String(cString: $0) },
                eventCount: result.event_count,
                latestSaid: result.latest_said.map { String(cString: $0) },
                isDivergent: result.is_divergent,
                isContested: result.is_contested,
                isDecommissioned: result.is_decommissioned,
                useHardware: result.use_hardware
            )
        }
    }

    /// Get a page of KEL events as JSON.
    /// - Parameters:
    ///   - prefix: The KEL prefix (nil for current KEL)
    ///   - limit: Maximum events per page (clamped to server max)
    ///   - offset: Event offset to start from
    /// - Returns: JSON string `{"events": [...], "has_more": bool}`
    public func getKel(prefix: String? = nil, limit: UInt64 = 512, offset: UInt64 = 0) throws -> String {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            guard let json = kels_get_kel(ctx, prefix, limit, offset) else {
                let error = Self.getLastError()
                throw KelsClientError.unknown(error ?? "Failed to get KEL")
            }
            defer { kels_free_string(json) }

            return String(cString: json)
        }
    }

    /// List all local KEL prefixes
    /// - Returns: Array of prefix strings
    public func list() throws -> [String] {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            var result = KelsListResult()
            kels_list(ctx, &result)
            defer { kels_list_result_free(&result) }

            if result.status != KELS_STATUS_OK {
                throw parseStatus(result.status, error: result.error)
            }

            guard let json = result.prefixes_json else {
                return []
            }

            let jsonString = String(cString: json)
            guard let data = jsonString.data(using: .utf8),
                  let prefixes = try? JSONDecoder().decode([String].self, from: data)
            else {
                return []
            }

            return prefixes
        }
    }

    // MARK: - Dev Tools

    #if DEV_TOOLS
    /// Dump the local KEL for debugging
    /// - Returns: Pretty-printed JSON of the KEL
    public func dumpKel() throws -> String {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            guard let json = kels_dump_local_kel(ctx) else {
                let error = Self.getLastError()
                throw KelsClientError.unknown(error ?? "Failed to dump KEL")
            }
            defer { kels_free_string(json) }

            return String(cString: json)
        }
    }

    /// Inject adversary events for testing divergence scenarios
    /// - Parameter eventTypes: Comma-separated event types (e.g., "rot,ixn")
    public func adversaryInjectEvents(_ eventTypes: String) throws {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            let result = kels_adversary_inject_events(ctx, eventTypes)
            if result != 0 {
                let error = Self.getLastError()
                throw KelsClientError.unknown(error ?? "Failed to inject adversary events")
            }
        }
    }

    /// Truncate the local KEL, keeping only the first N events
    /// - Parameter keepEvents: Number of events to keep
    public func truncateLocalKel(keepEvents: UInt32) throws {
        try lock.withLock {
            guard let ctx = context else {
                throw KelsClientError.notInitialized
            }

            let result = kels_truncate_local_kel(ctx, keepEvents)
            if result != 0 {
                let error = Self.getLastError()
                throw KelsClientError.unknown(error ?? "Failed to truncate KEL")
            }
        }
    }
    #endif

    // MARK: - Private Helpers

    private static func defaultStateDirectory() -> String {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        return paths[0].appendingPathComponent("kels").path
    }

    // MARK: - Reset

    /// Reset all local state (KELs, keys)
    /// This is a static method that can be called without an existing client instance
    /// - Parameter stateDir: Directory containing local state (defaults to app documents)
    public static func reset(stateDir: String? = nil) throws {
        let dir = stateDir ?? defaultStateDirectory()

        let result = kels_reset(dir)
        if result != 0 {
            let error = getLastError()
            throw KelsClientError.unknown(error ?? "Failed to reset state")
        }
    }

    private static func getLastError() -> String? {
        guard let errorPtr = kels_last_error() else {
            return nil
        }
        return String(cString: errorPtr)
    }

    private func parseEventResult(_ result: KelsEventResult) throws -> KelEvent {
        if result.status != KELS_STATUS_OK {
            throw parseStatus(result.status, error: result.error)
        }

        let prefix = result.prefix.map { String(cString: $0) } ?? ""
        let said = result.said.map { String(cString: $0) } ?? ""

        return KelEvent(prefix: prefix, said: said)
    }

    private func parseStatus(_ status: KelsStatus, error: UnsafeMutablePointer<CChar>?) -> KelsClientError {
        let errorMessage = error.map { String(cString: $0) }

        switch status {
        case KELS_STATUS_NOT_INITIALIZED:
            return .notInitialized
        case KELS_STATUS_DIVERGENCE_DETECTED:
            return .divergenceDetected
        case KELS_STATUS_KEL_NOT_FOUND:
            return .kelNotFound
        case KELS_STATUS_KEL_FROZEN:
            return .kelFrozen
        case KELS_STATUS_NETWORK_ERROR:
            return .networkError(errorMessage)
        case KELS_STATUS_NOT_INCEPTED:
            return .notIncepted
        case KELS_STATUS_CONTEST_REQUIRED:
            return .contestRequired
        default:
            return .unknown(errorMessage ?? "Unknown error")
        }
    }
}
