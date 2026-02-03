import SwiftUI

@MainActor
class KelsViewModel: ObservableObject {
    // Status
    @Published var isIncepted = false
    @Published var prefix: String?
    @Published var eventCount: UInt32 = 0
    @Published var latestSaid: String?
    @Published var isDivergent = false
    @Published var isContested = false
    @Published var isDecommissioned = false
    @Published var useHardware = false
    @Published var isLoading = false
    @Published var needsRecovery = false
    @Published var needsContest = false

    // Registry-based discovery
    @Published var registryUrl: String = "" {
        didSet {
            UserDefaults.standard.set(registryUrl, forKey: registryUrlKey)
        }
    }
    @Published var discoveredNodes: [RegistryNode] = []
    @Published var selectedDiscoveredNode: RegistryNode?

    // KEL list
    @Published var kelPrefixes: [String] = []

    // Current node URL
    @Published var currentNodeUrl: String = ""

    // Error alert
    @Published var errorMessage: String?

    private var client: KelsClient?
    private let prefixKey = "com.kels.currentPrefix"
    private let registryUrlKey = "com.kels.registryUrl"
    private let nodeUrlKey = "com.kels.nodeUrl"
    private let selectedRegistryKey = "com.kels.selectedRegistry"
    private let keyNamespace = "com.kels.kelsclient"

    // Available registries with their URLs
    static let registryUrls = [
        ("registry-a", "http://kels-registry.kels-registry-a.local"),
        ("registry-b", "http://kels-registry.kels-registry-b.local"),
        ("registry-c", "http://kels-registry.kels-registry-c.local")
    ]

    // Parse TRUSTED_REGISTRIES from Generated.swift into a dictionary of prefix -> url
    static let trustedRegistries: [(prefix: String, url: String)] = {
        var registries: [(prefix: String, url: String)] = []
        for pair in TRUSTED_REGISTRIES.split(separator: ",") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            if parts.count == 2 {
                let prefix = String(parts[0]).trimmingCharacters(in: .whitespaces)
                let url = String(parts[1]).trimmingCharacters(in: .whitespaces)
                registries.append((prefix: prefix, url: url))
            }
        }
        return registries
    }()

    // Get the expected prefix for the selected registry by matching URL
    func getExpectedPrefix() -> String? {
        // Get the URL for the selected registry
        guard let registryUrlForSelected = Self.registryUrls.first(where: { $0.0 == selectedRegistry })?.1 else {
            return nil
        }

        // Find the trusted registry entry that matches this URL
        // Match by looking for the registry name in the URL (e.g., "registry-a" in the URL)
        for (prefix, url) in Self.trustedRegistries {
            // Check if the URL contains the registry name
            if url.contains(selectedRegistry) || registryUrlForSelected.contains(selectedRegistry) {
                // Both URLs reference the same registry
                if url.contains(selectedRegistry) {
                    return prefix
                }
            }
        }
        return nil
    }
    @Published var selectedRegistry: String = "registry-a" {
        didSet {
            UserDefaults.standard.set(selectedRegistry, forKey: selectedRegistryKey)
            // Update registry URL when selection changes
            if let url = Self.registryUrls.first(where: { $0.0 == selectedRegistry })?.1 {
                registryUrl = url
            }
        }
    }

    private var defaultRegistryUrl: String {
        Self.registryUrls.first(where: { $0.0 == selectedRegistry })?.1 ?? Self.registryUrls[0].1
    }
    private let defaultNodeUrl = "http://kels.kels-node-a.local"

    // Developer tools logging
    #if DEV_TOOLS
    @Published var logOutput = ""
    #endif

    init() {
        log("KELS iOS app initialized")
        loadSavedSettings()
        initializeClient()

        // Always refresh nodes from registry on startup
        Task {
            await discoverNodes()
        }
    }

    // MARK: - Persistence

    private func loadSavedSettings() {
        // Load selected registry first
        if let savedRegistry = UserDefaults.standard.string(forKey: selectedRegistryKey),
           Self.registryUrls.contains(where: { $0.0 == savedRegistry }) {
            selectedRegistry = savedRegistry
        }

        if let savedRegistryUrl = UserDefaults.standard.string(forKey: registryUrlKey), !savedRegistryUrl.isEmpty {
            registryUrl = savedRegistryUrl
        } else {
            registryUrl = defaultRegistryUrl
        }

        if let savedNodeUrl = UserDefaults.standard.string(forKey: nodeUrlKey), !savedNodeUrl.isEmpty {
            currentNodeUrl = savedNodeUrl
        } else {
            currentNodeUrl = defaultNodeUrl
        }

        loadCachedNodes()
    }

    private func savePrefix(_ prefix: String?) {
        if let prefix = prefix {
            UserDefaults.standard.set(prefix, forKey: prefixKey)
        } else {
            UserDefaults.standard.removeObject(forKey: prefixKey)
        }
    }

    private func loadSavedPrefix() -> String? {
        return UserDefaults.standard.string(forKey: prefixKey)
    }

    private func saveNodeUrl(_ url: String) {
        UserDefaults.standard.set(url, forKey: nodeUrlKey)
        currentNodeUrl = url
    }

    // MARK: - Node Caching

    private let cachedNodesKey = "com.kels.cachedNodes"

    private func loadCachedNodes() {
        guard let data = UserDefaults.standard.data(forKey: cachedNodesKey),
              let nodes = try? JSONDecoder().decode([RegistryNode].self, from: data) else {
            return
        }
        discoveredNodes = nodes
        log("Loaded \(nodes.count) cached nodes")
    }

    private func saveCachedNodes(_ nodes: [RegistryNode]) {
        guard let data = try? JSONEncoder().encode(nodes) else { return }
        UserDefaults.standard.set(data, forKey: cachedNodesKey)
        log("Cached \(nodes.count) nodes")
    }

    private func clearCachedNodes() {
        UserDefaults.standard.removeObject(forKey: cachedNodesKey)
        log("Cleared cached nodes")
    }

    // MARK: - Registry Discovery

    /// Discover nodes from the configured registry
    func discoverNodes() async {
        guard !registryUrl.isEmpty else {
            log("ERROR: Registry URL not configured")
            errorMessage = "Registry URL not configured"
            return
        }

        isLoading = true
        defer { isLoading = false }

        log("Discovering nodes from \(registryUrl)...")

        do {
            // Use trusted prefix for cryptographic verification
            guard let expectedPrefix = getExpectedPrefix() else {
                throw NSError(domain: "KelsClient", code: 1, userInfo: [NSLocalizedDescriptionKey: "No trusted prefix found for \(selectedRegistry)"])
            }
            discoveredNodes = try await NodeDiscovery.discoverNodes(registryUrl: registryUrl, registryPrefix: expectedPrefix)
            log("Found \(discoveredNodes.count) nodes")

            // Cache nodes for fallback
            saveCachedNodes(discoveredNodes)

            for node in discoveredNodes {
                let latencyStr = node.latencyMs.map { "\($0)ms" } ?? "-"
                log("  \(node.nodeId) [\(node.status)] - \(latencyStr)")
            }

            // Auto-select the fastest ready node
            if let fastestNode = discoveredNodes.first(where: { $0.status == .ready && $0.latencyMs != nil }) {
                selectNode(fastestNode)
                log("Auto-selected \(fastestNode.displayName) (\(fastestNode.latencyMs ?? 0)ms)")
            }
        } catch {
            log("ERROR: Node discovery failed: \(error.localizedDescription)")

            // Clear cached nodes on verification failure - don't trust unverified data
            discoveredNodes = []
            clearCachedNodes()
            errorMessage = "Node discovery failed: \(error.localizedDescription)"
        }
    }

    /// Select a discovered node and update the client
    func selectNode(_ node: RegistryNode) {
        guard let client = client else { return }

        selectedDiscoveredNode = node
        do {
            try client.setURL(node.kelsUrl)
            saveNodeUrl(node.kelsUrl)
            log("Switched to \(node.displayName) (\(node.kelsUrl))")
            Task { await refreshStatus() }
        } catch {
            log("ERROR: Failed to switch to node: \(error.localizedDescription)")
            errorMessage = "Failed to switch node: \(error.localizedDescription)"
        }
    }

    /// Auto-select the fastest available node from registry
    func autoSelectNode() async {
        guard !registryUrl.isEmpty else {
            log("ERROR: Registry URL not configured")
            errorMessage = "Registry URL not configured"
            return
        }

        isLoading = true
        defer { isLoading = false }

        log("Auto-selecting fastest node...")

        do {
            // Use trusted prefix for cryptographic verification
            guard let expectedPrefix = getExpectedPrefix() else {
                throw NSError(domain: "KelsClient", code: 1, userInfo: [NSLocalizedDescriptionKey: "No trusted prefix found for \(selectedRegistry)"])
            }
            // Discover nodes (this will also cache them)
            let nodes = try await NodeDiscovery.discoverNodes(registryUrl: registryUrl, registryPrefix: expectedPrefix)
            discoveredNodes = nodes
            saveCachedNodes(nodes)

            if let fastestNode = nodes.first(where: { $0.status == .ready && $0.latencyMs != nil }) {
                selectNode(fastestNode)
                log("Auto-selected \(fastestNode.displayName) (\(fastestNode.latencyMs ?? 0)ms)")
            } else {
                log("ERROR: No ready nodes available")
                errorMessage = "No ready nodes available"
            }
        } catch {
            log("ERROR: Registry unavailable: \(error.localizedDescription)")

            // Clear cached nodes on verification failure - don't trust unverified data
            discoveredNodes = []
            clearCachedNodes()
            errorMessage = "Auto-select failed: \(error.localizedDescription)"
        }
    }

    /// Test latency to a KELS node
    private func testLatency(to kelsUrl: String) async -> UInt64? {
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

    private func initializeClient() {
        let savedPrefix = loadSavedPrefix()
        log("Loading with prefix: \(savedPrefix ?? "none")")
        log("Connecting to: \(currentNodeUrl)")

        do {
            client = try KelsClient(kelsURL: currentNodeUrl, keyNamespace: keyNamespace, prefix: savedPrefix)
            log("Client initialized successfully")
            Task {
                await refreshStatus()
                await refreshKelList()
            }
        } catch {
            log("ERROR: Failed to initialize client: \(error.localizedDescription)")
            errorMessage = "Failed to initialize: \(error.localizedDescription)"
        }
    }

    func refreshStatus() async {
        guard let client = client else {
            log("ERROR: Client not initialized")
            return
        }

        do {
            let status = try client.status()
            isIncepted = status.prefix != nil
            prefix = status.prefix
            eventCount = status.eventCount
            latestSaid = status.latestSaid
            isDivergent = status.isDivergent
            isContested = status.isContested
            isDecommissioned = status.isDecommissioned
            useHardware = status.useHardware

            // Persist prefix for app restart
            if let prefix = status.prefix {
                savePrefix(prefix)
            }

            if isDivergent {
                needsRecovery = true
            }

            log("Status: incepted=\(isIncepted), events=\(eventCount), hardware=\(useHardware)")
        } catch KelsClientError.notIncepted {
            isIncepted = false
            prefix = nil
            eventCount = 0
            log("Not incepted yet")
        } catch {
            log("ERROR: Failed to get status: \(error.localizedDescription)")
        }
    }

    func refreshKelList() async {
        guard let client = client else { return }

        do {
            kelPrefixes = try client.list()
            log("Found \(kelPrefixes.count) local KELs")
        } catch {
            log("ERROR: Failed to list KELs: \(error.localizedDescription)")
        }
    }

    // MARK: - KEL Operations

    func incept() async {
        isLoading = true
        defer { isLoading = false }

        guard let client = client else {
            log("ERROR: Client not initialized")
            errorMessage = "Client not initialized"
            return
        }

        log("Creating new KEL (inception)...")

        do {
            let event = try client.incept()
            log("KEL created successfully!")
            log("Prefix: \(event.prefix)")
            log("SAID: \(event.said)")
            savePrefix(event.prefix)
            await refreshStatus()
            await refreshKelList()
        } catch {
            log("ERROR: Inception failed: \(error.localizedDescription)")
            errorMessage = "Inception failed: \(error.localizedDescription)"
        }
    }

    func interact(anchor: String) async {
        isLoading = true
        defer { isLoading = false }

        guard let client = client else {
            log("ERROR: Client not initialized")
            errorMessage = "Client not initialized"
            return
        }

        log("Creating interaction event with anchor: \(anchor)")

        do {
            let event = try client.interact(anchor: anchor)
            log("Interaction event created: \(event.said)")
            await refreshStatus()
        } catch {
            log("ERROR: Interaction failed: \(error.localizedDescription)")
            if checkForDivergence(error: error) {
                await refreshStatus()
            } else {
                errorMessage = "Interaction failed: \(error.localizedDescription)"
            }
        }
    }

    // MARK: - Key Management

    func rotateKey() async {
        isLoading = true
        defer { isLoading = false }

        guard let client = client else {
            log("ERROR: Client not initialized")
            errorMessage = "Client not initialized"
            return
        }

        log("Rotating signing key...")

        do {
            let event = try client.rotate()
            log("Key rotated successfully: \(event.said)")
            await refreshStatus()
        } catch {
            log("ERROR: Key rotation failed: \(error.localizedDescription)")
            if checkForDivergence(error: error) {
                await refreshStatus()
            } else {
                errorMessage = "Key rotation failed: \(error.localizedDescription)"
            }
        }
    }

    func rotateRecoveryKey() async {
        isLoading = true
        defer { isLoading = false }

        guard let client = client else {
            log("ERROR: Client not initialized")
            errorMessage = "Client not initialized"
            return
        }

        log("Rotating recovery key...")

        do {
            let event = try client.rotateRecovery()
            log("Recovery key rotated successfully: \(event.said)")
            await refreshStatus()
        } catch {
            log("ERROR: Recovery key rotation failed: \(error.localizedDescription)")
            if checkForDivergence(error: error) {
                await refreshStatus()
            } else {
                errorMessage = "Recovery key rotation failed: \(error.localizedDescription)"
            }
        }
    }

    func recover() async {
        isLoading = true
        defer { isLoading = false }

        guard let client = client else {
            log("ERROR: Client not initialized")
            errorMessage = "Client not initialized"
            return
        }

        log("Attempting recovery...")

        do {
            let (outcome, event) = try client.recover()
            switch outcome {
            case .recovered:
                log("Recovery successful: \(event.said)")
                needsRecovery = false
                needsContest = false
            case .contested:
                log("KEL CONTESTED - adversary had recovery key")
                isContested = true
                needsRecovery = false
                needsContest = false
            case .failed:
                log("Recovery failed")
                errorMessage = "Recovery failed"
            }
            await refreshStatus()
        } catch KelsClientError.recoveryProtected {
            log("Recovery protected - adversary used recovery key, contest required")
            needsContest = true
            needsRecovery = false
            errorMessage = "Adversary used recovery key. Use 'Contest' to freeze the KEL."
        } catch {
            log("ERROR: Recovery failed: \(error.localizedDescription)")
            errorMessage = "Recovery failed: \(error.localizedDescription)"
        }
    }

    func contest() async {
        isLoading = true
        defer { isLoading = false }

        guard let client = client else {
            log("ERROR: Client not initialized")
            errorMessage = "Client not initialized"
            return
        }

        log("Contesting malicious recovery...")

        do {
            let event = try client.contest()
            log("KEL CONTESTED successfully: \(event.said)")
            isContested = true
            needsRecovery = false
            needsContest = false
            await refreshStatus()
        } catch {
            log("ERROR: Contest failed: \(error.localizedDescription)")
            errorMessage = "Contest failed: \(error.localizedDescription)"
        }
    }

    func decommission() async {
        isLoading = true
        defer { isLoading = false }

        guard let client = client else {
            log("ERROR: Client not initialized")
            errorMessage = "Client not initialized"
            return
        }

        log("Decommissioning KEL...")

        do {
            let event = try client.decommission()
            log("KEL decommissioned: \(event.said)")
            isDecommissioned = true
            await refreshStatus()
        } catch {
            log("ERROR: Decommission failed: \(error.localizedDescription)")
            errorMessage = "Decommission failed: \(error.localizedDescription)"
        }
    }

    // MARK: - KEL Query

    func getKel(prefix: String? = nil) -> String? {
        guard let client = client else { return nil }

        do {
            return try client.getKel(prefix: prefix)
        } catch {
            log("ERROR: Failed to get KEL: \(error.localizedDescription)")
            return nil
        }
    }

    // MARK: - Reset

    func resetAllState() async {
        isLoading = true
        defer { isLoading = false }

        log("Resetting all local state...")

        do {
            try KelsClient.reset()
            log("Local state reset successfully")

            // Clear saved prefix
            UserDefaults.standard.removeObject(forKey: prefixKey)

            // Reset local state
            isIncepted = false
            prefix = nil
            eventCount = 0
            latestSaid = nil
            isDivergent = false
            isContested = false
            isDecommissioned = false
            needsRecovery = false
            needsContest = false
            kelPrefixes = []

            // Reinitialize client
            client = nil
            initializeClient()
        } catch {
            log("ERROR: Reset failed: \(error.localizedDescription)")
            errorMessage = "Reset failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Error Handling

    private func checkForDivergence(error: Error) -> Bool {
        // Check for recovery protection (adversary used recovery key)
        if case KelsClientError.recoveryProtected = error {
            needsContest = true
            log("Contest needed - adversary used recovery key")
            errorMessage = "Adversary used recovery key. Use 'Contest' to freeze the KEL."
            return true
        }

        // Check for regular divergence
        if case KelsClientError.divergenceDetected = error {
            needsRecovery = true
            isDivergent = true
            log("Recovery needed - KEL divergence detected")
            errorMessage = "KEL divergence detected. Please use 'Recover' to resolve."
            return true
        }

        return false
    }

    // MARK: - Developer Tools

    #if DEV_TOOLS
    @Published var localKelEventCount: Int = 0

    func refreshKelEventCount() async {
        guard let client = client else { return }

        do {
            let status = try client.status()
            localKelEventCount = Int(status.eventCount)
        } catch {
            log("ERROR: Failed to get KEL event count: \(error.localizedDescription)")
            localKelEventCount = 0
        }
    }

    func dumpLocalKel() async {
        guard let client = client else {
            log("ERROR: Client not initialized")
            return
        }

        log("Dumping local KEL...")

        do {
            let dump = try client.dumpKel()
            log("Local KEL:\n\(dump)")
        } catch {
            log("ERROR: KEL dump failed: \(error.localizedDescription)")
        }
    }

    func truncateLocalKel(keepEvents: UInt32) async {
        isLoading = true
        defer { isLoading = false }

        guard let client = client else {
            log("ERROR: Client not initialized")
            return
        }

        log("Truncating local KEL to \(keepEvents) events...")

        do {
            try client.truncateLocalKel(keepEvents: keepEvents)
            log("KEL truncated successfully")
            await refreshKelEventCount()
        } catch {
            log("ERROR: KEL truncation failed: \(error.localizedDescription)")
        }
    }

    func adversaryInjectEvents(_ eventTypes: String) async {
        isLoading = true
        defer { isLoading = false }

        guard let client = client else {
            log("ERROR: Client not initialized")
            errorMessage = "Client not initialized"
            return
        }

        log("Injecting adversary events: \(eventTypes)")

        do {
            try client.adversaryInjectEvents(eventTypes)
            log("Adversary events injected successfully")
            await refreshKelEventCount()
        } catch {
            log("ERROR: Adversary injection failed: \(error.localizedDescription)")
            errorMessage = "Adversary injection failed: \(error.localizedDescription)"
        }
    }

    func clearLog() {
        logOutput = ""
    }
    #endif

    // MARK: - Logging

    private func log(_ message: String) {
        #if DEV_TOOLS
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        logOutput += "[\(timestamp)] \(message)\n"
        #endif
    }
}
