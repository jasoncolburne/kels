import SwiftUI
import UIKit

// MARK: - IdentifiableString

struct IdentifiableString: Identifiable {
    let id = UUID()
    let value: String
}

// MARK: - StyledTabView

struct StyledTabItem {
    let title: String
    let icon: String
    let enabled: Bool
}

struct StyledTabView<Content: View>: View {
    @Binding var selection: Int
    let items: [StyledTabItem]
    @ViewBuilder let content: (Int) -> Content

    var body: some View {
        VStack(spacing: 0) {
            content(selection)
                .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()

            HStack(spacing: 0) {
                ForEach(items.indices, id: \.self) { index in
                    let item = items[index]
                    Button {
                        if item.enabled {
                            selection = index
                        }
                    } label: {
                        VStack(spacing: 4) {
                            Image(systemName: item.icon)
                                .font(.system(size: 22))
                            Text(item.title)
                                .font(.caption2)
                        }
                        .frame(maxWidth: .infinity)
                        .foregroundColor(tabColor(index: index, item: item))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.top, 8)
            .padding(.bottom, 4)
            .background(Color(UIColor.systemBackground))
        }
    }

    private func tabColor(index: Int, item: StyledTabItem) -> Color {
        if !item.enabled {
            return .gray.opacity(0.4)
        }
        return index == selection ? .accentColor : .gray
    }
}

// MARK: - ContentView

struct ContentView: View {
    @StateObject private var viewModel = KelsViewModel()
    @State private var selectedTab = 0

    private var tabItems: [StyledTabItem] {
        var items = [
            StyledTabItem(title: "KELs", icon: "key.horizontal", enabled: true),
            StyledTabItem(title: "Keys", icon: "lock.rotation", enabled: viewModel.isIncepted),
            StyledTabItem(title: "Settings", icon: "gear", enabled: true),
        ]
        #if DEV_TOOLS
        items.append(StyledTabItem(title: "Dev", icon: "hammer", enabled: true))
        #endif
        return items
    }

    var body: some View {
        StyledTabView(selection: $selectedTab, items: tabItems) { tab in
            switch tab {
            case 0: KelsTab(viewModel: viewModel)
            case 1: KeysTab(viewModel: viewModel)
            case 2: SettingsTab(viewModel: viewModel)
            #if DEV_TOOLS
            case 3: DeveloperTab(viewModel: viewModel)
            #endif
            default: EmptyView()
            }
        }
        .onChange(of: viewModel.isIncepted) {
            if viewModel.isIncepted && selectedTab > 0 {
                // Stay on current tab
            } else if !viewModel.isIncepted {
                selectedTab = 0
            }
        }
        .overlay {
            if viewModel.isLoading {
                ProgressView()
                    .scaleEffect(1.5)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color.black.opacity(0.2))
            }
        }
        .alert("Error", isPresented: .init(
            get: { viewModel.errorMessage != nil },
            set: { if !$0 { viewModel.errorMessage = nil } }
        )) {
            Button("OK") { viewModel.errorMessage = nil }
        } message: {
            Text(viewModel.errorMessage ?? "")
        }
    }
}

// MARK: - KELs Tab

struct KelsTab: View {
    @ObservedObject var viewModel: KelsViewModel
    @State private var anchorText = ""
    @State private var kelJsonContent: IdentifiableString?
    @State private var copiedMessage: String?

    var body: some View {
        NavigationStack {
            List {
                // Status Section
                if viewModel.isIncepted {
                    Section("Current KEL") {
                        if let prefix = viewModel.prefix {
                            Button {
                                UIPasteboard.general.string = prefix
                                showCopied("Prefix")
                            } label: {
                                HStack {
                                    Text("Prefix")
                                        .foregroundColor(.primary)
                                    Spacer()
                                    Text(prefix)
                                        .font(.caption)
                                        .lineLimit(1)
                                        .foregroundColor(.secondary)
                                    Image(systemName: "doc.on.doc")
                                        .font(.caption)
                                        .foregroundColor(.accentColor)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }

                        HStack {
                            Text("Events")
                            Spacer()
                            Text("\(viewModel.eventCount)")
                                .foregroundColor(.secondary)
                        }

                        if let said = viewModel.latestSaid {
                            Button {
                                UIPasteboard.general.string = said
                                showCopied("Latest SAID")
                            } label: {
                                HStack {
                                    Text("Latest SAID")
                                        .foregroundColor(.primary)
                                    Spacer()
                                    Text(said)
                                        .font(.caption)
                                        .lineLimit(1)
                                        .foregroundColor(.secondary)
                                    Image(systemName: "doc.on.doc")
                                        .font(.caption)
                                        .foregroundColor(.accentColor)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }

                        // Status indicators
                        if viewModel.isDivergent {
                            HStack {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundColor(.orange)
                                Text("Divergence Detected")
                                    .foregroundColor(.orange)
                            }
                        }

                        if viewModel.isContested {
                            HStack {
                                Image(systemName: "xmark.shield.fill")
                                    .foregroundColor(.red)
                                Text("KEL Contested (Frozen)")
                                    .foregroundColor(.red)
                            }
                        }

                        if viewModel.isDecommissioned {
                            HStack {
                                Image(systemName: "lock.slash.fill")
                                    .foregroundColor(.orange)
                                Text("KEL Decommissioned")
                                    .foregroundColor(.orange)
                            }
                        }

                        // View KEL button
                        Button {
                            if let json = viewModel.getKel() {
                                kelJsonContent = IdentifiableString(value: json)
                            }
                        } label: {
                            HStack {
                                Image(systemName: "doc.text")
                                Text("View KEL JSON")
                            }
                        }
                    }

                    // Interaction Section
                    if !viewModel.isContested && !viewModel.isDecommissioned {
                        Section("Anchor Data") {
                            HStack {
                                TextField("Data to anchor (e.g., hash)", text: $anchorText)
                                    .textInputAutocapitalization(.never)
                                    .autocorrectionDisabled()

                                Button(action: createInteraction) {
                                    Image(systemName: "plus.circle.fill")
                                }
                                .disabled(anchorText.isEmpty || viewModel.isLoading)
                            }

                            Text("Create an interaction event to anchor data to your KEL")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }

                // Create KEL Section
                if !viewModel.isIncepted {
                    Section("Create KEL") {
                        Button(action: { Task { await viewModel.incept() } }) {
                            HStack {
                                Image(systemName: "plus.circle.fill")
                                Text("Create New KEL")
                            }
                        }
                        .disabled(viewModel.isLoading)

                        Text("Create a new Key Event Log with inception event")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                // Local KELs Section
                if !viewModel.kelPrefixes.isEmpty {
                    Section("Local KELs (\(viewModel.kelPrefixes.count))") {
                        ForEach(viewModel.kelPrefixes, id: \.self) { prefix in
                            Button {
                                UIPasteboard.general.string = prefix
                                showCopied("Prefix")
                            } label: {
                                HStack {
                                    if prefix == viewModel.prefix {
                                        Image(systemName: "checkmark.circle.fill")
                                            .foregroundColor(.green)
                                    }
                                    Text(prefix)
                                        .font(.caption.monospaced())
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                        .foregroundColor(.primary)
                                    Spacer()
                                    Image(systemName: "doc.on.doc")
                                        .font(.caption)
                                        .foregroundColor(.accentColor)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }
            .navigationTitle("KELs")
            .refreshable {
                await viewModel.refreshStatus()
                await viewModel.refreshKelList()
            }
            .sheet(item: $kelJsonContent) { content in
                KelJsonSheet(json: content.value)
            }
            .overlay(alignment: .bottom) {
                if let message = copiedMessage {
                    Text("\(message) copied!")
                        .font(.caption)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(Color.black.opacity(0.75))
                        .foregroundColor(.white)
                        .cornerRadius(8)
                        .padding(.bottom, 20)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.easeInOut(duration: 0.2), value: copiedMessage)
        }
    }

    private func createInteraction() {
        let anchor = anchorText.trimmingCharacters(in: .whitespaces)
        guard !anchor.isEmpty else { return }
        Task {
            await viewModel.interact(anchor: anchor)
            anchorText = ""
        }
    }

    private func showCopied(_ what: String) {
        copiedMessage = what
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            copiedMessage = nil
        }
    }
}

// MARK: - KEL JSON Sheet

struct KelJsonSheet: View {
    let json: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(json)
                    .font(.caption.monospaced())
                    .padding()
            }
            .navigationTitle("KEL JSON")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        UIPasteboard.general.string = json
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                }
            }
        }
    }
}

// MARK: - Keys Tab

struct KeysTab: View {
    @ObservedObject var viewModel: KelsViewModel
    @State private var showingDecommissionConfirm = false
    @State private var showingRotateSuccess = false
    @State private var showingRecoverSuccess = false
    @State private var showingContestSuccess = false
    @State private var showingDecommissionSuccess = false

    private var isFrozen: Bool {
        viewModel.isContested || viewModel.isDecommissioned
    }

    var body: some View {
        NavigationStack {
            List {
                // Status Section
                Section("Key Status") {
                    HStack {
                        Text("Using Hardware Keys")
                        Spacer()
                        Text(viewModel.useHardware ? "Yes (Secure Enclave)" : "No")
                            .foregroundColor(viewModel.useHardware ? .green : .secondary)
                    }

                    if viewModel.isContested {
                        HStack {
                            Image(systemName: "xmark.shield.fill")
                                .foregroundColor(.red)
                            Text("Contested")
                                .foregroundColor(.red)
                        }
                    } else if viewModel.needsContest {
                        HStack {
                            Image(systemName: "exclamationmark.shield.fill")
                                .foregroundColor(.red)
                            Text("Contest Required")
                                .foregroundColor(.red)
                        }
                    } else if viewModel.needsRecovery {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text("Recovery Required")
                                .foregroundColor(.orange)
                        }
                    }
                }

                // Key Operations
                Section("Key Operations") {
                    if viewModel.needsContest && !viewModel.isContested {
                        Button(action: {
                            Task {
                                await viewModel.recover()
                                if viewModel.errorMessage == nil {
                                    showingContestSuccess = true
                                }
                            }
                        }) {
                            HStack {
                                Image(systemName: "xmark.shield")
                                Text("Contest")
                            }
                            .foregroundColor(.red)
                        }
                        .disabled(viewModel.isLoading)
                    } else if viewModel.needsRecovery && !viewModel.isContested {
                        Button(action: {
                            Task {
                                await viewModel.recover()
                                if viewModel.errorMessage == nil && !viewModel.isContested {
                                    showingRecoverSuccess = true
                                }
                            }
                        }) {
                            HStack {
                                Image(systemName: "exclamationmark.arrow.circlepath")
                                Text("Recover")
                            }
                            .foregroundColor(.orange)
                        }
                        .disabled(viewModel.isLoading)
                    } else if viewModel.isContested {
                        // Show disabled recovery button for contested KEL
                        HStack {
                            Image(systemName: "exclamationmark.arrow.circlepath")
                            Text("Recover")
                        }
                        .foregroundColor(.secondary)
                        .opacity(0.4)
                    } else {
                        Button(action: {
                            Task {
                                await viewModel.rotateKey()
                                if viewModel.errorMessage == nil {
                                    showingRotateSuccess = true
                                }
                            }
                        }) {
                            HStack {
                                Image(systemName: "arrow.triangle.2.circlepath")
                                Text("Rotate Signing Key")
                            }
                        }
                        .disabled(viewModel.isLoading || isFrozen)

                        Button(action: {
                            Task {
                                await viewModel.rotateRecoveryKey()
                                if viewModel.errorMessage == nil {
                                    showingRotateSuccess = true
                                }
                            }
                        }) {
                            HStack {
                                Image(systemName: "arrow.triangle.2.circlepath.circle")
                                Text("Rotate Recovery Key")
                            }
                        }
                        .disabled(viewModel.isLoading || isFrozen)
                    }
                }

                // Danger Zone
                Section("Danger Zone") {
                    Button(action: { showingDecommissionConfirm = true }) {
                        HStack {
                            Image(systemName: "lock.slash")
                            Text("Decommission KEL")
                        }
                        .foregroundColor(.red)
                    }
                    .disabled(viewModel.isLoading || isFrozen)
                    .opacity(isFrozen ? 0.4 : 1.0)
                    .confirmationDialog("Decommission KEL?", isPresented: $showingDecommissionConfirm) {
                        Button("Decommission", role: .destructive) {
                            Task {
                                await viewModel.decommission()
                                if viewModel.errorMessage == nil {
                                    showingDecommissionSuccess = true
                                }
                            }
                        }
                    } message: {
                        Text("This will PERMANENTLY freeze your KEL. You will not be able to add events or rotate keys. This action is IRREVERSIBLE.")
                    }
                }

                // Info
                Section {
                    Text("Regularly rotating your signing key helps protect against key compromise. The recovery key is used to recover your KEL if divergence is detected.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("Keys")
            .refreshable {
                await viewModel.refreshStatus()
            }
            .alert("Key Rotated", isPresented: $showingRotateSuccess) {
                Button("OK") { showingRotateSuccess = false }
            } message: {
                Text("Your key has been successfully rotated. Thank you for keeping your identity secure.")
            }
            .alert("Recovery Complete", isPresented: $showingRecoverSuccess) {
                Button("OK") { showingRecoverSuccess = false }
            } message: {
                Text("Your KEL has been recovered successfully.")
            }
            .alert("KEL Contested", isPresented: $showingContestSuccess) {
                Button("OK") { showingContestSuccess = false }
            } message: {
                Text("The KEL has been contested and frozen. The adversary had your recovery key (full compromise). This identity can no longer be used.")
            }
            .alert("KEL Decommissioned", isPresented: $showingDecommissionSuccess) {
                Button("OK") { showingDecommissionSuccess = false }
            } message: {
                Text("Your KEL has been permanently frozen and can no longer be modified.")
            }
        }
    }
}

// MARK: - Settings Tab

struct SettingsTab: View {
    @ObservedObject var viewModel: KelsViewModel
    @State private var copiedMessage: String?
    @State private var isDiscovering = false

    private let defaultRegistryUrl = "http://kels-registry.kels-registry.local"

    var body: some View {
        NavigationStack {
            List {
                // Registry Configuration
                Section("Node Registry") {
                    TextField("Registry URL", text: $viewModel.registryUrl)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onAppear {
                            if viewModel.registryUrl.isEmpty {
                                viewModel.registryUrl = defaultRegistryUrl
                            }
                        }

                    HStack {
                        Button(action: {
                            isDiscovering = true
                            Task {
                                await viewModel.discoverNodes()
                                isDiscovering = false
                            }
                        }) {
                            HStack {
                                if isDiscovering {
                                    ProgressView()
                                        .scaleEffect(0.8)
                                } else {
                                    Image(systemName: "arrow.clockwise")
                                }
                                Text("Discover")
                            }
                        }
                        .disabled(isDiscovering || viewModel.registryUrl.isEmpty)

                        Spacer()

                        Button(action: {
                            isDiscovering = true
                            Task {
                                await viewModel.autoSelectNode()
                                isDiscovering = false
                            }
                        }) {
                            HStack {
                                Image(systemName: "bolt.fill")
                                Text("Auto-Select")
                            }
                        }
                        .disabled(isDiscovering || viewModel.registryUrl.isEmpty)
                    }
                }

                // Discovered Nodes
                Section("KELS Nodes") {
                    if viewModel.discoveredNodes.isEmpty {
                        Text("Tap 'Discover' to find nodes")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    } else {
                        ForEach(viewModel.discoveredNodes) { node in
                            Button {
                                viewModel.selectNode(node)
                            } label: {
                                HStack {
                                    if viewModel.selectedDiscoveredNode?.nodeId == node.nodeId {
                                        Image(systemName: "checkmark.circle.fill")
                                            .foregroundColor(.green)
                                    } else {
                                        Image(systemName: "circle")
                                            .foregroundColor(.secondary)
                                    }

                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(node.displayName)
                                            .foregroundColor(.primary)
                                        Text(node.kelsUrl)
                                            .font(.caption2)
                                            .foregroundColor(.secondary)
                                    }

                                    Spacer()

                                    statusBadge(for: node.status)

                                    if let latency = node.latencyMs {
                                        Text("\(latency)ms")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    } else if node.status == .ready {
                                        Text("-")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .disabled(node.status != .ready)
                            .opacity(node.status == .ready ? 1.0 : 0.5)
                        }
                    }
                }

                // Status
                Section("Status") {
                    HStack {
                        Text("Connected To")
                        Spacer()
                        Text(viewModel.currentNodeUrl)
                            .font(.caption)
                            .lineLimit(1)
                            .foregroundColor(.secondary)
                    }

                    HStack {
                        Text("Secure Enclave")
                        Spacer()
                        Text(viewModel.useHardware ? "In Use" : "Not Available")
                            .foregroundColor(viewModel.useHardware ? .green : .secondary)
                    }

                    HStack {
                        Text("KEL Created")
                        Spacer()
                        if viewModel.isContested {
                            Text("Contested")
                                .foregroundColor(.red)
                        } else if viewModel.isDecommissioned {
                            Text("Decommissioned")
                                .foregroundColor(.orange)
                        } else {
                            Text(viewModel.isIncepted ? "Yes" : "No")
                                .foregroundColor(viewModel.isIncepted ? .green : .secondary)
                        }
                    }

                    if let prefix = viewModel.prefix {
                        Button {
                            UIPasteboard.general.string = prefix
                            showCopied("Prefix")
                        } label: {
                            HStack {
                                Text("Prefix")
                                    .foregroundColor(.primary)
                                Spacer()
                                Text(prefix)
                                    .font(.caption)
                                    .lineLimit(1)
                                    .foregroundColor(.secondary)
                                Image(systemName: "doc.on.doc")
                                    .font(.caption)
                                    .foregroundColor(.accentColor)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }

                // Danger Zone
                Section("Danger Zone") {
                    Button(role: .destructive) {
                        showingResetConfirm = true
                    } label: {
                        HStack {
                            Image(systemName: "trash")
                            Text("Reset All Local State")
                        }
                    }
                }

                // Info
                Section {
                    Text("KELS (Key Event Log Service) provides decentralized key management using self-certifying identifiers.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("Settings")
            .refreshable {
                await viewModel.refreshStatus()
            }
            .overlay(alignment: .bottom) {
                if let message = copiedMessage {
                    Text("\(message) copied!")
                        .font(.caption)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(Color.black.opacity(0.75))
                        .foregroundColor(.white)
                        .cornerRadius(8)
                        .padding(.bottom, 20)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.easeInOut(duration: 0.2), value: copiedMessage)
            .alert("Reset All State?", isPresented: $showingResetConfirm) {
                Button("Cancel", role: .cancel) { }
                Button("Reset", role: .destructive) {
                    Task { await viewModel.resetAllState() }
                }
            } message: {
                Text("This will delete all local KELs, keys, and state. Your identity on the server will still exist but you won't be able to control it. This cannot be undone.")
            }
        }
    }

    @State private var showingResetConfirm = false

    private func showCopied(_ what: String) {
        copiedMessage = what
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            copiedMessage = nil
        }
    }

    @ViewBuilder
    private func statusBadge(for status: RegistryNodeStatus) -> some View {
        switch status {
        case .ready:
            Text("READY")
                .font(.caption2)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.green.opacity(0.2))
                .foregroundColor(.green)
                .cornerRadius(4)
        case .bootstrapping:
            Text("SYNC")
                .font(.caption2)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.yellow.opacity(0.2))
                .foregroundColor(.orange)
                .cornerRadius(4)
        case .unhealthy:
            Text("DOWN")
                .font(.caption2)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.red.opacity(0.2))
                .foregroundColor(.red)
                .cornerRadius(4)
        }
    }
}

// MARK: - Developer Tab

#if DEV_TOOLS
struct DeveloperTab: View {
    @ObservedObject var viewModel: KelsViewModel
    @State private var truncateToCount: String = "1"
    @State private var showingTruncateConfirm = false
    @State private var adversaryEvents: String = ""
    @State private var showingInjectConfirm = false

    var body: some View {
        NavigationStack {
            List {
                // Adversary Injection
                Section("Adversary Injection") {
                    // Event type buttons
                    HStack(spacing: 8) {
                        ForEach(["ixn", "rot", "rec", "ror"], id: \.self) { eventType in
                            Button(eventType.uppercased()) {
                                if !adversaryEvents.isEmpty {
                                    adversaryEvents += ","
                                }
                                adversaryEvents += eventType
                            }
                            .buttonStyle(.bordered)
                            .tint(eventType == "rec" || eventType == "ror" ? .red : .accentColor)
                        }
                    }
                    .disabled(!viewModel.isIncepted || viewModel.isLoading)

                    // Accumulated events display
                    HStack {
                        Text(adversaryEvents.isEmpty ? "(tap events to build sequence)" : adversaryEvents)
                            .font(.caption)
                            .foregroundColor(adversaryEvents.isEmpty ? .secondary : .primary)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        if !adversaryEvents.isEmpty {
                            Button(action: { adversaryEvents = "" }) {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.secondary)
                            }
                            .buttonStyle(.plain)
                        }
                    }

                    // Inject button
                    Button(action: { showingInjectConfirm = true }) {
                        HStack {
                            Image(systemName: "bolt.fill")
                            Text("Inject Events")
                        }
                        .foregroundColor(.red)
                    }
                    .disabled(adversaryEvents.isEmpty || !viewModel.isIncepted || viewModel.isLoading)
                    .confirmationDialog("Inject Adversary Events?", isPresented: $showingInjectConfirm) {
                        Button("Inject: \(adversaryEvents)", role: .destructive) {
                            injectAdversaryEvents()
                        }
                    } message: {
                        Text("This simulates an adversary injecting events into KELS without your knowledge.")
                    }
                }

                // KEL Tools
                Section("KEL Tools") {
                    HStack {
                        Text("Local KEL Events")
                        Spacer()
                        Text("\(viewModel.localKelEventCount)")
                            .foregroundColor(.secondary)
                    }

                    Button(action: { Task { await viewModel.dumpLocalKel() } }) {
                        HStack {
                            Image(systemName: "doc.text")
                            Text("Dump KEL to Log")
                        }
                    }
                    .disabled(!viewModel.isIncepted || viewModel.isLoading || viewModel.localKelEventCount == 0)

                    HStack {
                        Text("Keep:")
                        TextField("", text: $truncateToCount)
                            .keyboardType(.numberPad)
                            .frame(width: 50)

                        Spacer()

                        Button(action: { showingTruncateConfirm = true }) {
                            HStack {
                                Image(systemName: "scissors")
                                Text("Truncate KEL")
                            }
                            .foregroundColor(.orange)
                        }
                        .disabled(!viewModel.isIncepted || viewModel.isLoading || viewModel.localKelEventCount == 0)
                        .confirmationDialog("Truncate KEL?", isPresented: $showingTruncateConfirm) {
                            Button("Truncate", role: .destructive) {
                                truncateKel()
                            }
                        } message: {
                            Text("This will remove events from your local KEL. Use for testing divergence recovery.")
                        }
                    }
                }

                // Log
                Section("Log") {
                    TextEditor(text: .constant(viewModel.logOutput))
                        .font(.caption)
                        .frame(height: 300)
                        .scrollContentBackground(.hidden)

                    HStack {
                        Button("Copy Log") {
                            UIPasteboard.general.string = viewModel.logOutput
                        }
                        .disabled(viewModel.logOutput.isEmpty)

                        Spacer()

                        Button("Clear Log") {
                            viewModel.clearLog()
                        }
                    }
                }
            }
            .navigationTitle("Developer")
            .onAppear {
                Task {
                    await viewModel.refreshKelEventCount()
                    truncateToCount = "\(viewModel.localKelEventCount)"
                }
            }
            .refreshable {
                await viewModel.refreshKelEventCount()
                truncateToCount = "\(viewModel.localKelEventCount)"
            }
        }
    }

    private func truncateKel() {
        guard let count = UInt32(truncateToCount), count > 0 else { return }
        Task {
            await viewModel.truncateLocalKel(keepEvents: count)
        }
    }

    private func injectAdversaryEvents() {
        let events = adversaryEvents
        adversaryEvents = ""
        Task {
            await viewModel.adversaryInjectEvents(events)
        }
    }
}
#endif

#Preview {
    ContentView()
}
