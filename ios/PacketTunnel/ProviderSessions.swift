import Foundation
import NetworkExtension

/// Wraps `NEPacketTunnelProvider.createTCPConnection` / `createUDPSession`.
/// Provider-created flows bypass the tunnel automatically.
final class ProviderSessionFactory: OutboundSessionFactory {
    private weak var provider: NEPacketTunnelProvider?

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    func makeTCP(host: String, port: Int) -> OutboundTCPConnection {
        ProviderTCPConnection(provider: provider, host: host, port: port)
    }

    func makeUDP(host: String, port: Int) -> OutboundUDPSession {
        ProviderUDPSession(provider: provider, host: host, port: port)
    }
}

private final class ProviderTCPConnection: OutboundTCPConnection {
    private let connection: NWTCPConnection?
    private var observation: NSKeyValueObservation?
    private var finishedConnect = false
    private let lock = NSLock()

    init(provider: NEPacketTunnelProvider?, host: String, port: Int) {
        if let provider {
            let endpoint = NWHostEndpoint(hostname: host, port: String(port))
            connection = provider.createTCPConnection(
                to: endpoint,
                enableTLS: false,
                tlsParameters: nil,
                delegate: nil
            )
        } else {
            connection = nil
        }
    }

    func connect(timeout: TimeInterval, completion: @escaping (Error?) -> Void) {
        guard let connection else {
            completion(RelayError.connectFailed)
            return
        }
        func finish(_ error: Error?) {
            lock.lock()
            defer { lock.unlock() }
            guard !finishedConnect else { return }
            finishedConnect = true
            observation?.invalidate()
            observation = nil
            completion(error)
        }
        observation = connection.observe(\.state, options: [.new, .initial]) { conn, _ in
            switch conn.state {
            case .connected:
                finish(nil)
            case .disconnected, .cancelled, .invalid:
                finish(RelayError.connectFailed)
            default:
                break
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let already = self.finishedConnect
            self.lock.unlock()
            if !already {
                connection.cancel()
                finish(RelayError.timeout)
            }
        }
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard let connection else {
            completion(RelayError.connectFailed)
            return
        }
        connection.write(data) { error in
            completion(error)
        }
    }

    func read(maximumLength: Int, completion: @escaping (Data?, Error?) -> Void) {
        guard let connection else {
            completion(nil, RelayError.connectFailed)
            return
        }
        connection.readMinimumLength(1, maximumLength: maximumLength) { data, error in
            completion(data, error)
        }
    }

    func cancel() {
        observation?.invalidate()
        observation = nil
        connection?.cancel()
    }
}

private final class ProviderUDPSession: OutboundUDPSession {
    private let session: NWUDPSession?
    private var observation: NSKeyValueObservation?
    private var queued: [Data] = []
    private var ready = false
    private let lock = NSLock()
    private var readHandler: ((Data) -> Void)?

    init(provider: NEPacketTunnelProvider?, host: String, port: Int) {
        if let provider {
            let endpoint = NWHostEndpoint(hostname: host, port: String(port))
            session = provider.createUDPSession(to: endpoint, from: nil)
        } else {
            session = nil
        }
        observation = session?.observe(\.state, options: [.new, .initial]) { [weak self] sess, _ in
            if sess.state == .ready {
                self?.flushQueue()
            }
        }
        session?.setReadHandler({ [weak self] datagrams, _ in
            guard let self, let datagrams else { return }
            for data in datagrams {
                self.readHandler?(data)
            }
        }, maxDatagrams: 32)
    }

    func write(_ data: Data) {
        lock.lock()
        if ready {
            lock.unlock()
            session?.writeDatagram(data, completionHandler: { _ in })
        } else {
            queued.append(data)
            lock.unlock()
        }
    }

    func setReadHandler(_ handler: @escaping (Data) -> Void) {
        readHandler = handler
    }

    func cancel() {
        observation?.invalidate()
        observation = nil
        session?.cancel()
    }

    private func flushQueue() {
        lock.lock()
        ready = true
        let pending = queued
        queued.removeAll()
        lock.unlock()
        for data in pending {
            session?.writeDatagram(data, completionHandler: { _ in })
        }
    }
}

final class PacketFlowWriter: TunWriting {
    private let flow: NEPacketTunnelFlow
    private let lock = NSLock()

    init(flow: NEPacketTunnelFlow) {
        self.flow = flow
    }

    func write(_ buf: [UInt8], length: Int) {
        let data = Data(buf.prefix(length))
        lock.lock()
        flow.writePackets([data], withProtocols: [NSNumber(value: AF_INET)])
        lock.unlock()
    }
}
