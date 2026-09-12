import Foundation

/// Serialized writer for the TUN device. Many relay callbacks write reply packets.
public protocol TunWriting: AnyObject {
    func write(_ buf: [UInt8], length: Int)
}

public final class CallbackTunWriter: TunWriting, @unchecked Sendable {
    private let lock = NSLock()
    private let sink: ([UInt8], Int) -> Void

    public init(_ sink: @escaping ([UInt8], Int) -> Void) {
        self.sink = sink
    }

    public func write(_ buf: [UInt8], length: Int) {
        lock.lock()
        sink(buf, length)
        lock.unlock()
    }
}
