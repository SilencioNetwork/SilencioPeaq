import Foundation

public struct DidInfo: Codable, Equatable {
    @BytesCodable public var name: Data
    @BytesCodable public var value: Data
    @StringCodable public var validity: BlockNumber
    @StringCodable public var created: UInt64
}
