import Foundation

struct DidInfo: Codable, Equatable {
    @BytesCodable var name: Data
    @BytesCodable var value: Data
    @StringCodable var validity: BlockNumber
    @StringCodable var created: UInt64
}
