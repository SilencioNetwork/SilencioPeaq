//
//  peaq.swift
//  peaq-iOS
//
//  Created by mac on 05/12/23.
//

import Foundation
import IrohaCrypto

public class DIDDocumentCustomData: NSObject {
    
    //MARK: - Properties
    var id: String!
    var type: String!
    var data: String!
    
    public init(id: String!, type: String!, data: String!) {
        self.id = id
        self.type = type
        self.data = data
    }
}

public class peaq: NSObject {
    
    //MARK: - Properties
    public static let shared: peaq = peaq()
    
    private var engine: WebSocketEngine? = nil
    private var runtimeVersion: RuntimeVersion?
    private var runtimeMetadata: RuntimeMetadataProtocol?
    private var catalog: TypeRegistryCatalog?
    private var extrinsicSubscriptionId: UInt16?
    private var issuerSeed: String = ""
    
    private static let fallbackMaxHashCount: BlockNumber = 250
    private static let maxFinalityLag: BlockNumber = 5
    private static let fallbackPeriod: Moment = 6 * 1000
    private static let mortalPeriod: UInt64 = 5 * 60 * 1000
    
    //MARK: - Functions
    public func generateMnemonicSeed() -> (String?, Error?) {
        do {
            let mnemonicCreator: IRMnemonicCreatorProtocol = IRMnemonicCreator()
            let mnemonic = try mnemonicCreator.randomMnemonic(.entropy128)
            let mnemonicWords = mnemonic.allWords().joined(separator: " ")
            
            return (mnemonicWords, nil)
        } catch {
            return (nil, error)
        }
    }
    
    public func createInstance(baseUrl: String, secretPhrase: String, _ completionHandler: @escaping (_ isSuccess: Bool, _ err: Error?) -> Void) throws {
        do {
            engine = WebSocketEngine(urls: [URL(string: baseUrl)!], logger: nil)
            (runtimeVersion, runtimeMetadata, catalog) = try fetchRuntimeData()
            issuerSeed = secretPhrase
            completionHandler(true, nil)
        } catch {
            completionHandler(false, error)
            throw error
        }
    }
    
    public func createDidDocument(ownerAddress: String, machineAddress: String, machinePublicKey: Data, customData: [DIDDocumentCustomData]?) -> String? {
        let (issuserAddress, addressGetError) = peaq.shared.getAddressFromSeed(machineSeed: issuerSeed)
        if let issuserAddress = issuserAddress {
            let originalData = try? SS58AddressFactory().type(fromAddress: machineAddress)
            
            if let data = originalData?.stringValue.data(using: .utf8) {
                
                if let machineKeypair = peaq.shared.generateKeyPair(machineSeed: issuerSeed) {
                    do {
                        let signature = try machineKeypair.sign(data)
                        print(signature.rawData().toHex())
                        
                        var doc = Document_Document()
                        doc.id = "did:peaq:\(machineAddress)"
                        doc.controller = "did:peaq:\(issuserAddress)"
                        
                        var docVerificationMethod = Document_VerificationMethod()
                        docVerificationMethod.type = .sr25519VerificationKey2020
                        let machineAccountIdOwner = try machinePublicKey.publicKeyToAccountId()
                        let machineAccountAddressOwner = try SS58AddressFactory().address(fromAccountId: machineAccountIdOwner, type: UInt16(SNAddressType.genericSubstrate.rawValue))
                        if let machineAccountAddressData = machineAccountAddressOwner.data(using: .utf8) {
                            docVerificationMethod.id = machineAccountAddressData.toHex()
                            doc.authentications = [machineAccountAddressData.toHex()]
                        }
                        docVerificationMethod.controller = "did:peaq:\(issuserAddress)"
                        docVerificationMethod.publicKeyMultibase = machineAddress
                        doc.verificationMethods = [docVerificationMethod]
                        
                        var docSignature = Document_Signature()
                        docSignature.issuer = issuserAddress
                        docSignature.type = .sr25519VerificationKey2020
                        docSignature.hash = signature.rawData().toHex()
                        doc.signature = docSignature
                        
                        var docService = Document_Service()
                        docService.id = "owner"
                        docService.type = "owner"
                        docService.data = ownerAddress
                        doc.services = [docService]
                        
                        if customData != nil && !customData!.isEmpty {
                            
                            for i in customData! {
                                var docCustomService = Document_Service()
                                docCustomService.id = i.id
                                docCustomService.type = i.type
                                docCustomService.data = i.data
                                doc.services.append(docCustomService)
                            }
                        }
                        
                        return try? doc.jsonUTF8Data().toHex()
                        
                    } catch {
                        print(error.localizedDescription)
                    }
                } else {
                    print("Getting error in keypairOwner")
                }
            } else {
                print("ERROR IN STRING TO DATA")
            }
        } else {
            print(addressGetError?.localizedDescription)
        }
        return nil
    }
    
    public func createDid(name: String, value: String,_ completionHandler: @escaping (_ hashKey: String?, _ err: Error?) -> Void) throws {
        
        let seedResult = try SeedFactory().deriveSeed(from: issuerSeed, password: "")
        
        let keypairOwner = try SR25519KeypairFactory().createKeypairFromSeed(
            seedResult.seed.miniSeed,
            chaincodeList: []
        )
        
        let publicKeyOwner = keypairOwner.publicKey().rawData()
        let privateKeyOwner = keypairOwner.privateKey().rawData()
        
        let accountIdOwner = try publicKeyOwner.publicKeyToAccountId()
        let accountAddressOwner = try SS58AddressFactory().address(fromAccountId: accountIdOwner, type: UInt16(SNAddressType.genericSubstrate.rawValue))
        
        let snPrivateKey = try SNPrivateKey(rawData: privateKeyOwner)
        let snPublicKey = try SNPublicKey(rawData: publicKeyOwner)
        let signerOwner = SNSigner(keypair: SNKeypair(privateKey: snPrivateKey, publicKey: snPublicKey))
        
        let genesisHash = try fetchBlockHash(with: 0)
        
        let nonceOwner = try fetchAccountNonce(with: accountAddressOwner)
        
        let (eraBlockNumber, extrinsicEra) = try executeMortalEraOperation()
        
        let eraBlockHash = try fetchBlockHash(with: eraBlockNumber)
        
        var builder: ExtrinsicBuilderProtocol =
        try ExtrinsicBuilder(
            specVersion: runtimeVersion!.specVersion,
            transactionVersion: runtimeVersion!.transactionVersion,
            genesisHash: genesisHash
        )
        .with(era: extrinsicEra, blockHash: eraBlockHash)
        .with(nonce: nonceOwner)
        .with(address: MultiAddress.accoundId(accountIdOwner))
        
        let call = try generateRuntimeCall(didAccountAddress: accountAddressOwner, didName: name, didValue: value)
        builder = try builder.adding(call: call)
        
        let signingClosure: (Data) throws -> Data = { data in
            let signedData = try signerOwner.sign(data).rawData()
            return signedData
        }
        
        builder = try builder.signing(
            by: signingClosure,
            of: .sr25519,
            using: DynamicScaleEncoder(registry: catalog!, version: UInt64(runtimeVersion!.specVersion)),
            metadata: runtimeMetadata!
        )
        
        let extrinsic = try builder.build(
            encodingBy: DynamicScaleEncoder(registry: catalog!, version: UInt64(runtimeVersion!.specVersion)),
            metadata: runtimeMetadata!
        )
        
        let updateClosure: (ExtrinsicSubscriptionUpdate) -> Void = { update in
            let status = update.params.result
            
            print("status", status)
            DispatchQueue.main.async {
                if case let .inBlock(extrinsicHash) = status {
                    self.engine!.cancelForIdentifier(self.extrinsicSubscriptionId!)
                    self.extrinsicSubscriptionId = nil
                    self.didCompleteExtrinsicSubmission(for: .success(extrinsicHash))
                    completionHandler(extrinsicHash, nil)
                }
            }
        }
        
        let failureClosure: (Error, Bool) -> Void = { error, _ in
            DispatchQueue.main.async {
                self.engine!.cancelForIdentifier(self.extrinsicSubscriptionId!)
                self.extrinsicSubscriptionId = nil
                self.didCompleteExtrinsicSubmission(for: .failure(error))
                completionHandler(nil, error)
            }
        }
        
        self.extrinsicSubscriptionId = try engine!.subscribe(
            RPCMethod.submitAndWatchExtrinsic,
            params: [extrinsic.toHex(includePrefix: true)],
            updateClosure: updateClosure,
            failureClosure: failureClosure
        )
    }
    
    public func read(address: String, name: String) throws -> DidInfo? {
        do {
            let didAccountId = try SS58AddressFactory().accountId(from: address)
            
            let didNameData = name.data(using: .utf8)!
            
            let keyParam = didAccountId.toHex() + didNameData.toHex()
            let keyParamData = try Data(hexString: keyParam)
            let keyParams = [keyParamData]
            
            let path = StorageCodingPath.attributeStore
            guard let entry = runtimeMetadata!.getStorageMetadata(
                in: path.moduleName,
                storageName: path.itemName
            ) else {
                throw NSError(domain: "Invalid storage path", code: 0)
            }
            
            let keyType: String
            let hasher: StorageHasher
            
            switch entry.type {
            case let .map(mapEntry):
                keyType = mapEntry.key
                hasher = mapEntry.hasher
            case let .doubleMap(doubleMapEntry):
                keyType = doubleMapEntry.key1
                hasher = doubleMapEntry.hasher
            case let .nMap(nMapEntry):
                guard
                    let firstKey = nMapEntry.keyVec.first,
                    let firstHasher = nMapEntry.hashers.first else {
                    throw NSError(domain: "Missing required params", code: 0)
                }
                
                keyType = firstKey
                hasher = firstHasher
            case .plain:
                throw NSError(domain: "Incompatible storage type", code: 0)
            }
            
            let keys: [Data] = try keyParams.map { keyParam in
                let encoder = DynamicScaleEncoder(registry: catalog!, version: UInt64(runtimeVersion!.specVersion))
                try encoder.append(keyParam, ofType: keyType)
                
                let encodedParam = try encoder.encode()
                
                let hasedParam: Data = try StorageHasher.blake256.hash(data: encodedParam)
                
                return try StorageKeyFactory().createStorageKey(
                    moduleName: path.moduleName,
                    storageName: path.itemName,
                    key: hasedParam,
                    hasher: hasher
                )
            }
            
            let params = StorageQuery(keys: keys, blockHash: nil)
            
            let queryOperation = JSONRPCQueryOperation(
                engine: engine!,
                method: RPCMethod.queryStorageAt,
                parameters: params
            )
            
            OperationQueue().addOperations([queryOperation], waitUntilFinished: true)
            
            let dataList = try queryOperation.extractNoCancellableResultData().flatMap { StorageUpdateData(update: $0).changes }
                .map(\.value)
            
            let data = dataList.first!
            if data != nil {
                let decoder = try DynamicScaleDecoder(data: data!, registry: catalog!, version: UInt64(runtimeVersion!.specVersion))
                return try decoder.read(type: entry.type.typeName).map(to: DidInfo.self)
            } else {
                return nil
            }
        } catch {
            throw error
        }
    }
    
    public func signData(plainData: String, machineSecretPhrase: String, format: CryptoType) -> String? {
        
        let originalData = plainData.data(using: .utf8)!
        
        do {
            let seedResult = try SeedFactory().deriveSeed(from: machineSecretPhrase, password: "")
            
            var keypairOwner : IRCryptoKeypairProtocol!
            
            if format == .ed25519 {
                keypairOwner = try Ed25519KeypairFactory().createKeypairFromSeed(
                    seedResult.seed.data,
                    chaincodeList: []
                )
                
                let edPrivateKey = try EDPrivateKey(rawData: keypairOwner.privateKey().rawData())
                let signerOwner = EDSigner(privateKey: edPrivateKey)
                
                print("edPrivateKey: ", keypairOwner.privateKey().rawData().toHex())
                print("edPublicKey: ", keypairOwner.publicKey().rawData().toHex())
                
                let signature = try signerOwner.sign(originalData)
                return signature.rawData().toHex()
                
            } else if format == .sr25519 {
                keypairOwner = try SR25519KeypairFactory().createKeypairFromSeed(
                    seedResult.seed.miniSeed,
                    chaincodeList: []
                )
                
                let snPrivateKey = try SNPrivateKey(rawData: keypairOwner.privateKey().rawData())
                let snPublicKey = try SNPublicKey(rawData: keypairOwner.publicKey().rawData())
                let signerOwner = SNSigner(keypair: SNKeypair(privateKey: snPrivateKey, publicKey: snPublicKey))
                
                let signature = try signerOwner.sign(originalData)
                return signature.rawData().toHex()
            }
            
        } catch {
            print(error.localizedDescription)
        }
        return nil
    }
    
    public func storeMachineDataHash(ownerSeed: String, value: String, key: String, _ completionHandler: @escaping (_ hashKey: String?, _ err: Error?) -> Void) throws {
        
        let seedResult = try SeedFactory().deriveSeed(from: ownerSeed, password: "")
        
        let keypairOwner = try SR25519KeypairFactory().createKeypairFromSeed(
            seedResult.seed.miniSeed,
            chaincodeList: []
        )
        
        let publicKeyOwner = keypairOwner.publicKey().rawData()
        let privateKeyOwner = keypairOwner.privateKey().rawData()
        
        let accountIdOwner = try publicKeyOwner.publicKeyToAccountId()
        let accountAddressOwner = try SS58AddressFactory().address(fromAccountId: accountIdOwner, type: UInt16(SNAddressType.genericSubstrate.rawValue))
        
        let snPrivateKey = try SNPrivateKey(rawData: privateKeyOwner)
        let snPublicKey = try SNPublicKey(rawData: publicKeyOwner)
        let signerOwner = SNSigner(keypair: SNKeypair(privateKey: snPrivateKey, publicKey: snPublicKey))
        
        let genesisHash = try fetchBlockHash(with: 0)
        
        let nonceOwner = try fetchAccountNonce(with: accountAddressOwner)
        
        let (eraBlockNumber, extrinsicEra) = try executeMortalEraOperation()
        
        let eraBlockHash = try fetchBlockHash(with: eraBlockNumber)
        
        var builder: ExtrinsicBuilderProtocol =
        try ExtrinsicBuilder(
            specVersion: runtimeVersion!.specVersion,
            transactionVersion: runtimeVersion!.transactionVersion,
            genesisHash: genesisHash
        )
        .with(era: extrinsicEra, blockHash: eraBlockHash)
        .with(nonce: nonceOwner)
        .with(address: MultiAddress.accoundId(accountIdOwner))
        
        let call = generateRuntimeCallForAddItems(payloadHex: value, itemType: key)
        builder = try builder.adding(call: call)
        
        let signingClosure: (Data) throws -> Data = { data in
            let signedData = try signerOwner.sign(data).rawData()
            return signedData
        }
        
        builder = try builder.signing(
            by: signingClosure,
            of: .sr25519,
            using: DynamicScaleEncoder(registry: catalog!, version: UInt64(runtimeVersion!.specVersion)),
            metadata: runtimeMetadata!
        )
        
        let extrinsic = try builder.build(
            encodingBy: DynamicScaleEncoder(registry: catalog!, version: UInt64(runtimeVersion!.specVersion)),
            metadata: runtimeMetadata!
        )
        
        let updateClosure: (ExtrinsicSubscriptionUpdate) -> Void = { update in
            let status = update.params.result
            
            print("status", status)
            DispatchQueue.main.async {
                if case let .inBlock(extrinsicHash) = status {
                    self.engine!.cancelForIdentifier(self.extrinsicSubscriptionId!)
                    self.extrinsicSubscriptionId = nil
                    self.didCompleteExtrinsicSubmission(for: .success(extrinsicHash))
                    completionHandler(extrinsicHash, nil)
                }
            }
        }
        
        let failureClosure: (Error, Bool) -> Void = { error, _ in
            DispatchQueue.main.async {
                self.engine!.cancelForIdentifier(self.extrinsicSubscriptionId!)
                self.extrinsicSubscriptionId = nil
                self.didCompleteExtrinsicSubmission(for: .failure(error))
                completionHandler(nil, error)
            }
        }
        
        self.extrinsicSubscriptionId = try engine!.subscribe(
            RPCMethod.submitAndWatchExtrinsic,
            params: [extrinsic.toHex(includePrefix: true)],
            updateClosure: updateClosure,
            failureClosure: failureClosure
        )
    }
    
    public func fetchStorageData(address: String, key: String) throws -> JSON? {
        do {
            let accountId = try SS58AddressFactory().accountId(from: address)
            let itemTypeData = key.data(using: .utf8)!
            let keyParam = accountId.toHex() + itemTypeData.toHex()
            let keyParamData = try Data(hexString: keyParam)
            let keyParams = [keyParamData]
            let path = StorageCodingPath.itemStore
            guard let entry = runtimeMetadata!.getStorageMetadata(
                in: path.moduleName,
                storageName: path.itemName
            ) else {
                throw NSError(domain: "Invalid storage path", code: 0)
            }
            print(entry.name)
            print(entry)
            let keyType: String
            let hasher: StorageHasher
            switch entry.type {
            case let .map(mapEntry):
                keyType = mapEntry.key
                hasher = mapEntry.hasher
            case let .doubleMap(doubleMapEntry):
                keyType = doubleMapEntry.key1
                hasher = doubleMapEntry.hasher
            case let .nMap(nMapEntry):
                guard
                    let firstKey = nMapEntry.keyVec.first,
                    let firstHasher = nMapEntry.hashers.first else {
                    throw NSError(domain: "Missing required params", code: 0)
                }
                keyType = firstKey
                hasher = firstHasher
            case .plain:
                throw NSError(domain: "Incompatible storage type", code: 0)
            }
            let keys: [Data] = try keyParams.map { keyParam in
                let encoder = DynamicScaleEncoder(registry: catalog!, version: UInt64(runtimeVersion!.specVersion))
                try encoder.append(keyParam, ofType: keyType)
                let encodedParam = try encoder.encode()
                let hasedParam: Data = try StorageHasher.blake256.hash(data: encodedParam)
                return try StorageKeyFactory().createStorageKey(
                    moduleName: path.moduleName,
                    storageName: path.itemName,
                    key: hasedParam,
                    hasher: hasher
                )
            }
            let params = StorageQuery(keys: keys, blockHash: nil)
            let queryOperation = JSONRPCQueryOperation(
                engine: engine!,
                method: RPCMethod.queryStorageAt,
                parameters: params
            )
            OperationQueue().addOperations([queryOperation], waitUntilFinished: true)
            let dataList = try queryOperation.extractNoCancellableResultData().flatMap { StorageUpdateData(update: $0).changes }
                .map(\.value)
            if let data = dataList.first { // Changed this line
                let decoder = try DynamicScaleDecoder(data: data!, registry: catalog!, version: UInt64(runtimeVersion!.specVersion))
                
                return try decoder.readString()
            } else { // Added this block
                return nil
            }
        } catch {
            throw error
        }
    }
    
    public func verifyData(machinePublicKey: String, plainDataHex: String, signature: String) -> Bool {
        do {
            let signatureData = try Data(hexString: signature)
            let publicKeyData = try Data(hexString: machinePublicKey)
            
            let edPublicKey = try EDPublicKey(rawData: publicKeyData)
            let edVerifier = IrohaCrypto.EDSignatureVerifier()
            if let plain = plainDataHex.data(using: .utf8) {
                let edSignature = try EDSignature(rawData: signatureData)
                let isVerify = edVerifier.verify(edSignature, forOriginalData: plain, usingPublicKey: edPublicKey)
                if isVerify {
                    return isVerify
                }
            }
            
            let snPublicKey = try SNPublicKey(rawData: publicKeyData)
            let snVerifier = IrohaCrypto.SNSignatureVerifier()
            if let plain = plainDataHex.data(using: .utf8) {
                let snSignature = try SNSignature(rawData: signatureData)
                let isVerify = snVerifier.verify(snSignature, forOriginalData: plain, using: snPublicKey)
                return isVerify
            }
        } catch {
            print("Error verifying machine data: \(error)")
            return false
        }
        return false
    }
    
    // TO DO
    func connect() {
        // PEAQ NETWORK WILL CONNECT HERE
    }
    
    // TO DO
    func disConnect() {
        // PEAQ NETWORK WILL DISCONNECT HERE
    }
    
    private func fetchRuntimeData() throws -> (RuntimeVersion, RuntimeMetadataProtocol, TypeRegistryCatalog) {
        do {
            // runtime version
            let versionOperation = JSONRPCListOperation<RuntimeVersion>(engine: engine!,
                                                                 method: RPCMethod.getRuntimeVersion,
                                                                 parameters: [])

            OperationQueue().addOperations([versionOperation], waitUntilFinished: true)

            let runtimeVersion = try versionOperation.extractNoCancellableResultData()

            // runtime metadata
            let metadataOperation = JSONRPCOperation<[String], String>(
                engine: engine!,
                method: RPCMethod.getRuntimeMetadata
            )

            OperationQueue().addOperations([metadataOperation], waitUntilFinished: true)

            let hexMetadata = try metadataOperation.extractNoCancellableResultData()
            let rawMetadata = try Data(hexString: hexMetadata)
            let decoder = try ScaleDecoder(data: rawMetadata)
            let runtimeMetadataContainer = try RuntimeMetadataContainer(scaleDecoder: decoder)
            let runtimeMetadata: RuntimeMetadataProtocol

            // catalog
            let frameworkBundle =  Bundle(for: type(of: self))
            
            let commonTypesUrl = frameworkBundle.url(forResource: "runtime-default", withExtension: "json")!
            let commonTypes = try Data(contentsOf: commonTypesUrl)

            let chainTypeUrl = frameworkBundle.url(forResource: "runtime-peaq", withExtension: "json")!
            let chainTypes = try Data(contentsOf: chainTypeUrl)

            let catalog: TypeRegistryCatalog

            switch runtimeMetadataContainer.runtimeMetadata {
            case let .v13(metadata):
                catalog = try TypeRegistryCatalog.createFromTypeDefinition(
                    commonTypes,
                    versioningData: chainTypes,
                    runtimeMetadata: metadata
                )
                runtimeMetadata = metadata
            case let .v14(metadata):
                catalog = try TypeRegistryCatalog.createFromSiDefinition(
                    versioningData: chainTypes,
                    runtimeMetadata: metadata,
                    customTypeMapper: SiDataTypeMapper(),
                    customNameMapper: ScaleInfoCamelCaseMapper()
                )
                runtimeMetadata = metadata
            }

            return (runtimeVersion, runtimeMetadata, catalog)
        } catch {
            print(error)
            throw error
        }
    }
    
    private func didCompleteExtrinsicSubmission(for result: Result<String, Error>) {
        switch result {
        case let .success(extrinsicHash):
            print("Hash: ", extrinsicHash)
        case let .failure(error):
            print(error.localizedDescription)
        }
    }
    
    private func fetchBlockHash(with blockNumber: BlockNumber) throws -> String {
        let operation = JSONRPCListOperation<String>(engine: engine!,
                                                      method: RPCMethod.getBlockHash,
                                                      parameters: [blockNumber.toHex()])

        OperationQueue().addOperations([operation], waitUntilFinished: true)

        do {
            return try operation.extractNoCancellableResultData()
        } catch {
            throw error
        }
    }
    
    private func fetchAccountNonce(with accountAddress: String) throws -> UInt32 {
        let operation = JSONRPCListOperation<UInt32>(engine: engine!,
                                                     method: RPCMethod.getExtrinsicNonce,
                                                     parameters: [accountAddress])

        OperationQueue().addOperations([operation], waitUntilFinished: true)

        do {
            return try operation.extractNoCancellableResultData()
        } catch {
            throw error
        }
    }
    
    private func fetchPrimitiveConstant(with path: ConstantCodingPath) throws -> JSON {
        guard let entry = runtimeMetadata!.getConstant(in: path.moduleName, constantName: path.constantName) else {
            throw NSError(domain: "Invalid storage path", code: 0)
        }

        do {
            let decoder = try DynamicScaleDecoder(data: entry.value, registry: catalog!, version: UInt64(runtimeVersion!.specVersion))
            return try decoder.read(type: entry.type)
        } catch {
            throw error
        }
    }
    
    private func executeMortalEraOperation() throws -> (BlockNumber, Era) {
        do {
            var path = ConstantCodingPath.blockHashCount
            let blockHashCountOperation: StringScaleMapper<BlockNumber> = try fetchPrimitiveConstant(with: path).map(to: StringScaleMapper<BlockNumber>.self)
            let blockHashCount = blockHashCountOperation.value

            path = ConstantCodingPath.minimumPeriodBetweenBlocks
            let minimumPeriodOperation: StringScaleMapper<Moment> = try fetchPrimitiveConstant(with: path).map(to: StringScaleMapper<Moment>.self)
            let minimumPeriod = minimumPeriodOperation.value

            let blockTime = minimumPeriod

            let unmappedPeriod = (Self.mortalPeriod / UInt64(blockTime)) + UInt64(Self.maxFinalityLag)

            let mortalLength = min(UInt64(blockHashCount), unmappedPeriod)

            let blockNumber = try fetchBlockNumber()

            let constrainedPeriod: UInt64 = min(1 << 16, max(4, mortalLength))
            var period: UInt64 = 1

            while period < constrainedPeriod {
                period = period << 1
            }

            let unquantizedPhase = UInt64(blockNumber) % period
            let quantizeFactor = max(period >> 12, 1)
            let phase = (unquantizedPhase / quantizeFactor) * quantizeFactor

            let eraBlockNumber = ((UInt64(blockNumber) - phase) / period) * period + phase
            return (BlockNumber(eraBlockNumber), Era.mortal(period: period, phase: phase))
        } catch {
            throw error
        }
    }
    
    private func fetchBlockNumber() throws -> BlockNumber {
        do {
            let finalizedBlockHashOperation: JSONRPCListOperation<String> = JSONRPCListOperation(
                engine: engine!,
                method: RPCMethod.getFinalizedBlockHash
            )

            OperationQueue().addOperations([finalizedBlockHashOperation], waitUntilFinished: true)

            let blockHash = try finalizedBlockHashOperation.extractNoCancellableResultData()

            let finalizedHeaderOperation: JSONRPCListOperation<Block.Header> = JSONRPCListOperation(
                engine: engine!,
                method: RPCMethod.getBlockHeader,
                parameters: [blockHash]
            )

            OperationQueue().addOperations([finalizedHeaderOperation], waitUntilFinished: true)

            let finalizedHeader = try finalizedHeaderOperation.extractNoCancellableResultData()

            let currentHeaderOperation: JSONRPCListOperation<Block.Header> = JSONRPCListOperation(
                engine: engine!,
                method: RPCMethod.getBlockHeader
            )

            OperationQueue().addOperations([currentHeaderOperation], waitUntilFinished: true)

            let header = try currentHeaderOperation.extractNoCancellableResultData()

            var bestHeader: Block.Header
            if !header.parentHash.isEmpty {
                let bestHeaderOperation: JSONRPCListOperation<Block.Header> = JSONRPCListOperation(
                    engine: engine!,
                    method: RPCMethod.getBlockHeader,
                    parameters: [header.parentHash]
                )

                OperationQueue().addOperations([bestHeaderOperation], waitUntilFinished: true)

                bestHeader = try bestHeaderOperation.extractNoCancellableResultData()
            } else {
                bestHeader = header
            }

            guard
                let bestNumber = BigUInt.fromHexString(bestHeader.number),
                let finalizedNumber = BigUInt.fromHexString(finalizedHeader.number),
                bestNumber >= finalizedNumber else {
                throw BaseOperationError.unexpectedDependentResult
            }

            let blockNumber = bestNumber - finalizedNumber > Self.maxFinalityLag ? bestNumber : finalizedNumber

            return BlockNumber(blockNumber)
        } catch {
            throw error
        }
    }
    
    public func getAddressFromMachineSeed(machineSeed: String) -> String? {
        do {
            let seedResult = try SeedFactory().deriveSeed(from: machineSeed, password: "")
            
            let keypairOwner = try SR25519KeypairFactory().createKeypairFromSeed(
                seedResult.seed.miniSeed,
                chaincodeList: []
            )
            let publicKeyOwner = keypairOwner.publicKey().rawData()
            
            let accountIdOwner = try publicKeyOwner.publicKeyToAccountId()
            let accountAddressOwner = try SS58AddressFactory().address(fromAccountId: accountIdOwner, type: UInt16(SNAddressType.genericSubstrate.rawValue))
            
            return accountAddressOwner
        } catch {
            print(error.localizedDescription)
        }
        return nil
    }
    
    public func getAddressFromSeed(machineSeed: String) -> (String?, Error?) {
        do {
            let seedResult = try SeedFactory().deriveSeed(from: machineSeed, password: "")
            
            let keypairOwner = try SR25519KeypairFactory().createKeypairFromSeed(
                seedResult.seed.miniSeed,
                chaincodeList: []
            )
            let publicKeyOwner = keypairOwner.publicKey().rawData()
            
            let accountIdOwner = try publicKeyOwner.publicKeyToAccountId()
            let accountAddressOwner = try SS58AddressFactory().address(fromAccountId: accountIdOwner, type: UInt16(SNAddressType.genericSubstrate.rawValue))
            
            return (accountAddressOwner, nil)
        } catch {
            print(error.localizedDescription)
            return (nil, error)
        }
        
    }
    
    public func getPublicKey(machineSeed: String, format: CryptoType) -> String? {
        do {
            let seedResult = try SeedFactory().deriveSeed(from: machineSeed, password: "")
            
            var keypairOwner : IRCryptoKeypairProtocol!
            
            if format == .ed25519 {
                keypairOwner = try Ed25519KeypairFactory().createKeypairFromSeed(
                    seedResult.seed.data,
                    chaincodeList: []
                )
                
            } else if format == .sr25519 {
                keypairOwner = try SR25519KeypairFactory().createKeypairFromSeed(
                    seedResult.seed.miniSeed,
                    chaincodeList: []
                )
            }
            if keypairOwner != nil {
                return keypairOwner.publicKey().rawData().toHex()
            }
        } catch {
            print(error.localizedDescription)
        }
        return nil
    }
    
    public func getPublicPrivateKeyAddressFromMachineSeed(machineSeed: String) -> (Data?, Data?, String?, Error?) {
        do {
            let seedResult = try SeedFactory().deriveSeed(from: machineSeed, password: "")
            
            let keypairOwner = try SR25519KeypairFactory().createKeypairFromSeed(
                seedResult.seed.miniSeed,
                chaincodeList: []
            )
            let publicKeyOwner = keypairOwner.publicKey().rawData()
            let privateKeyOwner = keypairOwner.privateKey().rawData()
            
            let accountIdOwner = try publicKeyOwner.publicKeyToAccountId()
            let accountAddressOwner = try SS58AddressFactory().address(fromAccountId: accountIdOwner, type: UInt16(SNAddressType.genericSubstrate.rawValue))
            
            return (publicKeyOwner, privateKeyOwner, accountAddressOwner, nil)
        } catch {
            print(error.localizedDescription)
            return (nil, nil, nil, error)
        }
    }
    
    public func getED25519PublicPrivateKeyAddressFromMachineSeed(machineSeed: String) -> (Data?, Data?, String?, Error?) {
        do {
            let seedResult = try SeedFactory().deriveSeed(from: machineSeed, password: "")
            
            let keypairOwner = try Ed25519KeypairFactory().createKeypairFromSeed(
                seedResult.seed.miniSeed,
                chaincodeList: []
            )
            let publicKeyOwner = keypairOwner.publicKey().rawData()
            let privateKeyOwner = keypairOwner.privateKey().rawData()
            
            let accountIdOwner = try publicKeyOwner.publicKeyToAccountId()
            let accountAddressOwner = try SS58AddressFactory().address(fromAccountId: accountIdOwner, type: UInt16(SNAddressType.genericSubstrate.rawValue))
            
            return (publicKeyOwner, privateKeyOwner, accountAddressOwner, nil)
        } catch {
            print(error.localizedDescription)
            return (nil, nil, nil, error)
        }
    }
    
    public func generateKeyPair(machineSeed: String) -> SNSignerProtocol? {
        do {
            let seedResult = try SeedFactory().deriveSeed(from: machineSeed, password: "")
            
            let keypairOwner = try SR25519KeypairFactory().createKeypairFromSeed(
                seedResult.seed.miniSeed,
                chaincodeList: []
            )
            
            let snPrivateKey = try SNPrivateKey(rawData: keypairOwner.privateKey().rawData())
            let snPublicKey = try SNPublicKey(rawData: keypairOwner.publicKey().rawData())
            let signerOwner = SNSigner(keypair: SNKeypair(privateKey: snPrivateKey, publicKey: snPublicKey))
            
            return signerOwner
        } catch {
            print(error.localizedDescription)
        }
        return nil
    }
    
    private func generateRuntimeCall(didAccountAddress: String, didName: String, didValue: String) throws -> RuntimeCall<GenerateDidCall> {
        do {
            let didAccountId = try SS58AddressFactory().accountId(from: didAccountAddress)

            let didNameData = didName.data(using: .utf8)!
            let didValueData = didValue.data(using: .utf8)!

            let args = GenerateDidCall(did_account: didAccountId, name: didNameData, value: didValueData, valid_for: nil)

            return RuntimeCall<GenerateDidCall>(
                moduleName: "PeaqDid",
                callName: "add_attribute",
                args: args
            )
        } catch {
            throw error
        }
    }
    
    private func generateRuntimeCallForAddItems(payloadHex: String, itemType: String) -> RuntimeCall<GenerateAddItemCall> {
        
        let payloadHexData = payloadHex.data(using: .utf8)!
        let itemTypeData = itemType.data(using: .utf8)!
        
        let args = GenerateAddItemCall(item_type: itemTypeData, item: payloadHexData)
        
        return RuntimeCall<GenerateAddItemCall>(
            moduleName: "PeaqStorage",
            callName: "add_item",
            args: args
        )
    }
   
}

enum SNAddressType: UInt8 {
    case polkadotMain = 0
    case polkadotSecondary = 1
    case kusamaMain = 2
    case kusamaSecondary = 3
    case genericSubstrate = 42
}

struct RuntimeVersion: Codable, Equatable {
    let specVersion: UInt32
    let transactionVersion: UInt32
}

final class SiDataTypeMapper: SiTypeMapping {
    func map(type: RuntimeType, identifier _: String) -> Node? {
        if type.path == ["pallet_identity", "types", "Data"] {
            return DataNode()
        } else {
            return nil
        }
    }
}

struct GenerateDidCall: Codable {
    @BytesCodable var did_account: Data
    @BytesCodable var name: Data
    @BytesCodable var value: Data
    @OptionStringCodable var valid_for: BlockNumber?
}

struct GenerateAddItemCall: Codable {
    @BytesCodable var item_type: Data
    @BytesCodable var item: Data
}

extension StringProtocol {
    var hexa: [UInt8] {
        var startIndex = self.startIndex
        return (0..<count/2).compactMap { _ in
            let endIndex = index(after: startIndex)
            defer { startIndex = index(after: endIndex) }
            return UInt8(self[startIndex...endIndex], radix: 16)
        }
    }
}

extension DataProtocol {
    var data: Data { .init(self) }
    var hexa: String { map { .init(format: "%02x", $0) }.joined() }
}
