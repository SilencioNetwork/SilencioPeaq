//
//  ViewController.swift
//  Example
//
//  Created by mac on 12/01/24.
//

import UIKit
import peaq_iOS
import IrohaCrypto

class ViewController: UIViewController {

    //MARK: - Outlets
    @IBOutlet weak var btnCreateID: UIButton!
    @IBOutlet weak var btnCopy: UIButton!
    @IBOutlet weak var btnShare: UIButton!
    @IBOutlet weak var lblHash: UILabel!
    @IBOutlet weak var stackCopyShare: UIStackView!
    
    @IBOutlet weak var btnSignData: UIButton!
    @IBOutlet weak var lblSignature: UILabel!
    
    @IBOutlet weak var btnStoreData: UIButton!
    @IBOutlet weak var lblStoreData: UILabel!
    
    @IBOutlet weak var btnGetData: UIButton!
    @IBOutlet weak var lblGetData: UILabel!
    
    @IBOutlet weak var btnVerifyData: UIButton!
    @IBOutlet weak var lblVerifyData: UILabel!
    
    //MARK: - Properties
    let liveOrTest = false
    let peaq_url = "wss://wss.agung.peaq.network"
    let peaq_testnet_url = "wss://wsspc1-qa.agung.peaq.network"
    
    //MARK: - viewDidLoad
    override func viewDidLoad() {
        super.viewDidLoad()
        
        btnSignData.layer.cornerRadius = 10
        btnStoreData.layer.cornerRadius = 10
        btnGetData.layer.cornerRadius = 10
        btnVerifyData.layer.cornerRadius = 10
        btnCreateID.layer.cornerRadius = 10
        btnCopy.layer.cornerRadius = 10
        btnShare.layer.cornerRadius = 10
        
        hiddenShowViews(ishidden: true)
        
        lblSignature.isHidden = true
        lblStoreData.isHidden = true
        lblGetData.isHidden = true
        lblVerifyData.isHidden = true
    }
    
    //MARK: - Functions
    func hiddenShowViews(ishidden: Bool) {
        lblHash.isHidden = ishidden
        btnCopy.isHidden = ishidden
        btnShare.isHidden = ishidden
        stackCopyShare.isHidden = ishidden
    }
    
    //MARK: - Actions
    @IBAction func createMachineID(_ sender: UIButton) {
        createMachineID()
    }
    
    @IBAction func signData(_ sender: UIButton) {
        lblSignature.isHidden = true
        lblSignature.text = ""
        let machineSeed = "speed movie excess amateur tent envelope few raise egg large either antique"
        let signature = generateAndSignData(machineSeed: machineSeed, data: "Hello World")
        if signature != nil && !signature!.isEmpty {
            lblSignature.isHidden = false
            lblSignature.text = signature
        }
    }
    
    @IBAction func storeBtn(_ sender: UIButton) {
        lblStoreData.isHidden = true
        lblStoreData.text = ""
        store(data: "Hello World")
    }
    
    @IBAction func getDataBtn(_ sender: UIButton) {
        lblGetData.isHidden = true
        lblGetData.text = ""
        let itemType = "did:peaq:123"//"MPyBqjNlAY"
        getItem(itemType: itemType)
    }
    
    @IBAction func verifyData(_ sender: UIButton) {
        
        lblVerifyData.isHidden = true
        lblVerifyData.text = ""
        
        verifyData()
    }
    
    //MARK: - Functions
    func createMachineID() {
        self.hiddenShowViews(ishidden: true)
        IndicatorManager.showLoader()
        
        do {
            try peaq.shared.createInstance(baseUrl: liveOrTest ? peaq_url : peaq_testnet_url) { [self] isSuccess, err in
                if isSuccess {
                    
                    let (seed, error) = peaq.shared.generateMnemonicSeed()
                    let (seed2, error2) = peaq.shared.generateMnemonicSeed()
                    let mainSeed = "speed movie excess amateur tent envelope few raise egg large either antique"
                    if let seed = seed, let seed2 = seed2 {
                        print("SEED", seed)
                        
                        let (publicKey, _, address, addressGetError) = peaq.shared.getPublicPrivateKeyAddressFromMachineSeed(machineSeed: seed)
                        let (publicKey2, _, address2, _) = peaq.shared.getPublicPrivateKeyAddressFromMachineSeed(machineSeed: seed2)
                        if addressGetError != nil {
                            
                            IndicatorManager.hideLoader()
                            alert(addressGetError?.localizedDescription ?? "Something went wrong.")
                            
                        } else if let publicKey = publicKey, let address2 = address2, let address = address, let publicKey2 = publicKey2 {
                            
                            print("publicKey", publicKey)
                            print("address", address)
                            
                            if let dIdDoc = peaq.shared.createDidDocument(issuserSeed: mainSeed, ownerAddress: address, machineAddress: address2, machinePublicKey: publicKey2, customData: "{\"id\":1, \"name\":\"sensor 1\"}") {
                                do {
                                    try peaq.shared.create(seed: mainSeed, name: "did:peaq:\(address)", value: dIdDoc) { hashKey, err in
                                        
                                        IndicatorManager.hideLoader()
                                        guard err == nil else {
                                            self.alert(err!.localizedDescription)
                                            return
                                        }
                                        self.lblHash.text = hashKey
                                        self.hiddenShowViews(ishidden: false)
                                    }
                                } catch {
                                    IndicatorManager.hideLoader()
                                    alert(error.localizedDescription)
                                }
                            } else {
                                IndicatorManager.hideLoader()
                                alert("Something went wrong.")
                            }
                        } else {
                            IndicatorManager.hideLoader()
                            alert("Something went wrong.")
                        }
                    } else {
                        IndicatorManager.hideLoader()
                        alert((error?.localizedDescription ?? "Something went wrong.") + (error2?.localizedDescription ?? ""))
                    }
                } else {
                    IndicatorManager.hideLoader()
                    alert(err?.localizedDescription ?? "Something went wrong.")
                }
            }
        } catch {
            IndicatorManager.hideLoader()
            alert(error.localizedDescription)
        }
    }
    
    func register() {
        self.hiddenShowViews(ishidden: true)
        IndicatorManager.showLoader()
        
        do {
            try peaq.shared.createInstance(baseUrl: liveOrTest ? peaq_url : peaq_testnet_url) { [self] isSuccess, err in
                if isSuccess {
                    
                    let (seed, error) = peaq.shared.generateMnemonicSeed()
                    let (seed2, error2) = peaq.shared.generateMnemonicSeed()
                    let mainSeed = "speed movie excess amateur tent envelope few raise egg large either antique"
                    if let seed = seed, let seed2 = seed2 {
                        print("SEED", seed)
                        
                        let (publicKey, _, address, addressGetError) = peaq.shared.getPublicPrivateKeyAddressFromMachineSeed(machineSeed: seed)
                        let (publicKey2, _, address2, _) = peaq.shared.getPublicPrivateKeyAddressFromMachineSeed(machineSeed: seed2)
                        if addressGetError != nil {
                            
                            IndicatorManager.hideLoader()
                            alert(addressGetError?.localizedDescription ?? "Something went wrong.")
                            
                        } else if let publicKey = publicKey, let address2 = address2, let address = address, let publicKey2 = publicKey2 {
                            
                            print("publicKey", publicKey)
                            print("address", address)
                            
                            if let dIdDoc = peaq.shared.createDidDocument(issuserSeed: mainSeed, ownerAddress: address, machineAddress: address2, machinePublicKey: publicKey2, customData: "{\"id\":1, \"name\":\"sensor 1\"}") {
                                do {
                                    try peaq.shared.create(seed: mainSeed, name: "did:peaq:\(address)", value: dIdDoc) { hashKey, err in
                                        
                                        IndicatorManager.hideLoader()
                                        guard err == nil else {
                                            self.alert(err!.localizedDescription)
                                            return
                                        }
                                        self.lblHash.text = hashKey
                                        self.hiddenShowViews(ishidden: false)
                                    }
                                } catch {
                                    IndicatorManager.hideLoader()
                                    alert(error.localizedDescription)
                                }
                            } else {
                                IndicatorManager.hideLoader()
                                alert("Something went wrong.")
                            }
                        } else {
                            IndicatorManager.hideLoader()
                            alert("Something went wrong.")
                        }
                    } else {
                        IndicatorManager.hideLoader()
                        alert((error?.localizedDescription ?? "Something went wrong.") + (error2?.localizedDescription ?? ""))
                    }
                } else {
                    IndicatorManager.hideLoader()
                    alert(err?.localizedDescription ?? "Something went wrong.")
                }
            }
        } catch {
            IndicatorManager.hideLoader()
            alert(error.localizedDescription)
        }
    }
    
    func generateAndSignData(machineSeed: String, data: String) -> String? {
        let signature = peaq.shared.signData(painData: data, machineSeed: machineSeed, format: .sr25519)
        print("signature", signature ?? "")
        return signature
    }
    
    func store(data: String) {
        IndicatorManager.showLoader()
        do {
            try peaq.shared.createInstance(baseUrl: liveOrTest ? peaq_url : peaq_testnet_url) { [self] isSuccess, err in
                if isSuccess {
                    let machineSeed = "speed movie excess amateur tent envelope few raise egg large either antique"
                    if let signature = generateAndSignData(machineSeed: machineSeed, data: data) {
                        let itemType = randomString(length: 10)
                        
                        do {
                            try peaq.shared.addItems(seed: machineSeed, payloadHex: signature, itemType: itemType) { [self] str, err in
                                IndicatorManager.hideLoader()
                                guard err == nil else {
                                    self.alert(err!.localizedDescription)
                                    return
                                }
                                lblStoreData.isHidden = false
                                lblStoreData.text = str
                            }
                        } catch {
                            IndicatorManager.hideLoader()
                            alert(error.localizedDescription)
                        }
                    }
                    
                } else {
                    IndicatorManager.hideLoader()
                    alert(err?.localizedDescription ?? "Something went wrong.")
                }
            }
        } catch {
            IndicatorManager.hideLoader()
            alert(error.localizedDescription)
        }
    }
    
    func getItem(itemType: String) {
        IndicatorManager.showLoader()
        do {
            try peaq.shared.createInstance(baseUrl: liveOrTest ? peaq_url : peaq_testnet_url) { [self] isSuccess, err in
                if isSuccess {
                    let machineSeed = "speed movie excess amateur tent envelope few raise egg large either antique"
                    if let address = peaq.shared.getAddressFromMachineSeed(machineSeed: machineSeed) {
                        do {
                            let data = try peaq.shared.getItem(address: address, itemType: itemType)
                            IndicatorManager.hideLoader()
                            lblGetData.isHidden = false
                            lblGetData.text = data?.stringValue
                        } catch {
                            IndicatorManager.hideLoader()
                            alert(error.localizedDescription)
                        }
                    } else {
                        IndicatorManager.hideLoader()
                        alert("Getting error in address")
                    }
                } else {
                    IndicatorManager.hideLoader()
                    alert(err?.localizedDescription ?? "Something went wrong.")
                }
            }
        } catch {
            IndicatorManager.hideLoader()
            alert(error.localizedDescription)
        }
    }
    
    func verifyData() {
        let machineSeed = "speed movie excess amateur tent envelope few raise egg large either antique"
        let data = "Hello World"
        let publicKey = peaq.shared.getPublicKey(machineSeed: machineSeed, format: .sr25519)
        if let signature = generateAndSignData(machineSeed: machineSeed, data: data) {
            let isVerify = peaq.shared.verifySignatureData(publicKey: publicKey ?? "", plainData: data, signature: signature)
            print("isVerify", isVerify)
            
            lblVerifyData.isHidden = false
            lblVerifyData.text = isVerify ? "Verified successfully!!" : "Verification failed!!"
        }
    }
    
    @IBAction func btnCopy(_ sender: UIButton) {
        UIPasteboard.general.string = self.lblHash.text
        alert("Copied")
    }
    
    @IBAction func shareBtn(_ sender: UIButton) {
        let textToShare = [ self.lblHash.text ]
        let activityViewController = UIActivityViewController(activityItems: textToShare as [Any], applicationActivities: nil)
        activityViewController.popoverPresentationController?.sourceView = self.view
        activityViewController.excludedActivityTypes = [ UIActivity.ActivityType.airDrop, UIActivity.ActivityType.postToFacebook ]
        self.present(activityViewController, animated: true, completion: nil)
    }
    
    func alert(_ message: String) {
        let alert = UIAlertController(title: message, message: nil, preferredStyle: UIAlertController.Style.alert)
        alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }
}


func randomString(length: Int) -> String {
    let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return String((0..<length).map{ _ in letters.randomElement()! })
}
