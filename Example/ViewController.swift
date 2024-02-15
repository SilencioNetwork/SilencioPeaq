//
//  ViewController.swift
//  Example
//
//  Created by mac on 12/01/24.
//

import UIKit
import peaq_iOS

class ViewController: UIViewController {

    //MARK: - Outlets
    @IBOutlet weak var btnCreateID: UIButton!
    @IBOutlet weak var btnCopy: UIButton!
    @IBOutlet weak var btnShare: UIButton!
    @IBOutlet weak var lblHash: UILabel!
    
    //MARK: - Properties
    let liveOrTest = false
    let peaq_url = "wss://wss.agung.peaq.network"
    let peaq_testnet_url = "wss://wsspc1-qa.agung.peaq.network"
    
    //MARK: - viewDidLoad
    override func viewDidLoad() {
        super.viewDidLoad()
        btnCreateID.layer.cornerRadius = 10
        btnCopy.layer.cornerRadius = 10
        btnShare.layer.cornerRadius = 10
        
        hiddenShowViews(ishidden: true)
    }
    
    //MARK: - Functions
    func hiddenShowViews(ishidden: Bool) {
        lblHash.isHidden = ishidden
        btnCopy.isHidden = ishidden
        btnShare.isHidden = ishidden
    }
    
    //MARK: - Actions
    @IBAction func createMachineID(_ sender: UIButton) {
        
        self.hiddenShowViews(ishidden: true)
        IndicatorManager.showLoader()
        
        do {
            try peaq.shared.createInstance(baseUrl: liveOrTest ? peaq_url : peaq_testnet_url) { [self] isSuccess, err in
                if isSuccess {
                    do {
                        try peaq.shared.create(seed: "speed movie excess amateur tent envelope few raise egg large either antique", name: randomString(length: 2), address: randomString(length: 2)) { hashKey, err in
                            
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
                    alert(err?.localizedDescription ?? "Something went wrong.")
                }
            }
        } catch {
            IndicatorManager.hideLoader()
            alert(error.localizedDescription)
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
