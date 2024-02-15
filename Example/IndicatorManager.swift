//
//  IndicatorManager.swift
//  Silencio
//
//  Created by Vishal Dobariya on 05/10/22.
//

import Foundation
import UIKit

let appDelegate = UIApplication.shared.connectedScenes.first?.delegate as? SceneDelegate

class IndicatorManager: NSObject {

    private static var loadingCount = 0

    private static var isLoaderShow = true
    

    class func showLoader() {
        guard isLoaderShow else {
            return
        }

        if loadingCount == 0 {
            DispatchQueue.main.async {
                if let vi = appDelegate?.window {
                    ActivityIndicatorWithLabel.shared.showProgressView(uiView: vi)
                }
            }
        }
        loadingCount += 1

    }

    class func hideLoader() {
        guard isLoaderShow else {
            return
        }

        if loadingCount > 0 {
            loadingCount -= 1
        }
        if loadingCount == 0 {
            // Hide loader
            DispatchQueue.main.async {
                if let vi = appDelegate?.window?.rootViewController?.view {
                    ActivityIndicatorWithLabel.shared.hideProgressView()
                }
            }
        }

    }
}

public class ActivityIndicatorWithLabel {
    
    var containerView = UIView()
    var progressView = UIView()
    var activityIndicator = UIActivityIndicatorView()
    
    public class var shared: ActivityIndicatorWithLabel {
        struct Static {
            static let instance: ActivityIndicatorWithLabel = ActivityIndicatorWithLabel()
        }
        return Static.instance
    }
    
    var pinchImageView = UIImageView()
    
    public func showProgressView(uiView: UIView) {
        containerView.frame = CGRect(x: 0, y: 0, width: uiView.frame.width, height: uiView.frame.height)
        containerView.backgroundColor = UIColorFromHex(rgbValue: 0x000000, alpha: 0.20)
        
        let url = Bundle.main.url(forResource: "loadingSpinner", withExtension: "gif")!
        let data = try! Data(contentsOf: url)
        let imageDecoder = DBImageDecoder()
        imageDecoder.setData(data, allDataReceived: true)
        DispatchQueue.main.async {
            self.pinchImageView.image = imageDecoder.uiImage
        }
        pinchImageView.frame = CGRect(x: 0.0, y: 0.0, width: 100 * 3.58, height: 100)
        progressView.frame = CGRectMake(0, 0, (pinchImageView.frame.size.width), 60)
        progressView.center = uiView.center
        progressView.addSubview(pinchImageView)
        containerView.addSubview(progressView)
        uiView.addSubview(containerView)
    }
    
    public func hideProgressView() {
        activityIndicator.stopAnimating()
        pinchImageView.removeFromSuperview()
        activityIndicator.removeFromSuperview()
        progressView.removeFromSuperview()
        containerView.removeFromSuperview()
       
    }
    
    public func UIColorFromHex(rgbValue:UInt32, alpha:Double=1.0)->UIColor {
        let red = CGFloat((rgbValue & 0xFF0000) >> 16)/256.0
        let green = CGFloat((rgbValue & 0xFF00) >> 8)/256.0
        let blue = CGFloat(rgbValue & 0xFF)/256.0
        return UIColor(red:red, green:green, blue:blue, alpha:CGFloat(alpha))
    }
}
