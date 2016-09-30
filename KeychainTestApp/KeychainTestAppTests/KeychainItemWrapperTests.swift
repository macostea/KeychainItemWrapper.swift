//
//  KeychainItemWrapperTests.swift
//  KeychainTestApp
//
//  Created by MihaiC on 30/09/2016.
//  Copyright © 2016 Mihai Costea. All rights reserved.
//

import XCTest
@testable import KeychainTestApp


class KeychainItemWrapperTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testSetItem() {
        let keychainItemWrapper = KeychainItemWrapper(identifier: "identifier", accessGroup: nil)
        keychainItemWrapper["superSecretKey"] = "aSuperSecretValue" as AnyObject?
        
        XCTAssertEqual(keychainItemWrapper["superSecretKey"] as! String!, "aSuperSecretValue")
    }
    
    func testGetItem() {
        let keychainItemWrapper = KeychainItemWrapper(identifier: "identifier", accessGroup: nil)
        keychainItemWrapper["superSecretKey"] = "testvalue" as AnyObject?
        
        let otherKeychainItemWrapper = KeychainItemWrapper(identifier: "identifier", accessGroup: nil)
        XCTAssertEqual(otherKeychainItemWrapper["superSecretKey"] as! String!, "testvalue")
    }
    
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }
}
