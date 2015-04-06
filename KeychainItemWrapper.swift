// KeychainItemWrapper.swift
//
// Copyright (c) 2015 Mihai Costea (http://mcostea.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import Foundation
import Security

class KeychainItemWrapper {
    
    var genericPasswordQuery = [String: AnyObject]()
    var keychainItemData = [String: AnyObject]()
    
    var values = [String: AnyObject]()
    
    init(identifier: String, accessGroup: String?) {
        self.genericPasswordQuery[kSecClass] = kSecClassGenericPassword
        self.genericPasswordQuery[kSecAttrGeneric] = identifier
        
        if (accessGroup != nil) {
            if TARGET_IPHONE_SIMULATOR != 1 {
                self.genericPasswordQuery[kSecAttrAccessGroup] = accessGroup
            }
        }
        
        self.genericPasswordQuery[kSecMatchLimit] = kSecMatchLimitOne
        self.genericPasswordQuery[kSecReturnAttributes] = kCFBooleanTrue
        
        let tempQuery = self.genericPasswordQuery as NSDictionary
        var outDict: Unmanaged<AnyObject>?
        
        let copyMatchingResult = SecItemCopyMatching(tempQuery as CFDictionary, &outDict)
        
        if copyMatchingResult != noErr {
            self.resetKeychain()
            
            self.keychainItemData[kSecAttrGeneric] = identifier
            if (accessGroup != nil) {
                if TARGET_IPHONE_SIMULATOR != 1 {
                    self.keychainItemData[kSecAttrAccessGroup] = accessGroup
                }
            }
        } else {
            self.keychainItemData = self.secItemDataToDict(outDict!.takeRetainedValue() as [String: AnyObject])
        }
    }
    
    subscript(key: String) -> AnyObject? {
        get {
            return self.values[key]
        }
        
        set(newValue) {
            self.values[key] = newValue
            self.writeKeychainData()
        }
    }
    
    func resetKeychain() {
        
        if !self.keychainItemData.isEmpty {
            let tempDict = self.dictToSecItemData(self.keychainItemData)
            var junk = noErr
            junk = SecItemDelete(tempDict as CFDictionary)
        
            assert(junk == noErr || junk == errSecItemNotFound, "Failed to delete current dict")
        }
        
        self.keychainItemData[kSecAttrAccount] = ""
        self.keychainItemData[kSecAttrLabel] = ""
        self.keychainItemData[kSecAttrDescription] = ""
        
        self.keychainItemData[kSecValueData] = ""
    }
    
    private func secItemDataToDict(data: [String: AnyObject]) -> [String: AnyObject] {
        var returnDict = [String: AnyObject]()
        for (key, value) in data {
            returnDict[key] = value
        }
        
        returnDict[kSecReturnData] = kCFBooleanTrue
        returnDict[kSecClass] = kSecClassGenericPassword
        
        var passwordData: Unmanaged<AnyObject>?
        
        // We could use returnDict like the Apple example but this crashes the app with swift_unknownRelease
        // when we try to access returnDict again
        var queryDict = returnDict
        
        let copyMatchingResult = SecItemCopyMatching(queryDict as CFDictionary, &passwordData)
        
        if copyMatchingResult != noErr {
            assert(false, "No matching item found in keychain")
        } else {
            let retainedValuesData = passwordData!.takeRetainedValue() as NSData
            var val = NSJSONSerialization.JSONObjectWithData(retainedValuesData, options: .allZeros, error: nil) as [String: AnyObject]
            
            returnDict.removeValueForKey(kSecReturnData)
            returnDict[kSecValueData] = val
            
            self.values = val
        }
        
        return returnDict
    }
    
    private func dictToSecItemData(dict: [String: AnyObject]) -> [String: AnyObject] {
        var returnDict = [String: AnyObject]()
        for (key, value) in self.keychainItemData {
            returnDict[key] = value
        }
        
        returnDict[kSecClass] = kSecClassGenericPassword
        
        returnDict[kSecValueData] = NSJSONSerialization.dataWithJSONObject(self.values, options: .allZeros, error: nil)
        
        return returnDict
    }
    
    private func writeKeychainData() {
        var attributes: Unmanaged<AnyObject>?
        var updateItem: [String: AnyObject]?
        
        var result: OSStatus?
        
        let copyMatchingResult = SecItemCopyMatching(self.genericPasswordQuery as CFDictionary, &attributes)
        
        if copyMatchingResult != noErr {
            result = SecItemAdd(self.dictToSecItemData(self.keychainItemData), nil)
            assert(result == noErr, "Failed to add keychain item")
        } else {
            updateItem = [String: AnyObject]()
            for (key, value) in attributes!.takeRetainedValue() as [String: AnyObject] {
                updateItem![key] = value
            }
            updateItem![kSecClass] = self.genericPasswordQuery[kSecClass]
            
            var tempCheck = self.dictToSecItemData(self.keychainItemData)
            tempCheck.removeValueForKey(kSecClass)
            
            if TARGET_IPHONE_SIMULATOR == 1 {
                tempCheck.removeValueForKey(kSecAttrAccessGroup)
            }
            
            result = SecItemUpdate(updateItem! as CFDictionary, tempCheck as CFDictionary)
            assert(result == noErr, "Failed to update keychain item")
        }
    }
}