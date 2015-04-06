# KeychainItemWrapper.swift
A Swift implementation of the KeychainItemWrapper from the [Apple example](https://developer.apple.com/library/ios/samplecode/GenericKeychain/Introduction/Intro.html).

# Installation

1. Drag and drop KeychainItemWrapper.swift into your Xcode project.
2. All done

# Usage

## Setting a Keychain item value
```swift
let keychainItemWrapper = KeychainItemWrapper(identifier: "identifier for this item", accessGroup: "access group if shared")
keychainItemWrapper["superSecretKey"] = "aSuperSecretValue"
```

## Getting a Keychain item value
```swift
let keychainItemWrapper = KeychainItemWrapper(identifier: "identifier for this item", accessGroup: "access group if shared")
let superSecretValue = keychainItemWrapper["superSecretKey"] as String?
println("The super secret value is: \(sharedPassword)")
```

# Contact
Follow me on twitter [@mcostea](https://twitter.com/mcostea)

# License

KeychainItemWrapper.swift is released under the MIT license. See LICENSE for details.
