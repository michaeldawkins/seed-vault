// seed-enclave: keeps a Seed Vault agent key inside the Mac's Secure Enclave.
//
// The private key is made inside the chip and never leaves it. The key file
// holds only an encrypted handle that THIS Mac's Secure Enclave can use; it is
// useless on any other machine and cannot be turned back into the key.
//
//   seed-enclave create KEY_FILE   make a key in the chip, print its public key
//   seed-enclave public KEY_FILE   print the public key
//   seed-enclave sign KEY_FILE     sign stdin, print the signature
//
// Public key: base64url of the 65-byte uncompressed P-256 point (x9.63).
// Signature: base64url of the raw 64-byte ES256 signature (r || s).
// The same protocol is spoken by seed-soft-enclave, which tests use.
//
// Build: swiftc -O seed-enclave.swift -o seed-enclave   (see build.sh)

import CryptoKit
import Foundation
import Security

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(("seed-enclave: " + message + "\n").data(using: .utf8)!)
    exit(1)
}

func base64url(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func load(_ path: String) -> SecureEnclave.P256.Signing.PrivateKey {
    guard let blob = FileManager.default.contents(atPath: path) else {
        fail("cannot read \(path)")
    }
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
    } catch {
        fail("this key file does not belong to this Mac's Secure Enclave (\(error))")
    }
}

let args = CommandLine.arguments
guard args.count == 3 else { fail("usage: seed-enclave create|public|sign KEY_FILE") }
let command = args[1]
let path = args[2]

guard SecureEnclave.isAvailable else { fail("this Mac has no Secure Enclave") }

switch command {
case "create":
    if FileManager.default.fileExists(atPath: path) {
        fail("\(path) already exists; not overwriting a key")
    }
    // Usable after the Mac has been unlocked once since start-up, so an agent
    // can run unattended. Never synced, never exported, this device only.
    var cfError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        .privateKeyUsage,
        &cfError
    ) else {
        fail("cannot set key access rules")
    }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let ok = FileManager.default.createFile(
            atPath: path,
            contents: key.dataRepresentation,
            attributes: [.posixPermissions: 0o600]
        )
        if !ok { fail("cannot write \(path)") }
        print(base64url(key.publicKey.x963Representation))
    } catch {
        fail("the Secure Enclave refused to make a key (\(error))")
    }
case "public":
    print(base64url(load(path).publicKey.x963Representation))
case "sign":
    let key = load(path)
    let message = FileHandle.standardInput.readDataToEndOfFile()
    do {
        // CryptoKit hashes with SHA-256 first, which is exactly ES256.
        let signature = try key.signature(for: message)
        print(base64url(signature.rawRepresentation))
    } catch {
        fail("the Secure Enclave refused to sign (\(error))")
    }
default:
    fail("unknown command '\(command)'")
}
