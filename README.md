# Blowfish

<p align="center">
<a href="https://pub.dev/packages/blowfish"><img src="https://img.shields.io/pub/v/blowfish" alt="pub: blowfish"></a>
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-AGPL v3.0-green.svg" alt="License: AGPL"></a>
<a href="https://pub.dev/packages/lint"><img src="https://img.shields.io/badge/style-lint-4BC0F5.svg" alt="style: lint"></a>
</p>

Blowfish encryption algorithm implementation in Dart with both ECB and CBC modes.


## Usage

The following simple usage is adapted from the included example project:
```
import 'dart:convert';
import 'package:blowfish/blowfish.dart';

void main() {
  // Example key 
  List<int> key = utf8.encode("mysecretpassword");

  // Plaintext
  String plaintext = "testtext";
  List<int> plaintextBytes = utf8.encode(plaintext);

  print("Plaintext: $plaintextBytes");

  // Create a Blowfish instance
  Blowfish blowfish = newBlowfish(key);

  // Encrypt
  List<int> encrypted = blowfish.encryptECB(plaintextBytes);
  print("Encrypted ECB: $encrypted");

  // Decrypt
  List<int> decrypted = blowfish.decryptECB(encrypted);

  print("Decrypted ECB: $decrypted");

  // Encrypt with CBC
  encrypted = blowfish.encryptCBC(plaintextBytes, utf8.encode("12345678"));
  print("Encrypted CBC: $encrypted");

  // Decrypt with CBC
  decrypted = blowfish.decryptCBC(encrypted, utf8.encode("12345678"));
  print("Decrypted CBC: $decrypted");

  // newSaltedBlowfish
  Blowfish saltedBlowfish = newSaltedBlowfish(key, utf8.encode("12345678"));
  encrypted = saltedBlowfish.encryptECB(plaintextBytes);
  print("Encrypted Salted: $encrypted");

  decrypted = saltedBlowfish.decryptECB(encrypted);
  print("Decrypted Salted: $decrypted");
}

```

## License
Everything is licenced under the GNU Lesser General Public License v3 or above.  
See [`LICENCE`](LICENSE) for more
information.

## Features
- Blowfish Encryption: Encrypt plaintext using Blowfish algorithm.
- Blowfish Decryption: Decrypt ciphertext encrypted with Blowfish.
- ECB Mode: Support for Electronic Codebook (ECB) mode encryption and decryption.
- CBC Mode: Support for Cipher Block Chaining (CBC) mode encryption and decryption.
- Salting: Ability to create salted Blowfish instances for added security.

## Contributing
Contributions are welcome! If you'd like to contribute to this package, please follow these steps:

- Fork the repository
- Create your feature branch (git checkout -b feature)
- Commit your changes (git commit -am 'Add new feature')
- Push to the branch (git push origin feature)
- Create a new Pull Request
