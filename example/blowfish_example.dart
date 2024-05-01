/*
Blowfish: A Dart implementation of the Blowfish encryption algorithm.
Copyright (C) 2024 sirimath.net

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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
