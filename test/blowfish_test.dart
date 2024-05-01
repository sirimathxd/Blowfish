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
import 'package:test/test.dart';

void main() {
  group('Blowfish Tests', () {
    // Example key
    List<int> key = utf8.encode("mysecretpassword");

    // Example plaintext
    List<int> plaintextBytes = [104, 101, 108, 108, 111, 119, 97, 114];

    // Example initialization vector (IV)
    List<int> iv = utf8.encode("12345678");

    // Create a Blowfish instance
    Blowfish blowfish = newBlowfish(key);

    test('Encrypt and Decrypt ECB', () {
      // Encrypt with ECB
      List<int> encryptedECB = blowfish.encryptECB(plaintextBytes);

      // Decrypt with ECB
      List<int> decryptedECB = blowfish.decryptECB(encryptedECB);

      expect(decryptedECB, plaintextBytes);
    });

    test('Encrypt and Decrypt CBC', () {
      // Encrypt with CBC
      List<int> encryptedCBC = blowfish.encryptCBC(plaintextBytes, iv);

      // Decrypt with CBC
      List<int> decryptedCBC = blowfish.decryptCBC(encryptedCBC, iv);

      expect(decryptedCBC, plaintextBytes);
    });

    test('New Salted Blowfish ECB', () {
      // Create a Salted Blowfish instance
      Blowfish saltedBlowfish = newSaltedBlowfish(key, iv);

      // Encrypt with Salted ECB
      List<int> encryptedSaltedECB = saltedBlowfish.encryptECB(plaintextBytes);

      // Decrypt with Salted ECB
      List<int> decryptedSaltedECB =
          saltedBlowfish.decryptECB(encryptedSaltedECB);

      expect(decryptedSaltedECB, plaintextBytes);
    });

    test('New Salted Blowfish CBC', () {
      // Create a Salted Blowfish instance
      Blowfish saltedBlowfish = newSaltedBlowfish(key, iv);

      // Encrypt with Salted CBC
      List<int> encryptedSaltedCBC =
          saltedBlowfish.encryptCBC(plaintextBytes, iv);

      // Decrypt with Salted CBC
      List<int> decryptedSaltedCBC =
          saltedBlowfish.decryptCBC(encryptedSaltedCBC, iv);

      expect(decryptedSaltedCBC, plaintextBytes);
    });
  });
}
