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

import 'utils.dart';
import 'constants.dart';

class Blowfish {
  final int blocksize = BlowfishConstants.blockSize;
  final List<int> p = BlowfishConstants.p;
  final List<int> s0 = BlowfishConstants.s0;
  final List<int> s1 = BlowfishConstants.s1;
  final List<int> s2 = BlowfishConstants.s2;
  final List<int> s3 = BlowfishConstants.s3;

  List<int> encryptCBC(List<int> src, List<int> iv) {
    // Check if the IV length is valid
    if (iv.length != blocksize) {
      throw ArgumentError('IV length must match block size');
    }
    List<int> dst = [];
    int numBlocks = src.length ~/ blocksize;
    List<int> previousBlock = List<int>.from(iv);

    for (int i = 0; i < numBlocks; i++) {
      List<int> block = src.sublist(i * blocksize, (i + 1) * blocksize);

      for (int j = 0; j < blocksize; j++) {
        block[j] ^= previousBlock[j];
      }

      List<int> encryptedBlock = encryptECB(block);

      previousBlock = List<int>.from(encryptedBlock);

      dst.addAll(encryptedBlock);
    }
    return dst;
  }

  List<int> decryptCBC(List<int> src, List<int> iv) {
    // Check if the IV length is valid
    if (iv.length != blocksize) {
      throw ArgumentError('IV length must match block size');
    }
    List<int> dst = [];
    int numBlocks = src.length ~/ blocksize;
    List<int> previousBlock = List<int>.from(iv);

    for (int i = 0; i < numBlocks; i++) {
      List<int> block = src.sublist(i * blocksize, (i + 1) * blocksize);
      List<int> decryptedBlock = decryptECB(block);

      for (int j = 0; j < blocksize; j++) {
        decryptedBlock[j] ^= previousBlock[j];
      }

      previousBlock = List<int>.from(block);

      dst.addAll(decryptedBlock);
    }
    return dst;
  }

  List<int> encryptECB(List<int> src) {
    if (src.length != blocksize) {
      throw ArgumentError('Invalid block size ${src.length}');
    }
    int l = (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];
    int r = (src[4] << 24) | (src[5] << 16) | (src[6] << 8) | src[7];
    List<int> encrypted = encryptBlock(l, r, this);
    return [
      (encrypted[0] >> 24) & 0xFF,
      (encrypted[0] >> 16) & 0xFF,
      (encrypted[0] >> 8) & 0xFF,
      encrypted[0] & 0xFF,
      (encrypted[1] >> 24) & 0xFF,
      (encrypted[1] >> 16) & 0xFF,
      (encrypted[1] >> 8) & 0xFF,
      encrypted[1] & 0xFF
    ];
  }

  List<int> decryptECB(List<int> src) {
    if (src.length != blocksize) {
      throw ArgumentError('Invalid block size ${src.length}');
    }
    int l = (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];
    int r = (src[4] << 24) | (src[5] << 16) | (src[6] << 8) | src[7];
    List<int> decrypted = decryptBlock(l, r, this);
    return [
      (decrypted[0] >> 24) & 0xFF,
      (decrypted[0] >> 16) & 0xFF,
      (decrypted[0] >> 8) & 0xFF,
      decrypted[0] & 0xFF,
      (decrypted[1] >> 24) & 0xFF,
      (decrypted[1] >> 16) & 0xFF,
      (decrypted[1] >> 8) & 0xFF,
      decrypted[1] & 0xFF
    ];
  }

  //just add dunno if it usefull or not :\
  List<int> encryptECBL(List<int> src) {
    if (src.length % blocksize != 0) {
      // just add loop so u can enc more than 8 block :/
      throw ArgumentError('Invalid block size');
    }
    int blockCount = src.length ~/ blocksize;
    List<int> dst = [];
    for (int i = 0; i < blockCount; i++) {
      int l = (src[i * blocksize] << 24) |
          (src[i * blocksize + 1] << 16) |
          (src[i * blocksize + 2] << 8) |
          src[i * blocksize + 3];
      int r = (src[i * blocksize + 4] << 24) |
          (src[i * blocksize + 5] << 16) |
          (src[i * blocksize + 6] << 8) |
          src[i * blocksize + 7];
      List<int> encrypted = encryptBlock(l, r, this);
      dst.addAll([
        (encrypted[0] >> 24) & 0xFF,
        (encrypted[0] >> 16) & 0xFF,
        (encrypted[0] >> 8) & 0xFF,
        encrypted[0] & 0xFF,
        (encrypted[1] >> 24) & 0xFF,
        (encrypted[1] >> 16) & 0xFF,
        (encrypted[1] >> 8) & 0xFF,
        encrypted[1] & 0xFF
      ]);
    }
    return dst;
  }

  List<int> decryptECBL(List<int> src) {
    if (src.length % blocksize != 0) {
      throw ArgumentError('Invalid block size');
    }
    int blockCount = src.length ~/ blocksize;
    List<int> dst = [];
    for (int i = 0; i < blockCount; i++) {
      int l = (src[i * blocksize] << 24) |
          (src[i * blocksize + 1] << 16) |
          (src[i * blocksize + 2] << 8) |
          src[i * blocksize + 3];
      int r = (src[i * blocksize + 4] << 24) |
          (src[i * blocksize + 5] << 16) |
          (src[i * blocksize + 6] << 8) |
          src[i * blocksize + 7];
      List<int> decrypted = decryptBlock(l, r, this);
      dst.addAll([
        (decrypted[0] >> 24) & 0xFF,
        (decrypted[0] >> 16) & 0xFF,
        (decrypted[0] >> 8) & 0xFF,
        decrypted[0] & 0xFF,
        (decrypted[1] >> 24) & 0xFF,
        (decrypted[1] >> 16) & 0xFF,
        (decrypted[1] >> 8) & 0xFF,
        decrypted[1] & 0xFF
      ]);
    }
    return dst;
  }
}

class KeySizeError implements Exception {
  final int size;

  KeySizeError(this.size);

  @override
  String toString() {
    return 'Invalid key size: $size';
  }
}

Blowfish newBlowfish(List<int> key) {
  if (key.isEmpty || key.length > 56) {
    throw KeySizeError(key.length);
  }
  Blowfish result = Blowfish();
  expandKey(key, result);
  return result;
}

Blowfish newSaltedBlowfish(List<int> key, List<int> salt) {
  if (salt.isEmpty) {
    return newBlowfish(key);
  }
  if (key.isEmpty) {
    throw KeySizeError(key.length);
  }
  Blowfish result = Blowfish();
  expandKeyWithSalt(key, salt, result);
  return result;
}
