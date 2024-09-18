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

  /// Adds PKCS#7 padding to the input data.
  List<int> _addPadding(List<int> src) {
    int paddingLength = blocksize - (src.length % blocksize);
    return src + List<int>.filled(paddingLength, paddingLength);
  }

  /// Removes PKCS#7 padding from the input data.
  List<int> _removePadding(List<int> src) {
    if (src.isEmpty) return src;

    int paddingLength = src.last;
    if (paddingLength < 1 || paddingLength > blocksize) {
      throw ArgumentError('Invalid padding length');
    }
    return src.sublist(0, src.length - paddingLength);
  }

  /// Encrypts data using CBC mode.
  List<int> encryptCBC(List<int> src, List<int> iv, {bool applyPadding = false}) {
    _validateIV(iv);

    if (applyPadding) {
      src = _addPadding(src);
    } else {
      _validateBlockSize(src);
    }

    List<int> dst = [];
    int numBlocks = src.length ~/ blocksize;
    List<int> previousBlock = List<int>.from(iv);

    for (int i = 0; i < numBlocks; i++) {
      List<int> block = src.sublist(i * blocksize, (i + 1) * blocksize);
      _xorBlocks(block, previousBlock);
      List<int> encryptedBlock = encryptECB(block, applyPadding: false);
      previousBlock = List<int>.from(encryptedBlock);
      dst.addAll(encryptedBlock);
    }
    return dst;
  }

  /// Decrypts data using CBC mode.
  List<int> decryptCBC(List<int> src, List<int> iv, {bool applyPadding = false}) {
    _validateIV(iv);

    _validateBlockSize(src);

    List<int> dst = [];
    int numBlocks = src.length ~/ blocksize;
    List<int> previousBlock = List<int>.from(iv);

    for (int i = 0; i < numBlocks; i++) {
      List<int> block = src.sublist(i * blocksize, (i + 1) * blocksize);
      List<int> decryptedBlock = decryptECB(block, applyPadding: false);
      _xorBlocks(decryptedBlock, previousBlock);
      previousBlock = List<int>.from(block);
      dst.addAll(decryptedBlock);
    }

    return applyPadding ? _removePadding(dst) : dst;
  }

  /// Encrypts data using ECB mode.
  List<int> encryptECB(List<int> src, {bool applyPadding = true}) {

    if (applyPadding) {
      src = _addPadding(src);
    } else {
      _validateBlockSize(src);
    }

    int blockCount = src.length ~/ blocksize;
    List<int> dst = [];

    for (int i = 0; i < blockCount; i++) {
      int l = _bytesToInt(src, i * blocksize);
      int r = _bytesToInt(src, i * blocksize + 4);
      List<int> encrypted = encryptBlock(l, r, this);

      dst.addAll(_intToBytes(encrypted[0]));
      dst.addAll(_intToBytes(encrypted[1]));
    }

    return dst;
  }

  /// Decrypts data using ECB mode.
  List<int> decryptECB(List<int> src, {bool applyPadding = true}) {
    _validateBlockSize(src);

    int blockCount = src.length ~/ blocksize;
    List<int> dst = [];

    for (int i = 0; i < blockCount; i++) {
      int l = _bytesToInt(src, i * blocksize);
      int r = _bytesToInt(src, i * blocksize + 4);
      List<int> decrypted = decryptBlock(l, r, this);

      dst.addAll(_intToBytes(decrypted[0]));
      dst.addAll(_intToBytes(decrypted[1]));
    }

    return applyPadding ? _removePadding(dst) : dst;
  }

  /// Validates the IV length.
  void _validateIV(List<int> iv) {
    if (iv.length != blocksize) {
      throw ArgumentError('IV length must match block size ($blocksize bytes)');
    }
  }

  /// Validates the block size.
  void _validateBlockSize(List<int> src) {
    if (src.length % blocksize != 0) {
      throw ArgumentError('Invalid block size: Block size must be a multiple of 8 bytes when padding is disabled');
    }
  }

  /// XORs two blocks.
  void _xorBlocks(List<int> block, List<int> previousBlock) {
    for (int j = 0; j < blocksize; j++) {
      block[j] ^= previousBlock[j];
    }
  }

  /// Converts a list of bytes to an integer.
  int _bytesToInt(List<int> src, int offset) {
    return (src[offset] << 24) |
           (src[offset + 1] << 16) |
           (src[offset + 2] << 8) |
           src[offset + 3];
  }

  /// Converts an integer to a list of bytes.
  List<int> _intToBytes(int value) {
    return [
      (value >> 24) & 0xFF,
      (value >> 16) & 0xFF,
      (value >> 8) & 0xFF,
      value & 0xFF
    ];
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

Blowfish newSaltedBlowfish(List<int> key, List<int> salt, {bool usePadding = true}) {
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