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

import 'blowfish.dart';

int getNextWord(List<int> b, int pos) {
  int w = 0;
  int j = pos;
  for (int i = 0; i < 4; i++) {
    w = (w << 8) | b[j];
    j++;
    if (j >= b.length) {
      j = 0;
    }
  }
  return w;
}

void expandKey(List<int> key, Blowfish c) {
  int j = 0;
  for (int i = 0; i < 18; i++) {
    // Using inlined getNextWord for performance.
    int d = 0;
    for (int k = 0; k < 4; k++) {
      d = (d << 8) | key[j];
      j++;
      if (j >= key.length) {
        j = 0;
      }
    }
    c.p[i] ^= d;
  }

  int l = 0, r = 0;
  for (int i = 0; i < 18; i += 2) {
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.p[i] = l;
    c.p[i + 1] = r;
  }

  for (int i = 0; i < 256; i += 2) {
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.s0[i] = l;
    c.s0[i + 1] = r;
  }
  for (int i = 0; i < 256; i += 2) {
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.s1[i] = l;
    c.s1[i + 1] = r;
  }
  for (int i = 0; i < 256; i += 2) {
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.s2[i] = l;
    c.s2[i + 1] = r;
  }
  for (int i = 0; i < 256; i += 2) {
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.s3[i] = l;
    c.s3[i + 1] = r;
  }
}

void expandKeyWithSalt(List<int> key, List<int> salt, Blowfish c) {
  int j = 0;
  for (int i = 0; i < 18; i++) {
    c.p[i] ^= getNextWord(key, j);
  }

  j = 0;
  int l = 0, r = 0;
  for (int i = 0; i < 18; i += 2) {
    l ^= getNextWord(salt, j);
    r ^= getNextWord(salt, j);
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.p[i] = l;
    c.p[i + 1] = r;
  }

  for (int i = 0; i < 256; i += 2) {
    l ^= getNextWord(salt, j);
    r ^= getNextWord(salt, j);
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.s0[i] = l;
    c.s0[i + 1] = r;
  }

  for (int i = 0; i < 256; i += 2) {
    l ^= getNextWord(salt, j);
    r ^= getNextWord(salt, j);
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.s1[i] = l;
    c.s1[i + 1] = r;
  }

  for (int i = 0; i < 256; i += 2) {
    l ^= getNextWord(salt, j);
    r ^= getNextWord(salt, j);
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.s2[i] = l;
    c.s2[i + 1] = r;
  }

  for (int i = 0; i < 256; i += 2) {
    l ^= getNextWord(salt, j);
    r ^= getNextWord(salt, j);
    List<int> encrypted = encryptBlock(l, r, c);
    l = encrypted[0];
    r = encrypted[1];
    c.s3[i] = l;
    c.s3[i + 1] = r;
  }
}

List<int> encryptBlock(int l, int r, Blowfish c) {
  int xl = l, xr = r;
  xl ^= c.p[0];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[1];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[2];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[3];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[4];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[5];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[6];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[7];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[8];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[9];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[10];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[11];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[12];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[13];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[14];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[15];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[16];
  xr ^= c.p[17];
  return [xr, xl];
}

List<int> decryptBlock(int l, int r, Blowfish c) {
  int xl = l, xr = r;
  xl ^= c.p[17];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[16];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[15];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[14];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[13];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[12];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[11];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[10];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[9];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[8];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[7];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[6];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[5];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[4];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[3];
  xr ^= ((c.s0[(xl >> 24) & 0xFF] + c.s1[(xl >> 16) & 0xFF]) ^
              c.s2[(xl >> 8) & 0xFF]) +
          c.s3[(xl) & 0xFF] ^
      c.p[2];
  xl ^= ((c.s0[(xr >> 24) & 0xFF] + c.s1[(xr >> 16) & 0xFF]) ^
              c.s2[(xr >> 8) & 0xFF]) +
          c.s3[(xr) & 0xFF] ^
      c.p[1];
  xr ^= c.p[0];
  return [xr, xl];
}
