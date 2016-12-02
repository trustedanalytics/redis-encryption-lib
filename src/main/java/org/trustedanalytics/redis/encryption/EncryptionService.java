/**
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.trustedanalytics.redis.encryption;

import com.google.common.base.Preconditions;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionService {
  private SecretKeySpec key;
  private SecureRandom secureRandom;

  public EncryptionService(String cipher) {
    this(cipher, new SecureRandom());
  }

  public EncryptionService(String cipher, SecureRandom sRandom) {
    Preconditions.checkNotNull(cipher);
    Preconditions.checkArgument(cipher.length() == 16, "Encryption key has to be 128-bit long");

    secureRandom = sRandom;
    key = new SecretKeySpec(cipher.getBytes(), "AES");
  }

  public SecureJson encrypt(byte[] toEncrypt) throws EncryptionException {
    try {
      Cipher encryptionCipher = getCipherInstance();

      encryptionCipher.init(Cipher.ENCRYPT_MODE, key, secureRandom);
      byte[] ivBytes = encryptionCipher.getIV();
      byte[] valueBytes = encryptionCipher.doFinal(toEncrypt);

      return new SecureJson(ivBytes, valueBytes);
    } catch (NoSuchAlgorithmException |
            NoSuchPaddingException e) {
      throw new RuntimeEncryptionException("Unable to create encryption cipher", e);
    } catch (InvalidKeyException |
            IllegalBlockSizeException |
            BadPaddingException e) {
      throw new EncryptionException("Unable to encrypt message", e);
    }
  }

  public byte[] decrypt(SecureJson toDecrypt) throws EncryptionException {
    try {
      Cipher decryptionCipher = getCipherInstance();

      GCMParameterSpec iv = new GCMParameterSpec(128, toDecrypt.getIv());
      decryptionCipher.init(Cipher.DECRYPT_MODE, key, iv);

      return decryptionCipher.doFinal(toDecrypt.getValue());
    } catch (NoSuchAlgorithmException |
            NoSuchPaddingException e) {
      throw new RuntimeEncryptionException("Unable to create decryption cipher", e);
    } catch (InvalidKeyException |
            InvalidAlgorithmParameterException |
            IllegalBlockSizeException |
            BadPaddingException e) {
      throw new EncryptionException("Unable to decrypt message", e);
    }
  }

  private Cipher getCipherInstance() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return Cipher.getInstance("AES/GCM/NoPadding");
  }
}
