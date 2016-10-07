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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;


public class HashService {
  private MessageDigest sha;
  private String salt;

  public HashService(String salt) {
    Preconditions.checkNotNull(salt);
    Preconditions.checkArgument(salt.length() == 32, "Hash salt should be 256-bit long");
    this.salt = salt;
  }

  public String hash(String toHash) {
    try {
      sha = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeEncryptionException("Unable to create encryption service", e);
    }

    byte[] hashedBytes = sha.digest((salt+toHash).getBytes());
    return new String(Base64.getEncoder().encode(hashedBytes));
  }
}
