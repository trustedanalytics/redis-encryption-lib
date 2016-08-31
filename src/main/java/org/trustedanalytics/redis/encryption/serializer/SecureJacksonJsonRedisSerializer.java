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

package org.trustedanalytics.redis.encryption.serializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import org.trustedanalytics.redis.encryption.EncryptionException;
import org.trustedanalytics.redis.encryption.EncryptionService;
import org.trustedanalytics.redis.encryption.SecureJson;

import java.io.IOException;


public class SecureJacksonJsonRedisSerializer<T> extends Jackson2JsonRedisSerializer<T> {

  private EncryptionService encryptionService;

  private ObjectMapper objectMapper = new ObjectMapper();

  @Autowired
  public SecureJacksonJsonRedisSerializer(Class<T> type, EncryptionService encryptionService) {
    super(type);
    this.encryptionService = encryptionService;
  }

  @Override
  public T deserialize(byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      return null;
    }

    try {
      SecureJson sj = this.objectMapper.readValue(bytes, 0, bytes.length, SecureJson.class);
      byte[] plainJson = encryptionService.decrypt(sj);
      return super.deserialize(plainJson);
    } catch (IOException e) {
      throw new SerializationException("Could not read Secure-JSON", e);
    } catch (EncryptionException e) {
      throw new SerializationException("Could not decrypt Secure-JSON", e);
    }
  }

  @Override
  public byte[] serialize(Object t) {
    if (t == null) {
      return new byte[0];
    }

    try {
      byte[] plainJson = super.serialize(t);
      SecureJson sj = encryptionService.encrypt(plainJson);
      return this.objectMapper.writeValueAsBytes(sj);
    } catch (IOException e) {
      throw new SerializationException("Could not write Secure-JSON", e);
    } catch (EncryptionException e) {
      throw new SerializationException("Could not encrypt Secure-JSON", e);
    }
  }
}
