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

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;

import java.security.SecureRandom;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

@RunWith(MockitoJUnitRunner.class)
public class EncryptionServiceTest {

  private static final String CIPHER = "16-DigitsCipherK";

  private static final String ORIGINAL = "{\"iv\":\"ab==\",\"value\":\"def=\"}";
  private static final byte[] IV = new byte[]{64, -1, 109, 62, -93, -110, 2, 112, -86, 12, -25, -100};
  private static final byte[] ENCRYPTED = new byte[]{-83, 71, -116, 115, 105, -76, -102, -36, 50, 121, -79, 18, 45, -28, 55, -70, 78, -40, -105, -40, 46, 31, 18, -82, 82, -47, 66, 70, 50, -27, 9, 38, 102, -103, 70, -27, 5, 119, -42, -27, -28, -50, 4, 125};
  private static final SecureJson SECURE_JSON = new SecureJson(IV, ENCRYPTED);

  private EncryptionService encryptionService;

  @Mock
  private SecureRandom secureRandom;

  @Before
  public void setUp() {
    encryptionService = new EncryptionService(CIPHER, secureRandom);
  }

  @Test
  public void shouldEncrypt() throws EncryptionException {
    doAnswer(new Answer() {
      public Object answer(InvocationOnMock invocation) {
        Object[] args = invocation.getArguments();
        int length = ((byte[])args[0]).length;
        System.arraycopy(IV, 0, args[0], 0, length);
        return null;
      }
    }).when(secureRandom).nextBytes(any(byte[].class));

    SecureJson sut = encryptionService.encrypt(ORIGINAL.getBytes());

    Assert.assertEquals(SECURE_JSON, sut);
  }

  @Test
  public void shouldDecrypt() throws EncryptionException {
    byte[] sut = encryptionService.decrypt(SECURE_JSON);

    Assert.assertEquals(ORIGINAL, new String(sut));
  }

  @Test(expected = EncryptionException.class)
  public void decryption_shouldThrowException_whenWrongIV() throws EncryptionException {
    SecureJson secureJson = new SecureJson("aaa".getBytes(),"bbb".getBytes());

    byte[] sut = encryptionService.decrypt(secureJson);
  }

  @Test(expected = IllegalArgumentException.class)
  public void encryptionServiceConstructor_shouldThrowException_whenWrongCipher() {
    EncryptionService sut = new EncryptionService(CIPHER + CIPHER);
  }
}
