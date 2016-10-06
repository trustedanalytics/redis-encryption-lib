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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.security.SecureRandom;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;

@RunWith(MockitoJUnitRunner.class)
public class HashServiceTest {

  private static final String SALT = "Randomly_Ganareted_32-DigitsSalt";
  private static final String ProperHashResult = "jVxfRzp42MAbwvZj3nyMkZKPXriLhRh2uH7lMvxsmbw=";

  private HashService hashService;

  @Before
  public void setUp() {
    hashService = new HashService(SALT);
  }

  @Test
  public void shouldHash() {
      String userMail = "email@example.com";

      String sut = hashService.hash(userMail);

      Assert.assertEquals(ProperHashResult, sut);
  }
  @Test
  public void shouldHashSameResultForSameInput() {
    String userMail = "email@example.com";

    String sut_first = hashService.hash(userMail);
    String sut_second = hashService.hash(userMail);

    Assert.assertEquals(ProperHashResult,sut_first);
    Assert.assertEquals(ProperHashResult,sut_second);
  }
}
