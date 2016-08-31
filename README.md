# redis-encryption-lib
Encryption layer for redis database.
This library is used when there are sensetive information in DB which must be encrypted.
Currently it is used by:
 * [user-management](../../../user-management)
 * [service-exposer](../../../service-exposer)
 * [data-acquisition](../../../data-acquisition)

Key and values in redis are encrypted in different way.
 * **Value** - After encrypting, value in DB is stored as a special struct which contains IV and encrypted object. Each element has its own IV, which allows decrypting.
 * **Key** - is hashed, because there is no possibility to store IV for each of it. So only comparison of encrypted(hashed) keys is possible. There is no possiility to list all keys from DB.

### Sample usage
#### Encrypting value
###### Config
```java
@Value("${...}")
private String cipher;

@Bean
protected EncryptionService encryptionService() {
  return new EncryptionService(cipher);
}

@Bean
SecureJacksonJsonRedisSerializer<PLACEHOLDER> secureJacksonJsonRedisSerializer(EncryptionService encryptionService) {
  return new SecureJacksonJsonRedisSerializer<PLACEHOLDER>(PLACEHOLDER.class, encryptionService);
}
```
**NOTE:** `PLACEHOLDER` is name of class stored in DB. This class need to have parameterless constructor.
One service can be used for several serializers.
###### Usage
Set serializer in redis template:
`template.setValueSerializer()` or `template.setHashValueSerializer()`

#### Encrypting (hashing) key
###### Config
```java
@Value("${...}")
private String salt;

@Bean
protected HashService hashService() {
  return new HashService(salt);
}

@Bean
protected HashedStringRedisSerializer secureStringRedisSerializer(HashService hashService) {
  return new HashedStringRedisSerializer(hashService);
}
 ```
###### Usage
Set serializer in redis template:
`template.setKeySerializer(...)` or `template.setHashKeySerializer(...)`
