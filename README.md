EN | [中文](https://github.com/YYHEggEgg/EggEgg.XC.RSAUtil/tree/master/README_Chinese.md)

# Notice

This package is **not the official version of GitHub Repository [stulzq/RSAUtil](https://github.com/stulzq/RSAUtil)** but a custom fork. Please go to [NuGet XC.RSAUtil](https://www.nuget.org/packages/XC.RSAUtil) for the official one.

# RSAUtil
A .NET Core RSA tool that provides the ability of data encryption, decryption, signing and verifying signature. It supports using and converting RSA keys of formats, namely: `.xml`, `.pem`, `.der`.

[![Latest version](https://img.shields.io/nuget/v/EggEgg.XC.RSAUtil.svg?style=flat-square)](https://www.nuget.org/packages/EggEgg.XC.RSAUtil/)

## Installation via NuGet
````shell
Install-Package EggEgg.XC.RSAUtil
````

## Documentation

### What are the special features of this fork?

- The `RSAUtilBase.LoadRSAKey(byte[])` method can easily load any supported format of private and public keys, automatically detecting the format, key size, and other parameters, so you don't need to worry about the underlying details of RSA operations.
- (compared to the original version) Added comprehensive support for PKCS#1 RSA public keys.
- Supports the `.der` binary key format.
- Together with the `RsaKeyFeature` class and the `RSAUtilBase.TreatRSAKeyType(byte[])` method, compared to the original implementation's hard-coded approach, you can more flexibly handle RSA key operations.
- Added unit tests to ensure the correctness of the package's behavior.

### Generating keys

> Use the "RsaKeyGenerator" class. The result returned is a `BinaryKeyResult` containing `KeySize`, `Format`, `Padding`, `PrivateKey` and `PublicKey`.

Like this:

```csharp
var keys = RsaKeyGenerator.GetKey(RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, 2048);
// or use RsaKeyFeature class
// var keys = RsaKeyGenerator.GetKey(new RsaKeyFeature { Format = RsaKeyFormat.Der, Padding = RsaKeyPadding.Pkcs1 }, 2048);

byte[] privateKey = keys.PrivateKey;
byte[] publicKey = key.PublicKey;
// You can directly use it also:
var rsa = keys.GetRSAInstance();
// Or save key and load next time:
rsa = RSAUtilBase.LoadRSAKey(privateKey);
```

### RSA key conversion

You can freely convert key formats using `RsaKeyConvert.Format()`. For example:

```cs
RsaKeyConvert.Format(key,
    new RsaKeyFeature { IsPrivate = true; Format = RsaKeyFormat.Der; Padding = RsaKeyPadding.Pkcs1 });

RsaKeyConvert.Format(key,
    new RsaKeyFeature { IsPrivate = false; Format = RsaKeyFormat.Pem; Padding = RsaKeyPadding.Pkcs1 });

RsaKeyConvert.Format(key,
    new RsaKeyFeatire { IsPrivate = false; Format = RsaKeyFormat.Pem; Padding = RsaKeyPadding.Pkcs8 });
```

You can also use `RSAUtilBase`'s instance method `FormatPublicKey` or `FormatPrivateKey` to export the key of any RSA instance, in any format you want.

```cs
var rsa = RsaKeyGenerator.GetKey(RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, 2048).GetRSAInstance();
rsa.FormatPublicKey(new RsaKeyFeature { IsPrivate = false; Format = RsaKeyFormat.Xml; Padding = RsaKeyPadding.Xml });
rsa.FormatPrivateKey(new RsaKeyFeatire { IsPrivate = false; Format = RsaKeyFormat.Pem; Padding = RsaKeyPadding.Pkcs8 });
rsa.FormatPrivateKey(new RsaKeyFeature { IsPrivate = true; Format = RsaKeyFormat.Der; Padding = RsaKeyPadding.Pkcs1 });
```

### Encryption, decryption, signing, and signature verification

Load any key via `RSAUtilBase.LoadRSAKey(byte[])`, then:

- Encryption: `RSAUtilBase.RsaEncrypt()`
- Decryption: `RSAUtilBase.RsaDecrypt()`
- Sign: `RSAUtilBase.SignData()`
- Verification: `RSAUtilBase.VerifyData()`

## Open-source components used

[bc-csharp](https://github.com/onovotny/bc-csharp "bc-csharp") - onovotny
