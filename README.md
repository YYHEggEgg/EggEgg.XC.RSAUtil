EN | [中文](https://github.com/YYHEggEgg/EggEgg.XC.RSAUtil/tree/master/README_Chinese.md)

# Notice

This package is **not the official version of GitHub Repository [stulzq/RSAUtil](https://github.com/stulzq/RSAUtil)** but a custom fork. Please go to [NuGet XC.RSAUtil](https://www.nuget.org/packages/XC.RSAUtil) for the official one.

# RSAUtil
A .NET Core RSA tool that provides the ability of data encryption, decryption, signing and verifying signature. It supports using and converting RSA keys of 4 key formats, namely: xml, pkcs1, pkcs8, der.

[![Latest version](https://img.shields.io/nuget/v/EggEgg.XC.RSAUtil.svg?style=flat-square)](https://www.nuget.org/packages/EggEgg.XC.RSAUtil/)

## Installation via NuGet
````shell
Install-Package EggEgg.XC.RSAUtil
````

## Documentation

### Ready to use

You can use `RSAUtilBase.LoadRSAKey(byte[])` to quickly load private and public keys in XML, PKCS1, PKCS8 and DER formats, and paramters like the format and the bits of the RSA key can be auto-detected. The private key instance supports the functionality of the public key (public key encryption, signature verification).

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
    new RsaKeyFeature { IsPrivate = true; Format = RsaKeyFormat.Xml; Padding = RsaKeyPadding.Xml }, 
    new RsaKeyFeature { IsPrivate = true; Format = RsaKeyFormat.Der; Padding = RsaKeyPadding.Pkcs1 });

RsaKeyConvert.Format(key,
    new RsaKeyFeature { IsPrivate = false; Format = RsaKeyFormat.Xml; Padding = RsaKeyPadding.Xml },
    new RsaKeyFeature { IsPrivate = false; Format = RsaKeyFormat.Pem; Padding = RsaKeyPadding.Pkcs1 });

RsaKeyConvert.Format(key, 
    new RsaKeyFeature { IsPrivate = true; Format = RsaKeyFormat.Pem; Padding = RsaKeyPadding.Pkcs1 },
    new RsaKeyFeatire { IsPrivate = false; Format = RsaKeyFormat.Pem; Padding = RsaKeyPadding.Pkcs8 });
```

Other hardcoded conversion methods can also be used under the `RsaKeyConvert` class.

### Encryption, decryption, signing, and signature verification

Load any key via `RSAUtilBase.LoadRSAKey(byte[])`, then:

- Encryption: `RSAUtilBase.RsaEncrypt()`
- Decryption: `RSAUtilBase.RsaDecrypt()`
- Sign: `RSAUtilBase.SignData()`
- Verification: `RSAUtilBase.VerifyData()`

## Open-source components used

[bc-csharp](https://github.com/onovotny/bc-csharp "bc-csharp") - onovotny
