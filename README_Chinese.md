[EN](https://github.com/YYHEggEgg/EggEgg.XC.RSAUtil/tree/master/README.md) | 中文

# Notice

This package is **not the official version of GitHub Repository [stulzq/RSAUtil](https://github.com/stulzq/RSAUtil)** but a custom modified version. Please go to [NuGet XC.RSAUtil](https://www.nuget.org/packages/XC.RSAUtil) for the official one.

# RSAUtil
.NET Core RSA 工具，支持数据加密，解密，签名和验证签名，支持 XML、PKCS1、PKCS8、DER 4 种密钥格式，支持这 4 种格式的密钥转换。

[![Latest version](https://img.shields.io/nuget/v/EggEgg.XC.RSAUtil.svg?style=flat-square)](https://www.nuget.org/packages/EggEgg.XC.RSAUtil/)


## NuGet 安装
````shell
Install-Package EggEgg.XC.RSAUtil
````

## 文档

### 开箱即用

可使用 `RSAUtilBase.LoadRSAKey(byte[])` 来快捷加载任何 XML、PKCS1、PKCS8、DER 格式的私钥与公钥，自动检测格式、密钥位数等参数。私钥实例支持公钥的功能（公钥加密，验证签名）。

### 生成密钥

> 使用 `RsaKeyGenerator` 类。返回的结果为包含 `KeySize`, `Format`, `Padding`, `PrivateKey` 与 `PublicKey` 的 `BinaryKeyResult`.

例如：

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

### RSA密钥转换

使用 `RsaKeyConvert.Format()` 可进行密钥格式间的自由转换。例如：

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

也可使用 `RsaKeyConvert` 类下其他硬编码转化格式的方法。

### 加密，解密，签名和验证签名

使用 `RSAUtilBase.LoadRSAKey(byte[])` 加载密钥，然后就可以使用：

- 加密：`RSAUtilBase.RsaEncrypt()`
- 解密：`RSAUtilBase.RsaDecrypt()`
- 签名：`RSAUtilBase.SignData()`
- 验签：`RSAUtilBase.VerifyData()`

## 使用的开源组件

 [bc-csharp](https://github.com/onovotny/bc-csharp "bc-csharp") - onovotny
