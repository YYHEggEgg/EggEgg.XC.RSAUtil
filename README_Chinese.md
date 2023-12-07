[EN](README.md) | 中文

# Notice

This package is **not the official version of GitHub Repository [stulzq/RSAUtil](https://github.com/stulzq/RSAUtil)** but a custom modified version. Please go to [NuGet XC.RSAUtil](https://www.nuget.org/packages/XC.RSAUtil) for the official one.

# RSAUtil
.NET Core RSA 算法使用帮助工具，支持数据加密，解密，签名和验证签名，支持 XML、PKCS1、PKCS8 三种密钥格式，支持这三种格式的密钥转换。

[![Latest version](https://img.shields.io/nuget/v/EggEgg.XC.RSAUtil.svg?style=flat-square)](https://www.nuget.org/packages/EggEgg.XC.RSAUtil/)


## NuGet 安装
````shell
Install-Package EggEgg.XC.RSAUtil
````

## 文档

### 开箱即用

可使用 `RSAUtilBase.LoadRSAKey` 来快捷加载任何 XML、PKCS1、PKCS8 格式的私钥与公钥。私钥实例支持公钥的功能（公钥加密，验证签名）。

### 生成密钥

> 使用“RsaKeyGenerator”类。返回的结果是为包含 `privateKey` 与 `publicKey` 两项的 `KeyResult`。

格式：

```csharp
var keys = RsaKeyGenerator.XmlKey(2048); // XML 格式
// var keys = RsaKeyGenerator.Pkcs1Key(2048); // PKCS1 格式
// var keys = RsaKeyGenerator.Pkcs8Key(2048); // PKCS8 格式
var privateKey = keys.privateKey;
var publicKey = key.publicKey;
```

### RSA密钥转换

使用 `RsaKeyConvert.Format()` 可进行密钥格式间的自由转换。例如：

```cs
RsaKeyConvert.Format(key, RsaKeyType.Private | RsaKeyType.Xml, RsaKeyType.Private | RsaKeyType.Pkcs1);
RsaKeyConvert.Format(key, RsaKeyType.Public | RsaKeyType.Xml, RsaKeyType.Public | RsaKeyType.Pkcs1);
RsaKeyConvert.Format(key, RsaKeyType.Private | RsaKeyType.Pkcs1, RsaKeyType.Public | RsaKeyType.Pkcs8);
```

也可使用 `RsaKeyConvert` 类下其他硬编码转化格式的方法。

### 加密，解密，签名和验证签名

> XML，Pkcs1，Pkcs8分别对应类：`RsaXmlUtil`，`RsaPkcs1Util`，`RsaPkcs8Util`。它们继承自抽象类`RSAUtilBase`

- 加密：`RSAUtilBase.RsaEncrypt()`
- 解密：`RSAUtilBase.RsaDecrypt()`
- Sign：`RSAUtilBase.SignData()`
- 验证：`RSAUtilBase.VerifyData()`

## 使用的开源组件

 [bc-csharp](https://github.com/onovotny/bc-csharp "bc-csharp") - onovotny
