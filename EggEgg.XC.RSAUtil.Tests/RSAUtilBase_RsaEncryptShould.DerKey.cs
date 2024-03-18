using System.Security.Cryptography;

namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_RsaEncryptShould
{
    [Theory]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64)]
    public void RsaEncrypt_DerKey_AssertByDecrypt(string rsakeyPath, string raw_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        var res = key.RsaEncrypt(Convert.FromBase64String(raw_base64), RSAEncryptionPadding.Pkcs1);
        var decrypted = key.RsaDecrypt(res, RSAEncryptionPadding.Pkcs1);
        Assert.Equal(raw_base64, Convert.ToBase64String(decrypted));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64)]
    public void RsaEncrypt_DerKey_NoAssert(string rsakeyPath, string raw_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        key.RsaEncrypt(Convert.FromBase64String(raw_base64), RSAEncryptionPadding.Pkcs1);
    }
}
