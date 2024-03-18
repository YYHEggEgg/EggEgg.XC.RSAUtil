using System.Security.Cryptography;

namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_RsaEncryptShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64)]
    public void RsaEncrypt_StringKey_AssertByDecrypt(string rsakey, string raw_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(rsakey);
        var res = key.RsaEncrypt(Convert.FromBase64String(raw_base64), RSAEncryptionPadding.Pkcs1);
        var decrypted = key.RsaDecrypt(res, RSAEncryptionPadding.Pkcs1);
        Assert.Equal(raw_base64, Convert.ToBase64String(decrypted));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64)]
    public void RsaEncrypt_StringKey_NoAssert(string rsakey, string raw_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(rsakey);
        key.RsaEncrypt(Convert.FromBase64String(raw_base64), RSAEncryptionPadding.Pkcs1);
    }
}
