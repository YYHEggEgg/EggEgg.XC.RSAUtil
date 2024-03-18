using System.Security.Cryptography;

namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_VerifyDataShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    public void VerifyData_StringKey(string rsakey, string decrypted_base64, string sign_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(rsakey);
        var res = key.VerifyData(Convert.FromBase64String(decrypted_base64), Convert.FromBase64String(sign_base64), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(res);
    }
}
