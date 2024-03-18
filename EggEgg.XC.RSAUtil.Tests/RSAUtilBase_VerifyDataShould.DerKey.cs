using System.Security.Cryptography;

namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_VerifyDataShould
{
    [Theory]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    public void VerifyData_DerKey(string rsakeyPath, string decrypted_base64, string sign_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        var res = key.VerifyData(Convert.FromBase64String(decrypted_base64), Convert.FromBase64String(sign_base64), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(res);
    }
}
