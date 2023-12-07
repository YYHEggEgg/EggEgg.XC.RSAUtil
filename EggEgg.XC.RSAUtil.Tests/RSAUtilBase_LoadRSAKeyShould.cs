namespace YYHEggEgg.XC.RSAUtil.Tests;

public class RSAUtilBase_LoadRSAKeyShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5)]
    [InlineData(TestRSAKeys.XmlPrivateKey_2)]
    [InlineData(TestRSAKeys.XmlPrivateKey_3)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5)]
    [InlineData(TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.XmlPublicKey_5)]
    public void LoadRSAKey_ManyKeys(string rsakey)
    {
        var rsa = RSAUtilBase.LoadRSAKey(rsakey);
        Assert.Equal(2048, rsa.PublicRsa?.KeySize);
        if (rsa.PrivateRsa != null)
            Assert.Equal(2048, rsa.PrivateRsa.KeySize);
    }
}