namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_LoadRSAKeyShould
{
    [Theory]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der")]
    public void LoadRSAKey_DerKey_ManyKeys(string rsakeyPath)
    {
        var rsa = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        Assert.Equal(2048, rsa.PublicRsa?.KeySize);
        if (rsa.PrivateRsa != null)
            Assert.Equal(2048, rsa.PrivateRsa.KeySize);
    }
}
