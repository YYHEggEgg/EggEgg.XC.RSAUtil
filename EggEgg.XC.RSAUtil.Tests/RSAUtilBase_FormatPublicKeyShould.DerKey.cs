namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_FormatPublicKeyShould
{
    [Theory]
    [InlineData("TestDerKeys/Pkcs1PublicKey_2.der", RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_3.der", RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_5.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_2.der", RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_3.der", RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_5.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_2.der", RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_3.der", RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_5.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_2.der", RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_3.der", RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_5.der")]
    public void FormatPublicKey_DerKey2DerKey_ManyKeys(string rsakeyPath, RsaKeyPadding outputPadding, string expectedOutputPath)
    {
        var rsa = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        var exported = rsa.FormatPublicKey(new RsaKeyFeature { Format = RsaKeyFormat.Der, IsPrivate = false, Padding = outputPadding });
        Assert.Equal(File.ReadAllBytes(expectedOutputPath), exported);
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs1PublicKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_2.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_2)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_3.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_3)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_4)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_5)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_5)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_5)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_2.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_2)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_3.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_3)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_4)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_5)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_5)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_5)]
    public void FormatPublicKey_DerKey2StringKey_ManyKeys(string rsakeyPath, RsaKeyFormat outputFormat, RsaKeyPadding outputPadding, string expectedOutput)
    {
        var rsa = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        var expected = Encoding.Default.GetBytes(expectedOutput.ReplaceLineEndings());
        var exported = rsa.FormatPublicKey(new RsaKeyFeature { Format = outputFormat, IsPrivate = false, Padding = outputPadding });
        Assert.Equal(expected, exported);
    }
}