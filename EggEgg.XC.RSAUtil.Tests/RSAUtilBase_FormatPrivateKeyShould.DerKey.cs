namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_FormatPrivateKeyShould
{
    [Theory]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_5.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_5.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_5.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_5.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_5.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_5.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_5.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_5.der")]
    public void FormatPrivateKey_DerKey2DerKey_ManyKeys(string rsakeyPath, RsaKeyPadding outputPadding, bool outputIsPrivate, string expectedOutputPath)
    {
        var rsa = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        var exported = rsa.FormatPrivateKey(new RsaKeyFeature { Format = RsaKeyFormat.Der, IsPrivate = outputIsPrivate, Padding = outputPadding });
        Assert.Equal(File.ReadAllBytes(expectedOutputPath), exported);
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_5)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_5)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_5)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_5)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_5)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_5)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_2)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_3)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_4)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_5)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_5)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_5)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_2)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_3)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_4)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_5)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_5)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_5)]
    public void FormatPrivateKey_DerKey2StringKey_ManyKeys(string rsakeyPath, RsaKeyFormat outputFormat, RsaKeyPadding outputPadding, bool outputIsPrivate, string expectedOutput)
    {
        var rsa = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        var expected = Encoding.Default.GetBytes(expectedOutput.ReplaceLineEndings());
        var exported = rsa.FormatPrivateKey(new RsaKeyFeature { Format = outputFormat, IsPrivate = outputIsPrivate, Padding = outputPadding });
        Assert.Equal(expected, exported);
    }

}