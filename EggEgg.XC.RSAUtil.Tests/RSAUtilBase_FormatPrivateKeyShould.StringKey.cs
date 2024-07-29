namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_FormatPrivateKeyShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyPadding.Pkcs1, true, "TestDerKeys/Pkcs1PrivateKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyPadding.Pkcs8, true, "TestDerKeys/Pkcs8PrivateKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyPadding.Pkcs1, false, "TestDerKeys/Pkcs1PublicKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyPadding.Pkcs8, false, "TestDerKeys/Pkcs8PublicKey_5.der")]
    public void FormatPrivateKey_StringKey2DerKey_ManyKeys(string rsakey, RsaKeyPadding outputPadding, bool outputIsPrivate, string expectedOutputPath)
    {
        var rsa = RSAUtilBase.LoadRSAKey(rsakey);
        var exported = rsa.FormatPrivateKey(new RsaKeyFeature { Format = RsaKeyFormat.Der, IsPrivate = outputIsPrivate, Padding = outputPadding });
        Assert.Equal(File.ReadAllBytes(expectedOutputPath), exported);
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_5)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_5)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, true, TestRSAKeys.Pkcs1PrivateKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, true, TestRSAKeys.Pkcs8PrivateKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyFormat.Xml, RsaKeyPadding.Xml, true, TestRSAKeys.XmlPrivateKey_5)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, false, TestRSAKeys.Pkcs1PublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, false, TestRSAKeys.Pkcs8PublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, RsaKeyFormat.Xml, RsaKeyPadding.Xml, false, TestRSAKeys.XmlPublicKey_5)]
    public void FormatPrivateKey_StringKey2StringKey_ManyKeys(string rsakey, RsaKeyFormat outputFormat, RsaKeyPadding outputPadding, bool outputIsPrivate, string expectedOutput)
    {
        var rsa = RSAUtilBase.LoadRSAKey(rsakey);
        var expected = Encoding.Default.GetBytes(expectedOutput.ReplaceLineEndings());
        var exported = rsa.FormatPrivateKey(new RsaKeyFeature { Format = outputFormat, IsPrivate = outputIsPrivate, Padding = outputPadding });
        Assert.Equal(expected, exported);
    }

}