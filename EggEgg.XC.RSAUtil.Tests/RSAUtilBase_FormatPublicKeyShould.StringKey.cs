namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_FormatPublicKeyShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, RsaKeyPadding.Pkcs1, "TestDerKeys/Pkcs1PublicKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_5.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, RsaKeyPadding.Pkcs8, "TestDerKeys/Pkcs8PublicKey_5.der")]
    public void FormatPublicKey_StringKey2DerKey_ManyKeys(string rsakey, RsaKeyPadding outputPadding, string expectedOutputPath)
    {
        var rsa = RSAUtilBase.LoadRSAKey(rsakey);
        var exported = rsa.FormatPublicKey(new RsaKeyFeature { Format = RsaKeyFormat.Der, IsPrivate = false, Padding = outputPadding });
        Assert.Equal(File.ReadAllBytes(expectedOutputPath), exported);
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, TestRSAKeys.Pkcs1PublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, TestRSAKeys.Pkcs8PublicKey_5)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, RsaKeyFormat.Xml, RsaKeyPadding.Xml, TestRSAKeys.XmlPublicKey_5)]
    public void FormatPublicKey_StringKey2StringKey_ManyKeys(string rsakey, RsaKeyFormat outputFormat, RsaKeyPadding outputPadding, string expectedOutput)
    {
        var rsa = RSAUtilBase.LoadRSAKey(rsakey);
        var expected = Encoding.Default.GetBytes(expectedOutput.ReplaceLineEndings());
        var exported = rsa.FormatPublicKey(new RsaKeyFeature { Format = outputFormat, IsPrivate = false, Padding = outputPadding });
        Assert.Equal(expected, exported);
    }
}