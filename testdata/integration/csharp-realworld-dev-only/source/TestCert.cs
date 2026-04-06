using System.Security.Cryptography.X509Certificates;
class TestCert {
    public void TestImport() {
        var cert = new X509Certificate2();
        cert.Import("test.pfx");
    }
}
