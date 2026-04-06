using System.Security.Cryptography.X509Certificates;
class Program {
    static void Main(string[] args) {
        var data = System.IO.File.ReadAllBytes(args[0]);
        var cert = CertLoader.LoadCert(data);
        Console.WriteLine(cert.Subject);
    }
}
static class CertLoader {
    public static X509Certificate2 LoadCert(byte[] data) {
        var cert = new X509Certificate2();
        cert.Import(data);
        return cert;
    }
}
