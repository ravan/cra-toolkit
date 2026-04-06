using System.Security.Cryptography.X509Certificates;
class CertLoader {
    public static void LoadCert(string path) {
        var cert = new X509Certificate2();
        cert.Import(path);
    }
}
