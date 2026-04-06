using System.Security.Cryptography.X509Certificates;
class Program {
    static void Main(string[] args) {
        // Uses X509Certificate2 only to read subject, never calls Import
        var cert = new X509Certificate2(args[0]);
        Console.WriteLine(cert.Subject);
    }
}
