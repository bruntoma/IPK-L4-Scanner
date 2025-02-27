using System.Net;
using System.Runtime.InteropServices;

namespace IPK_L4_Scanner;

class Program
{
    static async Task Main(string[] args)
    {
        Scanner scanner = new Scanner("enp0s3", IPAddress.Parse("8.8.8.8"), ScannerProtocol.TCP);
        scanner.PrepareSocket();

        for (int i = 0; i < 100; i++)
        {
            var result = scanner.ScanPort(50);
            Console.WriteLine(result.PortState);
        }
        Console.WriteLine("done");
    }
}
