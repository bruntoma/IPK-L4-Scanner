using System.Net;
using System.Runtime.InteropServices;

namespace IPK_L4_Scanner;

class Program
{
    static void Main(string[] args)
    {
        Scanner scanner = new Scanner("enp0s3", IPAddress.Parse("8.8.8.8"), ScannerProtocol.TCP, 15000, 0);
        scanner.PrepareSocket();

        for (int i = 52; i < 54; i++)
        {
            var result = scanner.ScanPort(i);

            //if (result.PortState == PortState.Open)
            //{
                Console.WriteLine(result.Port + ", " + result.PortState);
            //}
        }
        Console.WriteLine("done");
    }
}
