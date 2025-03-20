using System.Net;
using System.Runtime.InteropServices;

namespace IPK_L4_Scanner;

class Program
{
    static void Main(string[] args)
    {
        //fe80::da44:89ff:fe62:1ffc%enp0s3"
        BaseScanner scanner = new UdpScanner("enp0s3", IPAddress.Parse("fe80::da44:89ff:fe62:1ffc%enp0s3"), 2000);

        scanner.CreateSockets();

        for (int i = 52; i < 90; i++)
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
