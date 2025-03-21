using System.Net;
using System.Runtime.InteropServices;

namespace IPK_L4_Scanner;

class Program
{
    static async Task Main(string[] args)
    {
        //fe80::da44:89ff:fe62:1ffc%enp0s3"
        BaseScanner scanner = new UdpScanner("enp0s3", IPAddress.Parse("10.0.0.138"), 2000);

        scanner.CreateSockets();

        var list = new List<Task<ScanResult>>();
        for (int i = 52; i < 56; i++)
        {
            list.Add(scanner.ScanPortAsync(i));

            //if (result.PortState == PortState.Open)
            //{
            //}
        }

        Task.WaitAll(list.ToArray());

        foreach(var t in list)
        {
            var result = t.Result;
            Console.WriteLine(result.Port + ", " + result.PortState);
        }


        Console.WriteLine("done");
    }
}

