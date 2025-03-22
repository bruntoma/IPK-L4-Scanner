using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace IPK_L4_Scanner;

class Program
{
    static async Task Main(string[] args)
    {
        //fe80::da44:89ff:fe62:1ffc%enp0s3"
        BaseScanner scanner = new UdpScanner("enp0s3", IPAddress.Parse("fe80::da44:89ff:fe62:1ffc%enp0s3"), 100);

        scanner.CreateSockets();

        Stopwatch watch = Stopwatch.StartNew();
        var list = new List<Task<ScanResult>>();
        for (int i = 0; i < 500; i++)
        {
            await scanner.ScanPortAsync(i);
        }

        System.Console.WriteLine("SENDING DONE");


        var tasks = scanner.GetScanningTasks().ToArray();

        try { 
        Task.WaitAll(tasks);
        }
        catch(Exception e)
        {
            System.Console.WriteLine(e.Message);
        }

        watch.Stop();

        foreach(var t in tasks)
        {
            var result = t.Result;

            //if (result.PortState == PortState.Open)
                Console.WriteLine(result.Port + ", " + result.PortState);
        }

        System.Console.WriteLine($"Time: {watch.ElapsedMilliseconds}");

        Console.WriteLine("done");
    }
}

