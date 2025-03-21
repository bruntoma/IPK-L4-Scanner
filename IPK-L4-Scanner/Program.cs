using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace IPK_L4_Scanner;

class Program
{
    static async Task Main(string[] args)
    {
        
        //fe80::da44:89ff:fe62:1ffc%enp0s3"
        BaseScanner scanner = new TcpScanner("enp0s3", IPAddress.Parse("fe80::da44:89ff:fe62:1ffc%enp0s3"), 100);

        scanner.CreateSockets();

        Stopwatch watch = Stopwatch.StartNew();
        var list = new List<Task<ScanResult>>();
        for (int i = 52; i < 270; i++)
        {
            //list.Add(scanner.ScanPortAsync(i));
            await scanner.ScanPortAsync(i);
            //Console.WriteLine(res.Port + ", " + res.PortState);
            //if (result.PortState == PortState.Open)
            //{
            //}
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
            Console.WriteLine(result.Port + ", " + result.PortState);
        }

        System.Console.WriteLine($"Time: {watch.ElapsedMilliseconds}");

        Console.WriteLine("done");
    }
}

