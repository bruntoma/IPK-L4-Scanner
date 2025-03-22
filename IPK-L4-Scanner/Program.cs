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
        BaseScanner scanner = new TcpScanner("enp0s3", IPAddress.Parse("10.0.0.138"), 2000);
        scanner.CreateSockets();

        scanner.ScanFinished += result => {
            Console.WriteLine(result.Port + ", " + result.PortState);
        };

        Stopwatch watch = Stopwatch.StartNew();
        for (int i = 0; i < 50000; i++)
        {
            await scanner.StartPortScanAsync(i);
        
            var tasks = scanner.GetScanningTasks();
            Task.WaitAll(tasks.ToArray());
        }


        

        // try { 
        // Task.WaitAll(tasks);
        // }
        // catch(Exception e)
        // {
        //     System.Console.WriteLine(e.Message);
        // }

        // watch.Stop();

        // foreach(var t in tasks)
        // {
        //     var result = t.Result;

        //     //if (result.PortState == PortState.Open)
        //         Console.WriteLine(result.Port + ", " + result.PortState);
        // }

        // System.Console.WriteLine($"Time: {watch.ElapsedMilliseconds}");

        // Console.WriteLine("done");
    }
}

