using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using static IPK_L4_Scanner.BaseScanner;

namespace IPK_L4_Scanner;

class Program
{


    static async Task Main(string[] args)
    {

        int timeout = 2000;
        string device = "enp0s3";
        //fe80::da44:89ff:fe62:1ffc%enp0s3"
        string target = "10.0.0.138";
        int portMin = 0;
        int portMax = 500;


        int filtered = 0;
        int open = 0;
        int closed = 0;
        var filteredList = new ConcurrentQueue<int>();

        var addresses = await Dns.GetHostAddressesAsync(target);

        Stopwatch watch = Stopwatch.StartNew();
        foreach(var address in addresses)
        {
            var tcpScanner = new UdpScanner(device, address, timeout);
            tcpScanner.ScanFinished += PrintScanResult;
            tcpScanner.CreateSockets();

            
            var tasks = new List<Task<ScanResult>>();
            for (int i = portMin; i <= portMax; i++)
            {
                tasks.Add(tcpScanner.StartPortScanAsync(i)); 
            }

            while(tasks.Count > 0)
            {
                var completed = await Task.WhenAny(tasks);
                var result = await completed;

                //Statistics
                if (result.PortState == PortState.Filtered)
                {
                    filtered++;
                    filteredList.Enqueue(result.Port);
                }
                else if (result.PortState == PortState.Closed)
                    closed++;
                else if (result.PortState == PortState.Open)
                    open++;

                tasks.Remove(completed);
            }

            tcpScanner.ScanFinished -= PrintScanResult;
            tcpScanner.Dispose();
        }

        System.Console.WriteLine($"Scanning finished. Time: {watch.ElapsedMilliseconds}");

        System.Console.WriteLine("Time: " + watch.ElapsedMilliseconds);
        System.Console.WriteLine("Filtered count: " + filtered);
        foreach(var port in filteredList)
          System.Console.Write(port + " ");
        System.Console.WriteLine();
        System.Console.WriteLine("Closed count: " + closed);
        System.Console.WriteLine("Open count: " + open);
        System.Console.WriteLine("Total count: " + (open + closed + filtered));
    }

    public static void PrintScanResult(IPAddress target, ScanResult result)
    {
        Console.WriteLine("[X]: " + target + ": " + ((int)result.Port).ToString() + ", " + result.PortState);
    }
}

