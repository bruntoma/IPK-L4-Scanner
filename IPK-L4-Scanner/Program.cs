using System.Collections.Concurrent;
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
        int timeout = 2000;
        string device = "enp0s3";
        //fe80::da44:89ff:fe62:1ffc%enp0s3"
        string target = "scanme.nmap.org";
        int portMin = 0;
        int portMax = 300;


        int filtered = 0;
        int open = 0;
        int closed = 0;
        var filteredList = new ConcurrentQueue<int>();

        var addresses = await Dns.GetHostAddressesAsync(target);

        Stopwatch watch = Stopwatch.StartNew();
        foreach(var address in addresses)
        {
            var tcpScanner = new TcpScanner(device, address, timeout);
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
                Console.WriteLine("[X]: " + address + ": " + ((int)result.Port).ToString() + ", " + result.PortState);

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

           
        }

        System.Console.WriteLine($"Scanning finished. Time: {watch.ElapsedMilliseconds}");

        System.Console.WriteLine("Time: " + watch.ElapsedMilliseconds);
        System.Console.WriteLine("Filtered count: " + filtered);
        //foreach(var port in filteredList)
        //  System.Console.Write(port + " ");
        System.Console.WriteLine();
        System.Console.WriteLine("Closed count: " + closed);
        System.Console.WriteLine("Open count: " + open);
        System.Console.WriteLine("Total count: " + (open + closed + filtered));
    }
}

