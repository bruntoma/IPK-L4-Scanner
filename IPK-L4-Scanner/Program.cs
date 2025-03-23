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
        //fe80::da44:89ff:fe62:1ffc%enp0s3"
        using(BaseScanner scanner = new TcpScanner("enp0s3", IPAddress.Parse("fe80::da44:89ff:fe62:1ffc%enp0s3"), 2000))
        {
            scanner.CreateSockets();

            int filtered = 0;
            int open = 0;
            int closed = 0;
            var filteredList = new ConcurrentQueue<int>();
            scanner.ScanFinished += result => {
                Console.WriteLine(result.Port + ", " + result.PortState);
                if (result.PortState == PortState.Filtered)
                {
                    filtered++;
                    filteredList.Enqueue(result.Port);
                }
                else if (result.PortState == PortState.Closed)
                    closed++;
                else if (result.PortState == PortState.Open)
                    open++;
            };

            Stopwatch watch = Stopwatch.StartNew();

            var tasks = new List<Task>();
            for (int i = 40; i < 10000; i++)
            {
                tasks.Add(scanner.StartPortScanAsync(i)); 
            }

            Task.WaitAll(tasks.ToArray());
            System.Console.WriteLine($"Sending finished. Time: {watch.ElapsedMilliseconds}");

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
}

