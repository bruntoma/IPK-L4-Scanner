using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using CommandLine;
using static IPK_L4_Scanner.BaseScanner;

namespace IPK_L4_Scanner;

public enum ScannerType {
    Udp,
    Tcp
}

public class CommandLineOptions
{
    [Option('i', "interface", Required = false, HelpText = "Network interface to use for scanning")]
    public string? Interface { get; set; }

    [Option('t', "pt", Required = false, HelpText = "TCP ports to scan (e.g., 22 or 1-65535 or 22,23,24)")]
    public string? TcpPorts { get; set; }

    [Option('u', "pu", Required = false, HelpText = "UDP ports to scan (e.g., 53 or 1-65535 or 53,67)")]
    public string? UdpPorts { get; set; }

    [Option('w', "wait", Required = false, Default = 5000, HelpText = "Timeout in milliseconds (default: 5000)")]
    public int Timeout { get; set; } = 5000;

    [Value(0, MetaName = "target", HelpText = "Hostname or IP address to scan")]
    public string? Target { get; set; }
}

class Program
{

    static async Task Main(string[] args)
    {

        await Parser.Default.ParseArguments<CommandLineOptions>(args)
            .WithParsedAsync(async options =>
            {
                try 
                {                
                    if (options.Interface == null)
                    {
                        System.Console.WriteLine("Available interfaces:");
                        System.Console.WriteLine("---------------------");
                        var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                        foreach (var i in interfaces)
                        {
                            System.Console.WriteLine(i.Name);
                        }
                        return;
                    }

                    if (options.Target == null)
                    {
                        System.Console.WriteLine("Target not specified");
                        return;
                    }

                    if (options.TcpPorts != null)
                        await RunScan(options.Interface, options.Target, ParsePorts(options.TcpPorts), options.Timeout, ScannerType.Tcp);

                    if (options.UdpPorts != null)
                        await RunScan(options.Interface, options.Target, ParsePorts(options.UdpPorts), options.Timeout, ScannerType.Udp);
                }
                catch(Exception e)
                {
                    System.Console.WriteLine(e.Message);
                }
            });

        //fe80::da44:89ff:fe62:1ffc%enp0s3"
    }

    public static async Task RunScan(string deviceName, string target, IEnumerable<int> ports, int timeout, ScannerType scannerType)
    {
        var addresses = await Dns.GetHostAddressesAsync(target);

        foreach (var address in addresses)
        {
            BaseScanner scanner = (scannerType == ScannerType.Tcp) ? new TcpScanner(deviceName, address, timeout) : new UdpScanner(deviceName, address, timeout);
            scanner.CreateSockets();

            var tasks = new List<Task>();
            foreach (var port in ports)
            {
                tasks.Add(scanner.StartPortScanAsync(port).ContinueWith(result => PrintScanResult(address, result.Result)));
            }

            await Task.WhenAll(tasks);
            scanner.Dispose();
        }  
    }


     private static IEnumerable<int> ParsePorts(string portRanges)
    {
        var ports = new List<int>();

        foreach (var range in portRanges.Split(','))
        {
            if (range.Contains('-'))
            {
                var split = range.Split('-');
                if (int.TryParse(split[0], out int firstPort) && int.TryParse(split[1], out int lastPort))
                {
                    ports.AddRange(Enumerable.Range(firstPort, lastPort - firstPort + 1));
                }
                else
                {
                    throw new Exception($"Invalid port range: {range}");
                }
            }
            else
            {
                if (int.TryParse(range, out int port))
                {
                    ports.Add(port);
                }
                else
                {
                    throw new Exception($"Invalid port: {port}");
                }
            }
        }
        return ports.Distinct().OrderBy(p => p);
    }

    public static void PrintScanResult(IPAddress target, ScanResult result)
    {
        Console.WriteLine(target + " " + result.Port + " " + result.PortState.ToString().ToLower());
    }
}

