using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using CommandLine;
using static IPK_L4_Scanner.BaseScanner;

namespace IPK_L4_Scanner;

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
                if (options.Interface == null || options.Target == null || options.TcpPorts == null)
                {
                    System.Console.WriteLine("Args error");
                    return;
                }

                await RunTcpScan(options.Interface, options.Target, ParsePorts(options.TcpPorts), options.Timeout);
            });

        //fe80::da44:89ff:fe62:1ffc%enp0s3"
    }

    public static async Task RunTcpScan(string deviceName, string target, IEnumerable<int> ports, int timeout)
    {
        string device = "enp0s3";
        var addresses = await Dns.GetHostAddressesAsync(target);


        foreach (var address in addresses)
        {
            var tcpScanner = new UdpScanner(device, address, timeout);
            tcpScanner.ScanFinished += PrintScanResult;
            tcpScanner.CreateSockets();


            var tasks = new List<Task<ScanResult>>();
            foreach (var port in ports)
            {
                tasks.Add(tcpScanner.StartPortScanAsync(port));
            }
            await Task.WhenAll(tasks);
            tcpScanner.ScanFinished -= PrintScanResult;
            tcpScanner.Dispose();
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
        Console.WriteLine("[X]: " + target + ": " + ((int)result.Port).ToString() + ", " + result.PortState);
    }
}

