using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using IPK_L4_Scanner.Packets;
using static IPK_L4_Scanner.NetworkExtensions;

namespace IPK_L4_Scanner;

public abstract class BaseScanner : IDisposable
{
    protected const int SOURCE_PORT = 258;
    protected static byte[] receiveBuffer = new byte[256];

    protected Socket? sendingSocket = null;
    protected Socket? receivingSocket = null;
    protected IPacketFactory packetFactory;
    protected IPEndPoint sourceEndPoint;
    protected IPAddress destinationIp;
    protected string interfaceName;
    protected int timeout;

    protected int lastScannedPort = 0;

    private bool isListening = false;

    protected ConcurrentDictionary<int, TaskCompletionSource<ScanResult>> taskSources = new ConcurrentDictionary<int, TaskCompletionSource<ScanResult>>();
    private CancellationTokenSource cts = new CancellationTokenSource();

    public delegate void ScanFinishedHandler(ScanResult result);
    public event ScanFinishedHandler ScanFinished;


    public Stopwatch stopwatch = Stopwatch.StartNew();

    protected BaseScanner(string interfaceName, IPAddress destinationIp, IPacketFactory headerFactory, int timeout)
    {
        var ip = GetIpOfInterface(interfaceName, destinationIp.AddressFamily, destinationIp.IsIPv6LinkLocal) ?? throw new Exception($"Could not find IPAddress of network interface ({interfaceName})");
        this.sourceEndPoint = new IPEndPoint(ip, SOURCE_PORT);

        this.destinationIp = destinationIp;
        this.packetFactory = headerFactory;
        this.interfaceName = interfaceName;
        this.timeout = timeout;
    }

    public void CreateSockets(){
        this.sendingSocket = CreateSendingSocket();
        this.receivingSocket = CreateReceivingSocket();
    }

    public abstract Socket CreateSendingSocket();

    public abstract Socket CreateReceivingSocket();

    protected abstract Packet? GetPacketFromBytes(byte[] responseBytes, ref IPEndPoint? remoteEndPoint);

    protected ICollection<int> GetScannedPortsCollection()
    {
        return taskSources.Keys;
    }

    protected void SetScanResult(ScanResult result)
    {
        lock(taskSources[result.Port])
        {
            if (!taskSources[result.Port].Task.IsCompleted)
            {
                taskSources[result.Port].SetResult(result);
                ScanFinished?.Invoke(result);
            }
        }
    }

    public IEnumerable<Task<ScanResult>> GetScanningTasks()
    {
        return this.taskSources.Select(e => e.Value.Task);
    }

    public virtual async Task<ScanResult> StartPortScanAsync(int port, bool retry = false)
    {
        //System.Console.WriteLine("Sending ." + port + $". time: {stopwatch.ElapsedMilliseconds}");
        if (sendingSocket is null || receivingSocket is null) throw new NullReferenceException("Sending socket cannot be null. Ensure CreateSockets() is called before ScanPort");
        lastScannedPort = port;

        if (isListening == false)
        {
           StartListening();
        }
  
        try
        {
            var packet = packetFactory.CreatePacket(sourceEndPoint, new IPEndPoint(destinationIp, port));
            //Port is set to 0, because for some reason it is the only thing that works always
            System.Console.WriteLine($"Scanning: .{port}. time: {stopwatch.ElapsedMilliseconds}");

            var tcs = new TaskCompletionSource<ScanResult>();
            if (this.taskSources.TryAdd(port, tcs) == false && retry == false)
            {
                throw new Exception($"Creating tcs for port .{port}. failed");
            }

            await sendingSocket.SendToAsync(packet, new IPEndPoint(destinationIp, 0));

            var completed = await Task.WhenAny(tcs.Task, Task.Delay(timeout));
            if (completed == tcs.Task)
            {
                return tcs.Task.Result;
            }
            else
            {
                return new ScanResult(port, PortState.Filtered);
            }
           

            // var cancellationTokenSource = new CancellationTokenSource(timeout);
            // cancellationTokenSource.Token.Register(() => {

            //     if (taskSources.ContainsKey(port))
            //     {
            //             if (taskSources[port].Task.IsCompleted)  
            //                 return;
                        
            //             HandleTimeout(port, retry);
            //     }
            // }, useSynchronizationContext: true);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            throw;
        }
        finally{
        }
    }

    public void StartListening()
    {
        isListening = true;
        byte[] buffer = new byte[1024];
        if (receivingSocket == null)
            return;
        int index = 0;
        new Thread(() => {
            while(isListening)
            {
                EndPoint endpoint = new IPEndPoint(IPAddress.Any, 0);
                int bytesCount = receivingSocket.ReceiveFrom(buffer, SocketFlags.None, ref endpoint);            

                IPEndPoint? ipEndPoint = endpoint as IPEndPoint;
                var packet = GetPacketFromBytes(buffer, ref ipEndPoint);
                if (packet is TcpPacket tcpPacket)
                {
                    lock (this.taskSources[tcpPacket.SourcePort])
                    {
                        System.Console.WriteLine($"Received TCP packet from port .{tcpPacket.SourcePort}. at time: {this.stopwatch.ElapsedMilliseconds}. Index: {index}");
                        var result = GetScanResultFromResponse(packet);
                        SetScanResult(result);
                    }
                }
                index++;
            }
        }).Start();
    }



    protected abstract void HandleTimeout(int port, bool retry);

    protected abstract ScanResult GetScanResultFromResponse(Packet packet);

    public virtual void Dispose()
    {
        if (isListening)
        {
            isListening = false;
        }
        sendingSocket?.Dispose();
        //receivingSocket?.Dispose();


    }
}
