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
    protected int timeout;

    protected ConcurrentDictionary<int, TaskCompletionSource<ScanResult>> taskSources = new ConcurrentDictionary<int, TaskCompletionSource<ScanResult>>();
    private CancellationTokenSource? listeningTcs = null;

    public delegate void ScanFinishedHandler(ScanResult result);
    public event ScanFinishedHandler ScanFinished;


    public Stopwatch stopwatch = Stopwatch.StartNew();

    protected BaseScanner(string interfaceName, IPAddress destinationIp, IPacketFactory headerFactory, int timeout)
    {
        var ip = GetIpOfInterface(interfaceName, destinationIp.AddressFamily, destinationIp.IsIPv6LinkLocal) ?? throw new Exception($"Could not find IPAddress of network interface ({interfaceName})");
        this.sourceEndPoint = new IPEndPoint(ip, SOURCE_PORT);

        this.destinationIp = destinationIp;
        this.packetFactory = headerFactory;
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
        if (sendingSocket is null || receivingSocket is null) throw new NullReferenceException("Sending socket cannot be null. Ensure CreateSockets() is called before ScanPort");

        if (listeningTcs == null)
        {
            StartListening();
        }
  
        try
        {
            var tcs = new TaskCompletionSource<ScanResult>();
            if (this.taskSources.TryAdd(port, tcs) == false && retry == false)
            {
                throw new Exception($"Creating tcs for port .{port}. failed");
            }

            var packet = packetFactory.CreatePacket(sourceEndPoint, new IPEndPoint(destinationIp, port));
            await sendingSocket.SendToAsync(packet, new IPEndPoint(destinationIp, 0));

            var completed = await Task.WhenAny(tcs.Task, Task.Delay(timeout));
            if (completed == tcs.Task)
            {
                return tcs.Task.Result;
            }
            else
            {
                return await HandleTimeout(port, retry);
            }
        }
        catch (Exception ex)
        {
            throw new Exception("Error during starting port scan.", ex);
        }
    }

    public void StartListening()
    {
        listeningTcs = new CancellationTokenSource();

        byte[] buffer = new byte[1024];
        if (receivingSocket == null)
            return;
        int index = 0;
        new Task(async () => {
            while(!listeningTcs.IsCancellationRequested)
            {
                EndPoint endpoint = new IPEndPoint(IPAddress.Any, 0);

                if (!listeningTcs.IsCancellationRequested)
                {
                    await receivingSocket.ReceiveFromAsync(buffer, SocketFlags.None, endpoint);            
                }

                IPEndPoint? ipEndPoint = endpoint as IPEndPoint;
                var packet = GetPacketFromBytes(buffer, ref ipEndPoint);

                if ((packet is IcmpPacket || packet is TcpPacket) && ipEndPoint != null)
                {
                    lock (this.taskSources[ipEndPoint.Port])
                    {
                        var result = GetScanResultFromResponse(packet);
                        SetScanResult(result);
                    }
                }
                index++;
            }
        }, listeningTcs.Token).Start();
    }



    protected abstract Task<ScanResult> HandleTimeout(int port, bool retry);

    protected abstract ScanResult GetScanResultFromResponse(Packet packet);

    public virtual void Dispose()
    {
        
        listeningTcs?.Cancel();
        sendingSocket?.Dispose();
        receivingSocket?.Dispose();
    }
}
