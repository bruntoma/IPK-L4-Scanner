using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packets;

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

    public delegate void ScanFinishedHandler(IPAddress target, ScanResult result);
    public event ScanFinishedHandler? ScanFinished;
    private SemaphoreSlim parallelScansSemaphore;
    private const int MAX_PARALLEL_SCANS = 15;

    public Stopwatch stopwatch = Stopwatch.StartNew();

    protected BaseScanner(string interfaceName, IPAddress destinationIp, IPacketFactory headerFactory, int timeout)
    {
        parallelScansSemaphore = new SemaphoreSlim(MAX_PARALLEL_SCANS);
        var ip = NetworkHelper.GetIpOfInterface(interfaceName, destinationIp.AddressFamily, destinationIp.IsIPv6LinkLocal) ?? throw new Exception($"Could not find IPAddress of selected network interface ({interfaceName})");
        this.sourceEndPoint = new IPEndPoint(ip, SOURCE_PORT);

        this.destinationIp = destinationIp;
        this.packetFactory = headerFactory;
        this.timeout = timeout;
    }

    public void CreateSockets(){
        this.sendingSocket = CreateSendingSocket();
        this.receivingSocket = CreateReceivingSocket();

        StartListening();
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
                ScanFinished?.Invoke(destinationIp, result);
            }
        }
    }

    public IEnumerable<Task<ScanResult>> GetScanningTasks()
    {
        return this.taskSources.Select(e => e.Value.Task);
    }

    public virtual async Task<ScanResult> StartPortScanAsync(int port, bool retry = false)
    {
        if (retry == false)
        {
          await parallelScansSemaphore.WaitAsync();
        }

        if (sendingSocket is null || receivingSocket is null) throw new NullReferenceException("Sending socket cannot be null. Ensure CreateSockets() is called before ScanPort");
  
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
                parallelScansSemaphore?.Release();
                return tcs.Task.Result;
            }
            else
            {
                parallelScansSemaphore?.Release();
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

        byte[] buffer = new byte[256];
        if (receivingSocket == null)
            return;


        new Task(async () => {
            while(!listeningTcs.IsCancellationRequested)
            {
                try {
                    EndPoint endpoint = new IPEndPoint(IPAddress.Any, 0);
                    await receivingSocket.ReceiveFromAsync(buffer, SocketFlags.None, endpoint); 
                    
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
                }
                catch (SocketException ex) when (
                    ex.SocketErrorCode == SocketError.OperationAborted || 
                    ex.SocketErrorCode == SocketError.Interrupted ||
                    ex.SocketErrorCode == SocketError.Shutdown)
                {
                    break;
                }
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
