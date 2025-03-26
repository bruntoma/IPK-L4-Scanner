using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using IPK_L4_Scanner.Packets;

namespace IPK_L4_Scanner;

public abstract class BaseScanner : IDisposable
{
    protected const int DEFAULT_SOURCE_PORT = 44358;
    protected static byte[] receiveBuffer = new byte[256];

    protected Socket? sendingSocket = null;
    protected Socket? receivingSocket = null;
    protected IPacketFactory<Packet> packetFactory;
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

    protected BaseScanner(string interfaceName, IPAddress destinationIp, IPacketFactory<Packet> headerFactory, int timeout, int? sourcePort = 44358)
    {
        parallelScansSemaphore = new SemaphoreSlim(MAX_PARALLEL_SCANS);
        var ip = NetworkHelper.GetIpOfInterface(interfaceName, destinationIp.AddressFamily, destinationIp.IsIPv6LinkLocal) ?? throw new Exception($"Could not find IPAddress of selected network interface ({interfaceName})");

        //If no source port is specified, let OS choose.
        if (sourcePort == null)
        {
            sourcePort = GetRandomAvailablePort();
        }
                
        this.sourceEndPoint = new IPEndPoint(ip, sourcePort ?? DEFAULT_SOURCE_PORT);

        this.destinationIp = destinationIp;
        this.packetFactory = headerFactory;
        this.timeout = timeout;
    }

    public void CreateSockets(){
        this.sendingSocket = CreateSendingSocket();

        var endpoint = this.sendingSocket.LocalEndPoint as IPEndPoint;
        if (endpoint != null)
            this.sourceEndPoint = new IPEndPoint(endpoint.Address, sourceEndPoint.Port);
        
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

    protected async Task SetScanResult(ScanResult result)
    {
        if (!taskSources[result.Port].Task.IsCompleted)
        {
            lock(taskSources[result.Port])
            {
                
                    taskSources[result.Port].SetResult(result);
                    ScanFinished?.Invoke(destinationIp, result);
            }

            await SendLastPacket(result);
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

  
        try
        {
            var tcs = new TaskCompletionSource<ScanResult>();
            if (this.taskSources.TryAdd(port, tcs) == false && retry == false)
            {
                throw new Exception($"Creating tcs for port .{port}. failed");
            }


            var packet = packetFactory.CreatePacket(sourceEndPoint, new IPEndPoint(destinationIp, port));
            await SendPacketToDestination(packet);


            var completed = await Task.WhenAny(tcs.Task, Task.Delay(timeout));
            if (completed == tcs.Task)
            {
                parallelScansSemaphore?.Release();                
                return tcs.Task.Result;
            }
            else
            {
                parallelScansSemaphore?.Release();
                var result = await HandleTimeout(port, retry);
                //await SendLastPacket(result);
                return result;
            }
        }
        catch (Exception ex)
        {
            throw new Exception("Error during starting port scan.", ex);
        }
    }

    //Sends packet to destinationIp. The destination port is specified only in packet.
    protected async Task SendPacketToDestination(Packet packet)
    {
        if (sendingSocket is null || receivingSocket is null) throw new NullReferenceException("Sending socket cannot be null. Ensure CreateSockets() is called before SendPacketToDestination()");
        if (packet.Bytes == null) throw new NullReferenceException("Packet Bytes cannot be null when sending.");

        await sendingSocket.SendToAsync(packet.Bytes, new IPEndPoint(destinationIp, 0));
    }

    public void StartListening()
    {   
        listeningTcs = new CancellationTokenSource();

        byte[] buffer = new byte[256];
        if (receivingSocket == null)
            return;


        Task.Factory.StartNew(async() => {
            while(!listeningTcs.IsCancellationRequested)
            {
                try {
                    EndPoint endpoint = new IPEndPoint(IPAddress.Any, 0);
                    receivingSocket.ReceiveFrom(buffer, SocketFlags.None, ref endpoint); 
                    
                    IPEndPoint? ipEndPoint = endpoint as IPEndPoint;
                    var packet = GetPacketFromBytes(buffer, ref ipEndPoint);

                    if ((packet is IcmpPacket || packet is TcpPacket) && ipEndPoint != null)
                    {
                        //lock (this.taskSources[ipEndPoint.Port])
                        //{
                            var result = GetScanResultFromResponse(packet);
                            await SetScanResult(result);
                        //}
                    }
                }
                catch (SocketException ex) when (
                    ex.SocketErrorCode == SocketError.OperationAborted || 
                    ex.SocketErrorCode == SocketError.Interrupted ||
                    ex.SocketErrorCode == SocketError.Shutdown)
                {
                    break;
                }
                catch(Exception ex)
                {
                    System.Console.WriteLine("Exception occured: " + ex.Message);
                }
            }
        });
    }

    //Allows sending last packet after finishing scan (eg. TCP RST)
    protected virtual Task SendLastPacket(ScanResult result)
    {
        return Task.CompletedTask;
    }

    protected abstract Task<ScanResult> HandleTimeout(int port, bool retry);

    protected abstract ScanResult GetScanResultFromResponse(Packet packet);

    public virtual void Dispose()
    {
        listeningTcs?.Cancel();
        sendingSocket?.Dispose();
        receivingSocket?.Dispose();
    }

    private int? GetRandomAvailablePort()
    {
        Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        s.Bind(new IPEndPoint(IPAddress.Any, 0));
        var endpoint = s.LocalEndPoint as IPEndPoint;
        return endpoint?.Port;
    }


}
