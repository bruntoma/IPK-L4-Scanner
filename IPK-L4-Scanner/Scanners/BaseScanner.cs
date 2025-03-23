using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using IPK_L4_Scanner.Packets;
using SharpPcap;
using SharpPcap.LibPcap;
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

    private LibPcapLiveDevice device;

    private string interfaceName;

    public SemaphoreSlim semaphoreSlim;


    public Stopwatch stopwatch = Stopwatch.StartNew();

    protected BaseScanner(string interfaceName, IPAddress destinationIp, IPacketFactory headerFactory, int timeout)
    {
        semaphoreSlim = new SemaphoreSlim(5000);
        var ip = GetIpOfInterface(interfaceName, destinationIp.AddressFamily, destinationIp.IsIPv6LinkLocal) ?? throw new Exception($"Could not find IPAddress of network interface ({interfaceName})");
        this.sourceEndPoint = new IPEndPoint(ip, SOURCE_PORT);

        this.destinationIp = destinationIp;
        this.packetFactory = headerFactory;
        this.timeout = timeout;
        this.interfaceName = interfaceName;
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
        if (retry == false)
        {
            await semaphoreSlim.WaitAsync();
        }

        //Debug.WriteLine($"Sending {port}");
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
                semaphoreSlim?.Release();
                return tcs.Task.Result;
            }
            else
            {
                semaphoreSlim?.Release(1);
                    
                var result =  await HandleTimeout(port, retry);
                return result;
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
                await receivingSocket.ReceiveMessageFromAsync(buffer, SocketFlags.None, endpoint);            

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
         

        // LibPcapLiveDevice? device = LibPcapLiveDeviceList.Instance.FirstOrDefault(device => device.Name.Contains(this.interfaceName));

        // if (device == null)
        // {
        //     throw new Exception("Device not found");
        // }

    

        // device.OnPacketArrival += (sender, capture) => {
        //     var buffer = capture.Data.ToArray();
        //     int headerSize = 0;

        //     // Create new buffer without the header
        //     buffer = buffer.Skip(14).ToArray();

        //     EndPoint endpoint = new IPEndPoint(IPAddress.Any, 0);
        //     IPEndPoint? ipEndPoint = endpoint as IPEndPoint;
        //     var packet = GetPacketFromBytes(buffer, ref ipEndPoint);

        //     if ((packet is IcmpPacket || packet is TcpPacket) && ipEndPoint != null)
        //     {
        //             var result = GetScanResultFromResponse(packet);
        //             SetScanResult(result);
        //     }
        // };

        // device.Open(DeviceModes.Promiscuous | DeviceModes.MaxResponsiveness);
        // device.Filter = $"tcp and src host {destinationIp} and dst port {sourceEndPoint.Port} and dst host {sourceEndPoint.Address}";

        // device.StartCapture();
    }

    private void a(object sender, PacketCapture e)
    {
        throw new NotImplementedException();
    }

    protected abstract Task<ScanResult> HandleTimeout(int port, bool retry);

    protected abstract ScanResult GetScanResultFromResponse(Packet packet);

    public virtual void Dispose()
    {
        
        listeningTcs?.Cancel();
        sendingSocket?.Dispose();
        receivingSocket?.Dispose();
        device?.StopCapture();
        device?.Dispose();
    }
}
