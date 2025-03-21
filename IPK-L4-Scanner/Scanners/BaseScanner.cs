using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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

    private SocketAsyncEventArgs receiveEventArgs;

    private bool isListening = false;

    protected Dictionary<int, TaskCompletionSource<Packet>> taskSources = new Dictionary<int, TaskCompletionSource<Packet>>();

    protected BaseScanner(string interfaceName, IPAddress destinationIp, IPacketFactory headerFactory, int timeout)
    {
        var ip = GetIpOfInterface(interfaceName, destinationIp.AddressFamily) ?? throw new Exception($"Could not find IPAddress of network interface ({interfaceName})");
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

    public virtual async Task<ScanResult> ScanPortAsync(int port, bool retry = false)
    {
        if (sendingSocket is null || receivingSocket is null) throw new NullReferenceException("Sending socket cannot be null. Ensure CreateSockets() is called before ScanPort");
        lastScannedPort = port;

        if (isListening == false)
        {
            StartListening();
        }
  
        try
        {
            System.Console.WriteLine($"\nSENDING {port}");
            var destinationEndPoint = new IPEndPoint(destinationIp, port);
            var packet = packetFactory.CreatePacket(sourceEndPoint, destinationEndPoint);
            await sendingSocket.SendToAsync(packet, destinationEndPoint);

            
            var tcs = new TaskCompletionSource<Packet>();
            this.taskSources.Add(port, tcs);

            Task timeoutTask = Task.Delay(timeout);
            Task completedTask = await Task.WhenAny(tcs.Task, timeoutTask);

            await completedTask;
            if (completedTask == timeoutTask)
                throw new TimeoutException();

            System.Console.WriteLine($"PROCESSING: {port}");

            var res =  GetScanResultFromResponse(tcs.Task.Result);
            System.Console.WriteLine($"RESULT: {res.Port}");
            return res;
        }
        catch(TimeoutException ex)
        {
            System.Console.WriteLine($"TIMEOUT: {port}");
            this.taskSources.Remove(port);
            return await HandleTimeout(port, retry);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
            System.Console.WriteLine($"TIMEOUT: {port}");
            this.taskSources.Remove(port);
            return await HandleTimeout(port, retry);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            throw;
        }
    }

    public void StartListening()
    {
        // Configure the SocketAsyncEventArgs
        receiveEventArgs = new SocketAsyncEventArgs();
        receiveEventArgs.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

        byte[] buffer = new byte[1024];
        receiveEventArgs.SetBuffer(buffer, 0, buffer.Length);
        receiveEventArgs.Completed += OnPacketReceived;
        isListening = true;

        GetNextPacket();
    }

    private void GetNextPacket()
    {
        if (receivingSocket == null) throw new NullReferenceException("Receiving socket cannot be null");

        try
        {
            // Reset remote endpoint before each receive
            receiveEventArgs.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            
            // If ReceiveFromAsync returns false, it completed synchronously
            // and the event won't be raised, so we need to handle it directly
            bool pendingAsync = receivingSocket.ReceiveFromAsync(receiveEventArgs);
            if (!pendingAsync)
            {
                OnPacketReceived(receivingSocket, receiveEventArgs);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error starting receive: {ex.Message}");
        }
    }

    private void OnPacketReceived(object? sender, SocketAsyncEventArgs e)
    {
         if (e.SocketError == SocketError.Success && e.BytesTransferred > 0)
        {
            if (e.Buffer != null)
            {
                IPEndPoint? remoteEndPoint = e.RemoteEndPoint as IPEndPoint;
                var receivedPacket = GetPacketFromBytes(e.Buffer, ref remoteEndPoint);
                if (remoteEndPoint != null && receivedPacket != null && this.taskSources.ContainsKey(remoteEndPoint.Port))
                {
                    System.Console.WriteLine($"RECEIVED: {remoteEndPoint.Port}");
                    taskSources[remoteEndPoint.Port].SetResult(receivedPacket);
                }
            }
            
            // Start the next receive operation
            GetNextPacket();
        }
        else if (e.SocketError != SocketError.Success)
        {
            Console.WriteLine($"Socket error: {e.SocketError}");
            // Optionally restart or clean up
        }
    }



















    // public virtual ScanResult ScanPort(int port, bool retry = false)
    // {
    //     TaskCompletionSource<Packet> receivedPacketTcs = new TaskCompletionSource<Packet>(timeout);
    //     var cts = new CancellationTokenSource(timeout);

    //     var task =  Task.Run(() => {
    //             if (sendingSocket is null || receivingSocket is null) throw new NullReferenceException("Sending socket cannot be null. Ensure CreateSockets() is called before ScanPort");

    //             lastScannedPort = port;
    //             var destinationEndPoint = new IPEndPoint(destinationIp, port);

    //             try
    //             {
    //                 var packet = packetFactory.CreatePacket(sourceEndPoint, destinationEndPoint);
    //                 sendingSocket.SendTo(packet, destinationEndPoint);

    //                 EndPoint fromEndpoint = new IPEndPoint(IPAddress.Any, port);
    //                 Packet? receivedPacket = null;


    //                 var receiveBytes = new byte[128];
    //                 while(receivedPacket == null)
    //                 {
    //                     int bytesReceived = receivingSocket.ReceiveFrom(receiveBytes, SocketFlags.None, ref fromEndpoint);
    //                     receivedPacket = GetPacketFromBytes(receiveBytes, (IPEndPoint)fromEndpoint);

    //                     if (cts.IsCancellationRequested)
    //                     {
    //                         return HandleTimeout(port, retry);
    //                     }
    //                 }
                    
    //                 if (receivedPacket != null)
    //                 {
    //                     return GetScanResultFromResponse(receiveBytes, receivedPacket);
    //                 }
    //                 else
    //                 {
    //                     return HandleTimeout(port, retry);
    //                 }
    //             }
    //             catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
    //             {
    //                 return HandleTimeout(port, retry);
    //             }
    //             catch (Exception ex)
    //             {
    //                 Console.WriteLine("Error: " + ex.Message);
    //                 throw;
    //             }

    //     }, cts.Token);

    //    return task.Result;
    // }

    protected abstract Task<ScanResult> HandleTimeout(int port, bool retry);

    protected abstract ScanResult GetScanResultFromResponse(Packet packet);

    public virtual void Dispose()
    {
        sendingSocket?.Dispose();
        receivingSocket?.Dispose();

        if (isListening)
        {
            isListening = false;
        }
    }
}
