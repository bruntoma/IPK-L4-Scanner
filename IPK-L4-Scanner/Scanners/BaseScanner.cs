using System.Collections.Concurrent;
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

    protected ConcurrentDictionary<int, TaskCompletionSource<ScanResult>> taskSources = new ConcurrentDictionary<int, TaskCompletionSource<ScanResult>>();

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

    public IEnumerable<Task<ScanResult>> GetScanningTasks()
    {
        return this.taskSources.Select(e => e.Value.Task);
    }

    public virtual async Task ScanPortAsync(int port, bool retry = false)
    {
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
            await sendingSocket.SendToAsync(packet, new IPEndPoint(destinationIp, 0));
            
            var tcs = new TaskCompletionSource<ScanResult>();
            this.taskSources.TryAdd(port, tcs);

            //do not await this
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
            Task.Delay(timeout).ContinueWith(async e => {
                if (taskSources.ContainsKey(port))
                {

                        if (taskSources[port].Task.IsCompleted) 
                        {
                            return;
                        }

                        if (retry == false)
                        {
                            
                            if (retry)
                            {

                                this.taskSources[port].SetResult(new ScanResult(port, PortState.Filtered));
                                //this.taskSources.TryRemove(port, out _);                            
                            }
                            else
                            {
                                //this.taskSources.TryRemove(port, out _);          
                                this.taskSources[port].SetResult(new ScanResult(port, PortState.Closed));

                                ScanPortAsync(port, true);
                            }
                        }
                        //return await HandleTimeout(port, retry);
                }
                //await HandleTimeout(port, retry);
            });
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
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
                if (remoteEndPoint != null && receivedPacket != null)
                {
                    lock(this.taskSources[remoteEndPoint.Port])
                    {
                        if (!this.taskSources[remoteEndPoint.Port].Task.IsCompleted)
                        {
                            //System.Console.WriteLine($"RECEIVED: {remoteEndPoint.Port}");
                            var result = GetScanResultFromResponse(receivedPacket);
                            taskSources[remoteEndPoint.Port].SetResult(result);
                        }
                    }
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


    protected abstract Task HandleTimeout(int port, bool retry);

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
