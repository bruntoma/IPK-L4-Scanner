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
    protected static EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

    protected Socket? sendingSocket = null;
    protected Socket? receivingSocket = null;
    protected IPacketFactory packetFactory;
    protected IPEndPoint sourceEndPoint;
    protected IPAddress destinationIp;
    protected string interfaceName;
    protected int timeout;

    protected int lastScannedPort = 0;

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

    protected abstract Packet? GetPacketFromBytes(byte[] responseBytes, IPEndPoint destinationEndPoint);


    public virtual ScanResult ScanPort(int port, bool retry = false)
    {
        TaskCompletionSource<Packet> receivedPacketTcs = new TaskCompletionSource<Packet>(timeout);
        var cts = new CancellationTokenSource(timeout);

        var task =  Task.Run(() => {
                 if (sendingSocket is null || receivingSocket is null) throw new NullReferenceException("Sending socket cannot be null. Ensure CreateSockets() is called before ScanPort");

                lastScannedPort = port;
                var destinationEndPoint = new IPEndPoint(destinationIp, port);
                var receiveBytes = new byte[128];

                try
                {
                    var packet = packetFactory.CreatePacket(sourceEndPoint, destinationEndPoint);
                    sendingSocket.SendTo(packet, destinationEndPoint);

                    EndPoint fromEndpoint = new IPEndPoint(IPAddress.Any, port);
                    Packet? receivedPacket = null;
                
                    while(receivedPacket == null)
                    {
                        int bytesReceived = receivingSocket.ReceiveFrom(receiveBytes, SocketFlags.None, ref fromEndpoint);
                        receivedPacket = GetPacketFromBytes(receiveBytes, (IPEndPoint)fromEndpoint);

                        if (cts.IsCancellationRequested)
                        {
                            return HandleTimeout(port, retry);
                        }
                    }
                    
                    if (receivedPacket != null)
                    {
                        return GetScanResultFromResponse(receiveBytes, receivedPacket);
                    }
                    else
                    {
                        return HandleTimeout(port, retry);
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    return HandleTimeout(port, retry);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                    throw;
                }

        }, cts.Token);

       return task.Result;
    }

    protected abstract ScanResult HandleTimeout(int port, bool retry);

    protected abstract ScanResult GetScanResultFromResponse(byte[] response, Packet packet);

    public virtual void Dispose()
    {
        sendingSocket?.Dispose();
        receivingSocket?.Dispose();
    }
}
