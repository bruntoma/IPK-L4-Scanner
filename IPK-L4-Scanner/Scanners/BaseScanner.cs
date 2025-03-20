using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packet;
using static IPK_L4_Scanner.NetworkExtensions;

namespace IPK_L4_Scanner;

public abstract class BaseScanner : IDisposable
{
    protected const int SOURCE_PORT = 258;
    protected static byte[] receiveBuffer = new byte[256];
    protected static EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

    protected Socket? sendingSocket = null;
    protected Socket? receivingSocket = null;
    protected IHeaderFactory packetFactory;
    protected IPEndPoint sourceEndPoint;
    protected IPAddress destinationIp;
    protected string interfaceName;
    protected int delayBetweenScans;

    protected int lastScannedPort = 0;

    protected BaseScanner(string interfaceName, IPAddress destinationIp, IHeaderFactory headerFactory)
    {
        var ip = GetIpOfInterface(interfaceName, destinationIp.AddressFamily) ?? throw new Exception($"Could not find IPAddress of network interface ({interfaceName})");
        this.sourceEndPoint = new IPEndPoint(ip, SOURCE_PORT);

        this.destinationIp = destinationIp;
        this.packetFactory = headerFactory;
        this.interfaceName = interfaceName;
    }

    public abstract void CreateSockets();

    protected abstract TcpPacket? GetPacketFromBytes(byte[] responseBytes, IPEndPoint destinationEndPoint);


    public ScanResult ScanPort(int port, bool retry = false)
    {
        if (sendingSocket is null || receivingSocket is null) throw new NullReferenceException("Sending socket cannot be null. Ensure CreateSockets() is called before ScanPort");

        lastScannedPort = port;
        var destinationEndPoint = new IPEndPoint(destinationIp, port);
        var receiveBytes = new byte[128];

        try
        {
            var packet = packetFactory.CreatePacket(sourceEndPoint, destinationEndPoint);
            sendingSocket.SendTo(packet, destinationEndPoint);

            EndPoint fromEndpoint = new IPEndPoint(destinationEndPoint.Address, port);
            TcpPacket? tcpHeader = null;
            while(tcpHeader == null)
            {
                int bytesReceived = receivingSocket.ReceiveFrom(receiveBytes, SocketFlags.None, ref fromEndpoint);
                tcpHeader = GetPacketFromBytes(receiveBytes, (IPEndPoint)fromEndpoint);
            }
            
            if (tcpHeader != null)
            {
                return GetScanResultFromResponse(receiveBytes, tcpHeader);
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
    }

    protected abstract ScanResult HandleTimeout(int port, bool retry);

    protected abstract ScanResult GetScanResultFromResponse(byte[] response, TcpPacket tcpHeader);

    public void Dispose()
    {
        sendingSocket?.Dispose();
        receivingSocket?.Dispose();
    }
}
