using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packet;
using static IPK_L4_Scanner.NetworkExtensions;

namespace IPK_L4_Scanner;

enum ScannerProtocol
{
    TCP,
    UDP
}

class Scanner : IDisposable
{
    private const int SOURCE_PORT = 258;
    private static byte[] receiveBuffer = new byte[256];
    private static EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

    private Socket sendingSocket;
    private Socket receivingSocket;
    private PacketFactory packetFactory;
    private IPEndPoint sourceEndPoint;
    private IPAddress destinationIp;
    private ScannerProtocol scannerType;
    private string interfaceName;
    private int timeout;
    private int delayBetweenScans;

    private int lastScannedPort;

    public Scanner(string interfaceName, IPAddress destinationIp, ScannerProtocol scannerType, int timeout = 5000, int delayBetweenScans = 0)
    {
        var ip = GetIpOfInterface(interfaceName, destinationIp.AddressFamily) ?? throw new Exception($"Could not find IPAddress of netowrk interface ({interfaceName})");
        this.sourceEndPoint = new IPEndPoint(ip, SOURCE_PORT);

        this.sendingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, System.Net.Sockets.ProtocolType.Tcp);
        this.sendingSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        this.receivingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, System.Net.Sockets.ProtocolType.Tcp);
        this.receivingSocket.ReceiveTimeout = timeout;

        this.destinationIp = destinationIp;
        this.scannerType = scannerType;
        this.packetFactory = new PacketFactory();
        this.interfaceName = interfaceName;
        this.timeout = timeout;
        this.delayBetweenScans = delayBetweenScans;

        this.receivingSocket.Bind(sourceEndPoint);
    }

    public void PrepareSocket()
    {
    }


    public ScanResult ScanPort(int port, bool retry = false)
    {
        lastScannedPort = port;
        var destinationEndPoint = new IPEndPoint(destinationIp, port);
        var receiveBytes = new byte[128];

        try
        {
            sendingSocket.SendTo(packetFactory.CreatePacket(ScannerProtocol.TCP, sourceEndPoint, destinationEndPoint), destinationEndPoint);

            bool valid = false;
            while(!valid)
            {
                int bytesReceived = receivingSocket.Receive(receiveBytes);
                valid = IsValidResponse(receiveBytes, destinationEndPoint);
            }
            
            if (valid)
            {
                return GetScanResultFromResponse(receiveBytes);
            }
            else
            {
                return RetryOrFiltered(port, retry);
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
            return RetryOrFiltered(port, retry);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            throw;
        }
    }

    private ScanResult RetryOrFiltered(int port, bool retry)
    {
        if (retry)
            return new ScanResult(port, PortState.Filtered);
        else
            return ScanPort(port, true);
    }
    private bool IsValidResponse(byte[] responseBytes, IPEndPoint destinationEndPoint)
    {
        try
        {
            var ipHeader = IPv4Packet.FromBytes(responseBytes);
            if (ipHeader == null) return false;

            // Verify response is from the target IP
            if (!ipHeader.SourceIp.Equals(destinationEndPoint.Address))
                return false;

            if (scannerType == ScannerProtocol.TCP)
            {
                var tcpHeader = TcpPacket.FromBytes(responseBytes, ipHeader);
                if (tcpHeader == null) return false;

                // Check destination port matches our source port
                if (tcpHeader.DestinationPort != SOURCE_PORT)
                    return false;

                // Check source port matches the scanned port
                if (tcpHeader.SourcePort != lastScannedPort)
                    return false;

                return true;
            }
            else if (scannerType == ScannerProtocol.UDP)
            {
                throw new NotImplementedException("UDP not implemented");
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private ScanResult GetScanResultFromResponse(byte[] response)
    {
        var ipHeader = IPv4Packet.FromBytes(response) ?? throw new Exception("Invalid ip header");

        if (this.scannerType == ScannerProtocol.TCP)
        {
            var tcpHeader = TcpPacket.FromBytes(response, ipHeader) ?? throw new Exception("Invalid tcp header");

            if (tcpHeader.IsReset())
            {
                return new ScanResult(tcpHeader.SourcePort, PortState.Closed);
            }

            if (tcpHeader.IsAck())
            {
                return new ScanResult(tcpHeader.SourcePort, PortState.Open);
            }
            throw new Exception("Invalid response received");
        }
        else // UDP
        {
            // return new ScanResult(tcpHeader.SourcePort,PortState.Filtered);
            throw new NotImplementedException();
        }
    }

    public void Dispose()
    {
        sendingSocket.Dispose();
    }
}
