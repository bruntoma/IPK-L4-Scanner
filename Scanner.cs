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
        var ip = GetIpOfInterface(interfaceName, destinationIp.AddressFamily) ?? throw new Exception($"Could not find IPAddress of network interface ({interfaceName})");
        this.sourceEndPoint = new IPEndPoint(ip, SOURCE_PORT);

    
        //this.sendingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, System.Net.Sockets.ProtocolType.Raw);
        this.sendingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, System.Net.Sockets.ProtocolType.Raw);
        this.receivingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, System.Net.Sockets.ProtocolType.Tcp) { ReceiveTimeout = timeout};

        if (destinationIp.AddressFamily == AddressFamily.InterNetwork)
        {
            this.sendingSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        }


        this.receivingSocket.Bind(new IPEndPoint(sourceEndPoint.Address, 0));


        this.destinationIp = destinationIp;
        this.scannerType = scannerType;
        this.packetFactory = new PacketFactory();
        this.interfaceName = interfaceName;
        this.timeout = timeout;
        this.delayBetweenScans = delayBetweenScans;

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
            var packet = packetFactory.CreatePacket(ScannerProtocol.TCP, sourceEndPoint, destinationEndPoint);
            sendingSocket.SendTo(packet, destinationEndPoint);

            EndPoint fromEndpoint = new IPEndPoint(destinationEndPoint.Address, port);
            TcpPacket? tcpHeader = null;
            while(tcpHeader == null)
            {
                int bytesReceived = receivingSocket.ReceiveFrom(receiveBytes, SocketFlags.None, ref fromEndpoint);
                tcpHeader = GetTcpPacket(receiveBytes, (IPEndPoint)fromEndpoint);
            }
            
            if (tcpHeader != null)
            {
                return GetScanResultFromResponse(receiveBytes, tcpHeader);
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
    private TcpPacket? GetTcpPacket(byte[] responseBytes, IPEndPoint destinationEndPoint)
    {
        try
        {
            TcpPacket? tcpHeader;
            if (scannerType == ScannerProtocol.TCP)
            {
                IPPacket? ipHeader;
                if (destinationEndPoint.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    ipHeader = IPv4Packet.FromBytes(responseBytes);
                    if (ipHeader == null || ipHeader.SourceIp == null || ipHeader.DestinationIp == null) return null;

                    // Verify response is from the target IP
                    if (!ipHeader.SourceIp.Equals(destinationEndPoint.Address)) return null;

                    tcpHeader = TcpPacket.FromBytes(responseBytes, ipHeader.SourceIp, ipHeader.DestinationIp);

                } 
                else
                {
                    tcpHeader = TcpPacket.FromBytes(responseBytes, this.sourceEndPoint.Address, this.destinationIp);
                }
           

                if (tcpHeader == null) 
                    return null;
            

                if (tcpHeader.DestinationPort != SOURCE_PORT)
                    return null;

                if (tcpHeader.SourcePort != lastScannedPort)
                    return null;

                return tcpHeader;
            }
            else if (scannerType == ScannerProtocol.UDP)
            {
                throw new NotImplementedException("UDP not implemented");
            }

            return null;
        }
        catch
        {
            throw;
        }
    }

    private ScanResult GetScanResultFromResponse(byte[] response, TcpPacket tcpHeader)
    {

        if (this.scannerType == ScannerProtocol.TCP)
        {
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
