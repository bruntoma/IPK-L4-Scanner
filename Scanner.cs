using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packet;
using static IPK_L4_Scanner.NetworkExtensions;

namespace IPK_L4_Scanner;

enum ScannerProtocol {
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

    public Scanner(string interfaceName, IPAddress destinationIp, ScannerProtocol scannerType, int timeout = 5000, int delayBetweenScans = 0)
    {
        this.sendingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, System.Net.Sockets.ProtocolType.Tcp);
        this.sendingSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        this.receivingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, System.Net.Sockets.ProtocolType.Tcp);

        this.destinationIp = destinationIp;
        this.scannerType = scannerType;
        this.packetFactory = new PacketFactory();
        this.interfaceName = interfaceName;
        this.timeout = timeout;
        this.delayBetweenScans = delayBetweenScans;

        var ip = GetIpOfInterface(interfaceName, destinationIp.AddressFamily) ?? throw new Exception($"Could not find IPAddress of netowrk interface ({interfaceName})");
        this.sourceEndPoint = new IPEndPoint(ip, SOURCE_PORT);
    }

    public void PrepareSocket()
    {
        this.receivingSocket.Bind(sourceEndPoint);
    }


    public ScanResult ScanPort(int port, bool retry = false)
    {
        var destinationEndPoint = new IPEndPoint(destinationIp, port);
        sendingSocket.SendTo(packetFactory.CreatePacket(scannerType, sourceEndPoint, destinationEndPoint), destinationEndPoint);

        var receiveBytes = new byte[128];
        //receivingSocket.Bind(sourceEndPoint);

        var receiveTask = Task.Run(() => 
        { 
            receivingSocket.Receive(receiveBytes); 
            Console.WriteLine("Received");
         });

        var timeoutTask = Task.Delay(timeout);

        if (Task.WaitAny(receiveTask, timeoutTask) == 0)
        {
            return GetScanResultFromResponse(receiveBytes); 
        }

        // if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
        // {
        //         return GetScanResultFromResponse(buffer);
        // }
        
        // if (retry == false)
        // {
        //     await ScanPort(port, true);
        // }
        return new ScanResult(port, PortState.Filtered);
    }

    private bool IsValidResponse(byte[] responseBytes, IPEndPoint destinationEndPoint)
    {
        try
            {
                var ipHeader = IpHeader.FromBytes(responseBytes);
                
                // Verify IP addresses match
                if (!ipHeader.DestinationIp.Equals(this.sourceEndPoint)) return false;
                if (!ipHeader.SourceIp.Equals(this.destinationIp)) return false;

                if (scannerType == ScannerProtocol.TCP)
                {
                    var tcpHeader = TcpHeader.FromBytes(responseBytes);
                    return tcpHeader.SourcePort == destinationEndPoint.Port;
                }
                else if (scannerType == ScannerProtocol.UDP)
                {
                    if (ipHeader.Protocol != (byte)ProtocolType.Icmp) return false;
                    
                    var icmpHeader = IcmpHeader.FromBytes(responseBytes, ipHeader.HeaderLength);
                    return icmpHeader.IsPortUnreachableError(destinationEndPoint.Port);
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
         var ipHeader = IpHeader.FromBytes(response);

            if (this.scannerType == ScannerProtocol.TCP)
            {
                var tcpHeader = TcpHeader.FromBytes(response);

                if ((tcpHeader.Flags & (byte)TcpFlags.RST) != 0)
                {
                    return new ScanResult(tcpHeader.SourcePort, PortState.Closed);
                }

                if ((tcpHeader.Flags & (byte)TcpFlags.ACK) != 0) 
                {
                    return new ScanResult(tcpHeader.SourcePort, PortState.Open);
                }
            }
            else // UDP
            {
               // return new ScanResult(tcpHeader.SourcePort,PortState.Filtered); // Only ICMP errors would validate, handled below
               throw new NotImplementedException();
            }
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        sendingSocket.Dispose();
    }
}
