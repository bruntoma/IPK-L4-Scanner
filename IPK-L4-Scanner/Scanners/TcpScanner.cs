using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner;
using IPK_L4_Scanner.Packets;

public class TcpScanner : BaseScanner
{

    public TcpScanner(string interfaceName, IPAddress destinationIp, int timeout = 5000) : base(interfaceName, destinationIp, new PacketFactory(), timeout)
    {

    }

    public override Socket CreateSendingSocket()
    {
        var sendingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, ProtocolType.Tcp);
        if (destinationIp.AddressFamily == AddressFamily.InterNetwork)
        {
            sendingSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, false);
        }


        return sendingSocket;
    }

    public override Socket CreateReceivingSocket()
    {
        var receivingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, ProtocolType.Tcp);
        receivingSocket.Bind(new IPEndPoint(sourceEndPoint.Address, 0));
        return receivingSocket;
    } 

    protected override ScanResult GetScanResultFromResponse(Packet packet)
    {
        var tcpHeader = packet as TcpPacket;
        if (tcpHeader is null) { throw new NullReferenceException("Received packet is not a TCP packet. Wrong packets should not be returned from GetPacketFromBytes");};

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

    protected override TcpPacket? GetPacketFromBytes(byte[] responseBytes, ref IPEndPoint? remoteEndPoint)
    {

        //TODO: DO NOT USE remoteEndPoint, it does not work!
            TcpPacket? tcpHeader;
            // IPPacket? ipHeader;

            // if (remoteEndPoint == null)
            //     return null;

            // if (remoteEndPoint.Address.AddressFamily == AddressFamily.InterNetwork)
            // {
            //     ipHeader = IPv4Packet.FromBytes(responseBytes);
            //     if (ipHeader == null || ipHeader.SourceIp == null || ipHeader.DestinationIp == null) 
            //     {
            //         return null;
            //     }

            //     // Verify response is from the target IP
            //     if (!ipHeader.SourceIp.Equals(this.destinationIp)) 
            //     {
            //         return null;
            //     }

            //     //Verify response is sent to the source ip
            //     if (!ipHeader.DestinationIp.Equals(this.sourceEndPoint.Address)) 
            //     {
            //         return null;
            //     }

            // }

            tcpHeader = TcpPacket.FromBytes(responseBytes, remoteEndPoint.Address, this.sourceEndPoint.Address);

            if (tcpHeader == null)
                return null;

            if (tcpHeader.DestinationPort != SOURCE_PORT)
                return null;


            
            //The response is from scanned port
            if (!this.GetScannedPortsCollection().Contains(tcpHeader.SourcePort))
            {
                System.Console.WriteLine($"Received but not contains: .{tcpHeader.SourcePort}. IsCompleted: {this.taskSources[tcpHeader.SourcePort].Task.IsCompleted}");
                return null;
            }

            //System.Console.WriteLine($"Received: .{tcpHeader.SourcePort}. IsCompleted: {this.taskSources[tcpHeader.SourcePort].Task.IsCompleted}");
            

            remoteEndPoint = new IPEndPoint(tcpHeader.SourceIp, tcpHeader.SourcePort);
            return tcpHeader;
    }

    protected override void HandleTimeout(int port, bool retry)
    {
        
        if (retry)
        {
                //System.Console.WriteLine($"Timeouted: .{port}., IsCompleted: {taskSources[port].Task.IsCompleted}, Retry: {retry}, Time: {stopwatch.ElapsedMilliseconds}, RESULT: FILTERED");
                SetScanResult(new ScanResult(port, PortState.Filtered));
        }
        else
        {
            //System.Console.WriteLine($"Timeouted: .{port}., IsCompleted: {taskSources[port].Task.IsCompleted}, Retry: {retry}, Time: {stopwatch.ElapsedMilliseconds}");
            StartPortScanAsync(port, true);
        }
    }
}