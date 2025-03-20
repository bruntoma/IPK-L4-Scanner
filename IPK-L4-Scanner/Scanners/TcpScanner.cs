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
        var sendingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, ProtocolType.Raw);
        if (destinationIp.AddressFamily == AddressFamily.InterNetwork)
        {
            sendingSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        }
        return sendingSocket;
    }

    public override Socket CreateReceivingSocket()
    {
        var receivingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, ProtocolType.Tcp) { ReceiveTimeout = timeout};
        receivingSocket.Bind(new IPEndPoint(sourceEndPoint.Address, 0));
        return receivingSocket;
    } 

    protected override ScanResult GetScanResultFromResponse(byte[] response, Packet packet)
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

    protected override TcpPacket? GetPacketFromBytes(byte[] responseBytes, IPEndPoint destinationEndPoint)
    {
            TcpPacket? tcpHeader;
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

    protected override ScanResult HandleTimeout(int port, bool retry)
    {
        if (retry)
            return new ScanResult(port, PortState.Filtered);
        else
            return ScanPort(port, true);    
    }


}