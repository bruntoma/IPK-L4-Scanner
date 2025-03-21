using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner;
using IPK_L4_Scanner.Packets;

public class UdpScanner : BaseScanner
{

    protected int delayBetweenScans;

    public UdpScanner(string interfaceName, IPAddress destinationIp, int timeout = 5000, int delayBetweenScans = 1500) : base(interfaceName, destinationIp, new UdpPacketFactory(), timeout)
    {
        this.delayBetweenScans = delayBetweenScans;
    }

    public override ScanResult ScanPort(int port, bool retry = false)
    {
        var result = base.ScanPort(port, retry);
        Thread.Sleep(delayBetweenScans);
        return result;
    }

    public override Socket CreateReceivingSocket()
    {
        var protocolType = (destinationIp.AddressFamily == AddressFamily.InterNetwork) ? ProtocolType.Icmp : ProtocolType.IcmpV6;
        var receivingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, protocolType) { ReceiveTimeout = timeout};
        receivingSocket.Bind(new IPEndPoint(sourceEndPoint.Address, 0));
        return receivingSocket;
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

    protected override Packet? GetPacketFromBytes(byte[] responseBytes, IPEndPoint packetSourceEndpoint)
    {
            IcmpPacket? icmpPacket;
            IPPacket? ipPacket;
            if (packetSourceEndpoint.Address.AddressFamily == AddressFamily.InterNetwork)
            {
                ipPacket = IPv4Packet.FromBytes(responseBytes);
                if (ipPacket == null || ipPacket.SourceIp == null || ipPacket.DestinationIp == null) return null;
            }


            // Verify response is from the target IP
            if (!this.destinationIp.Equals(packetSourceEndpoint.Address)) return null;

            icmpPacket = IcmpPacket.FromBytes(responseBytes, this.sourceEndPoint.Address, this.destinationIp);

            var udpPacket = icmpPacket?.GetOriginalUdpPacket();
            if (udpPacket == null)
                return null;

            if (udpPacket.SourcePort != SOURCE_PORT || udpPacket.DestinationPort != lastScannedPort)
                return null;

            if (icmpPacket == null || icmpPacket.Code != 3 || icmpPacket.Type != 3)            
                return null;


            return icmpPacket;
    }

    protected override ScanResult GetScanResultFromResponse(byte[] response, Packet packet)
    {
        //We do not have to extract the original packet from ICMP packet to get port, because UDP scanning in sequential.
        var icmpPacket = packet as IcmpPacket;
        if (icmpPacket is null) { throw new NullReferenceException("Received packet is not a ICMP packet. Wrong packets should not be returned from GetPacketFromBytes");};

        if (icmpPacket.Type == 3)
        {
            return new ScanResult(lastScannedPort, PortState.Closed);
        }
        return new ScanResult(lastScannedPort, PortState.Open);
    }

    protected override ScanResult HandleTimeout(int port, bool retry)
    {
        return new ScanResult(port, PortState.Open);
    }
}