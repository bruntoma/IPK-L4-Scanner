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

    public override async Task StartPortScanAsync(int port, bool retry = false)
    {
        await base.StartPortScanAsync(port, retry);
        await Task.Delay(1000);
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

    protected override IcmpPacket? GetPacketFromBytes(byte[] responseBytes, ref IPEndPoint? remoteEndPoint)
    {
            IcmpPacket? icmpPacket;
            if (remoteEndPoint == null)
                return null;

            // Verify response is from the target IP
            icmpPacket = IcmpPacket.FromBytes(responseBytes, remoteEndPoint.Address, this.destinationIp);

            var udpPacket = icmpPacket?.GetOriginalUdpPacket();

            if (udpPacket == null || udpPacket.SourcePort != SOURCE_PORT || this.taskSources.ContainsKey(udpPacket.DestinationPort) == false)
            {
                remoteEndPoint = null;
                return null;
            }

            if (icmpPacket == null || icmpPacket.Code != 3 || icmpPacket.Type != 3)            
            {
                remoteEndPoint = null;
                return null;
            }

            remoteEndPoint = new IPEndPoint(remoteEndPoint.Address, udpPacket.DestinationPort);
            return icmpPacket;
    }

    protected override ScanResult GetScanResultFromResponse(Packet packet)
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

    protected override async Task HandleTimeout(int port, bool retry)
    {
        this.taskSources[port].SetResult(new ScanResult(port, PortState.Open));
    }
}