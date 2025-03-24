using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner;
using IPK_L4_Scanner.Packets;

public class UdpScanner : BaseScanner
{
    private SemaphoreSlim rateLimitSemaphore = new(0);
    private int packetsPerSecond;
    private Timer rateLimitTimer;

    public UdpScanner(string interfaceName, IPAddress destinationIp, int timeout = 5000, int packetsPerSecond = 1) : base(interfaceName, destinationIp, new UdpPacketFactory(), timeout)
    {

        int period = 1000 / packetsPerSecond;

        //Releases semaphore in intervals
        rateLimitTimer = new Timer(_ => { 
            //System.Console.WriteLine("Releasing semaphore");
            rateLimitSemaphore.Release(); 
        }, null, 0, period);
    }

    public override async Task<ScanResult> StartPortScanAsync(int port, bool retry = false)
    {
        //System.Console.WriteLine("WAITING SEMAPHORE");
        await rateLimitSemaphore.WaitAsync();
        //System.Console.WriteLine("STARTING SCAN");
        var result = await base.StartPortScanAsync(port, retry);

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
        var sendingSocket = new Socket(destinationIp.AddressFamily, SocketType.Raw, ProtocolType.Udp);
        if (destinationIp.AddressFamily == AddressFamily.InterNetwork)
        {
           // sendingSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        }
        return sendingSocket;
    }

    protected override IcmpPacket? GetPacketFromBytes(byte[] responseBytes, ref IPEndPoint? remoteEndPoint)
    {
            if (remoteEndPoint == null)
                return null;

            IcmpPacket? icmpPacket = IcmpPacket.FromBytes(responseBytes, remoteEndPoint.Address, this.sourceEndPoint.Address);
            var udpPacket = icmpPacket?.GetOriginalUdpPacket();

            if (udpPacket == null || udpPacket.SourcePort != this.sourceEndPoint.Port || !this.GetScannedPortsCollection().Contains(udpPacket.DestinationPort))
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

        var udpPacket = icmpPacket.GetOriginalUdpPacket();
        if (udpPacket == null)
            throw new NullReferenceException("UdpPacket cannot be null. If an ICMP packet has no copy of UDP packet, it should not pass through GetPacketFromBytes.");

        if (icmpPacket.Type == 3)
        {
            return new ScanResult(udpPacket.DestinationPort, PortState.Closed);
        }
        return new ScanResult(udpPacket.DestinationPort, PortState.Open);
    }

    protected override Task<ScanResult> HandleTimeout(int port, bool retry)
    {
        var result = new ScanResult(port, PortState.Open);
        SetScanResult(result);
        return Task.FromResult<ScanResult>(result);
    }
}