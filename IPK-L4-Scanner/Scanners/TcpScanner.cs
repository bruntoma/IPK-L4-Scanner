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
        if (remoteEndPoint == null)
        {
            return null;
        }

        TcpPacket? tcpHeader;
        tcpHeader = TcpPacket.FromBytes(responseBytes, this.sourceEndPoint.AddressFamily == AddressFamily.InterNetwork);

        if (tcpHeader == null )
        {
            return null;        
        }

        if (tcpHeader.DestinationPort != sourceEndPoint.Port)
        {
            return null;
        }
        
        if (!this.GetScannedPortsCollection().Contains(tcpHeader.SourcePort))
        {
            return null;
        }

        if (tcpHeader.IsSyn() && !(tcpHeader.IsAck() || tcpHeader.IsReset()))
        {
            return null;    
        }
        

        remoteEndPoint = new IPEndPoint(remoteEndPoint.Address, tcpHeader.SourcePort);
        return tcpHeader;
    }

    protected override async Task<ScanResult> HandleTimeout(int port, bool retry)
    {
        
        if (retry)
        {
                var result = new ScanResult(port, PortState.Filtered);
                SetScanResult(result);
                return result;
        }
        else
        {
            return await StartPortScanAsync(port, true);
        }
    }
}