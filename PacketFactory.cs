using System.Net;
using IPK_L4_Scanner.Packet;

namespace IPK_L4_Scanner;

class PacketFactory 
{
    public byte[] CreatePacket(ScannerProtocol protocolType, IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint)
    {
        var ipHeader = new IpHeader(sourceEndPoint.Address, destinationEndPoint.Address){
            TotalLength = (ushort)(20 + 20), // IP header + TCP header
            Protocol = 6, // TCP
            TimeToLive = 128
        };
        var tcpHeader = new TcpHeader((ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port) 
        { 
            IpHeader = ipHeader,
            SequenceNumber = 123456,
            Flags = (byte)TcpFlags.SYN
        };
        tcpHeader.SetFlag(TcpFlags.SYN);

        //ipHeader.UpdateChecksum();
        tcpHeader.UpdateChecksum();

        // Build final packet
        var ipBytes = ipHeader.ToBytes();
        var tcpBytes = tcpHeader.ToBytes();
        var packet = new byte[ipBytes.Length + tcpBytes.Length];
        Buffer.BlockCopy(ipBytes, 0, packet, 0, ipBytes.Length);
        Buffer.BlockCopy(tcpBytes, 0, packet, ipBytes.Length, tcpBytes.Length);

        return packet;
    }
}