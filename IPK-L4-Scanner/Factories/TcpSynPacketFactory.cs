using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packets;

namespace IPK_L4_Scanner;

class TcpSynPacketFactory : TcpPacketFactory
{
    public override TcpPacket CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint)
    {
        var tcpPacket = base.CreatePacket(sourceEndPoint, destinationEndPoint);
        tcpPacket.Flags = TcpFlags.SYN;
        
        return tcpPacket;
    }
}