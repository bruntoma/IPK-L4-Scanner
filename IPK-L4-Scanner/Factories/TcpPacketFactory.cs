using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packets;

namespace IPK_L4_Scanner;

class TcpPacketFactory : IPacketFactory<TcpPacket>
{
    public virtual TcpPacket CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint)
    {
        var tcpHeader = new TcpPacket(sourceEndPoint.Address, destinationEndPoint.Address, (ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port, 0);
        if (tcpHeader.Bytes == null) 
        { 
            throw new Exception("Packet creation failed"); 
        }
        return tcpHeader;
    }
}