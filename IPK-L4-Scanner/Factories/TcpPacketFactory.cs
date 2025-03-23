using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packets;

namespace IPK_L4_Scanner;

class PacketFactory : IPacketFactory
{
    public byte[] CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint)
    {
        var tcpHeader = new TcpPacket(sourceEndPoint.Address, destinationEndPoint.Address, (ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port, TcpFlags.SYN);
        if (tcpHeader.Bytes == null) 
        { 
            throw new Exception("Packet creation failed"); 
        }
        return tcpHeader.Bytes;
    }
}