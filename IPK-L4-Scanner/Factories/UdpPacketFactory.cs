using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packets;

namespace IPK_L4_Scanner;

class UdpPacketFactory : IPacketFactory
{
    public byte[] CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint)
    {        
        var udpHeader = new UdpPacket(sourceEndPoint.Address, destinationEndPoint.Address, (ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port);
        if (udpHeader.Bytes == null)  
        { 
            throw new Exception("Packet creation failed"); 
        }
        
        return udpHeader.Bytes;
    }
}