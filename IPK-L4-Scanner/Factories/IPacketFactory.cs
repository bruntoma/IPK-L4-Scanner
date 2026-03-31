using System.Net;
using IPK_L4_Scanner.Packets;

public interface IPacketFactory<out TPacket> where TPacket : Packet {
    TPacket CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint);
}



