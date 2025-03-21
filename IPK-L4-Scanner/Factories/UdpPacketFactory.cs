using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packets;

namespace IPK_L4_Scanner;

class UdpPacketFactory : IPacketFactory
{
    public byte[] CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint)
    {
        IPPacket ipHeader;
        if (sourceEndPoint.AddressFamily == AddressFamily.InterNetwork)
        {
            ipHeader = new IPv4Packet(sourceEndPoint.Address, destinationEndPoint.Address, ProtocolType.Udp);
        }
        else
        {
            ipHeader = new IPv6Packet(sourceEndPoint.Address, destinationEndPoint.Address, ProtocolType.Udp);
        }
        
        var udpHeader = new UdpPacket(ipHeader.SourceIp, ipHeader.DestinationIp, (ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port);
            
        if (ipHeader.Bytes == null || udpHeader.Bytes == null)  
        { 
            throw new Exception("Packet creation failed"); 
        }
        
        byte[] packet = new byte[ipHeader.Length + udpHeader.Length];
        Array.Copy(ipHeader.Bytes, 0, packet, 0, ipHeader.Length);
        Array.Copy(udpHeader.Bytes, 0, packet, ipHeader.Length, udpHeader.Length);
        
        return packet;
    }
}