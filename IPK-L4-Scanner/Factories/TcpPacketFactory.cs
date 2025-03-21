using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packets;

namespace IPK_L4_Scanner;

class PacketFactory : IPacketFactory
{
    public byte[] CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint)
    {
        IPPacket ipHeader;
        if (sourceEndPoint.AddressFamily == AddressFamily.InterNetwork)
        {
            ipHeader = new IPv4Packet(sourceEndPoint.Address, destinationEndPoint.Address, ProtocolType.Tcp);            
        }
        else
        {
            ipHeader = new IPv6Packet(sourceEndPoint.Address, destinationEndPoint.Address, ProtocolType.Tcp); 
        }

        var tcpHeader = new TcpPacket(ipHeader.SourceIp, ipHeader.DestinationIp, (ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port, TcpFlags.SYN);
        if (ipHeader.Bytes == null || tcpHeader.Bytes == null) 
        { 
            throw new Exception("Packet creation failed"); 
        }

        byte[] packet = new byte[ipHeader.Length + tcpHeader.Length];
        Array.Copy(ipHeader.Bytes, 0, packet, 0, ipHeader.Length);
        Array.Copy(tcpHeader.Bytes, 0, packet, ipHeader.Length, tcpHeader.Length);
        return packet;
    }
}