using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packet;

namespace IPK_L4_Scanner;

class PacketFactory : IPacketFactory
{
    public byte[] CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint)
    {
        // Construct the IP header.
        if (sourceEndPoint.AddressFamily == AddressFamily.InterNetwork)
        {
            var ipHeader = new IPv4Packet(sourceEndPoint.Address, destinationEndPoint.Address, ProtocolType.Tcp);

            // Construct the TCP header.
            var tcpHeader = new TcpPacket(ipHeader.SourceIp, ipHeader.DestinationIp, (ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port, TcpFlags.SYN);

            if (ipHeader.Bytes == null || tcpHeader.Bytes == null) { throw new Exception("Packet creation failed"); }

            byte[] packet = new byte[40];
            Array.Copy(ipHeader.Bytes, 0, packet, 0, 20);
            Array.Copy(tcpHeader.Bytes, 0, packet, 20, 20);
            return packet;
        }
        else
        {
            var ipHeader = new IPv6Packet(sourceEndPoint.Address, destinationEndPoint.Address, ProtocolType.Tcp);

            // Construct the TCP header.
            var tcpHeader = new TcpPacket(ipHeader.SourceIp, ipHeader.DestinationIp, (ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port, TcpFlags.SYN);

            if (ipHeader.Bytes == null || tcpHeader.Bytes == null) { throw new Exception("Packet creation failed"); }

            byte[] packet = new byte[60];
            Array.Copy(ipHeader.Bytes, 0, packet, 0, 40);
            Array.Copy(tcpHeader.Bytes, 0, packet, 40, 20);
            return packet;
        }
    }
}