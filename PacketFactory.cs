using System.Net;
using System.Net.Sockets;
using IPK_L4_Scanner.Packet;

namespace IPK_L4_Scanner;

class PacketFactory 
{
    public byte[] CreatePacket(ScannerProtocol protocolType, IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint)
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
            // var packet = new PacketDotNet.IPv6Packet(sourceEndPoint.Address, destinationEndPoint.Address);
            // var tcp = new PacketDotNet.TcpPacket((ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port);
            // tcp.Synchronize = true;
            // packet.PayloadPacket = tcp;

            // tcp.UpdateTcpChecksum();

            // return packet.Bytes;

            var ipHeader = new IPv6Packet(sourceEndPoint.Address, destinationEndPoint.Address, ProtocolType.Tcp);

            // Construct the TCP header.
            var tcpHeader = new TcpPacket(ipHeader.SourceIp, ipHeader.DestinationIp, (ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port, TcpFlags.SYN);

            if (ipHeader.Bytes == null || tcpHeader.Bytes == null) { throw new Exception("Packet creation failed"); }

            byte[] packet = new byte[60];
            Array.Copy(ipHeader.Bytes, 0, packet, 0, 40);
            Array.Copy(tcpHeader.Bytes, 0, packet, 40, 20);
            return packet;
        }

        // var ipHeader = new IpHeader(sourceEndPoint.Address, destinationEndPoint.Address){
        //     TotalLength = (ushort)(20 + 20), // IP header + TCP header
        //     Protocol = 6, // TCP
        //     TimeToLive = 128
        // };
        // var tcpHeader = new TcpHeader((ushort)sourceEndPoint.Port, (ushort)destinationEndPoint.Port) 
        // { 
        //     IpHeader = ipHeader,
        //     SequenceNumber = 123456,
        //     Flags = (byte)TcpFlags.SYN
        // };
        // tcpHeader.SetFlag(TcpFlags.SYN);

        // //ipHeader.UpdateChecksum();
        // tcpHeader.UpdateChecksum();

        // // Build final packet
        // var ipBytes = ipHeader.ToBytes();
        // var tcpBytes = tcpHeader.ToBytes();
        // var packet = new byte[ipBytes.Length + tcpBytes.Length];
        // Buffer.BlockCopy(ipBytes, 0, packet, 0, ipBytes.Length);
        // Buffer.BlockCopy(tcpBytes, 0, packet, ipBytes.Length, tcpBytes.Length);

        return null;
    }
}