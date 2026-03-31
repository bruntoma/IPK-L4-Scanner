using System;
using System.Net;
using System.Net.Sockets;

namespace IPK_L4_Scanner.Packets;

public class UdpPacket : Packet
{
    public ushort SourcePort { get; private set; }
    public ushort DestinationPort { get; private set; }
    public ushort Checksum { get; private set; }

    public IPAddress SourceIp { get; private set; }
    public IPAddress DestinationIp { get; private set; }


    public UdpPacket(IPAddress sourceIp, IPAddress destinationIp, ushort sourcePort, ushort destinationPort) 
        : base(Packet.DEFAULT_UDP_Length)
    {
        this.SourceIp = sourceIp;
        this.DestinationIp = destinationIp;
        this.SourcePort = sourcePort;
        this.DestinationPort = destinationPort;

        this.Bytes = new byte[Packet.DEFAULT_UDP_Length];

        // Source port
        this.Bytes[0] = (byte)(sourcePort >> 8);
        this.Bytes[1] = (byte)(sourcePort & 0xFF);
        
        // Destination port
        this.Bytes[2] = (byte)(destinationPort >> 8);
        this.Bytes[3] = (byte)(destinationPort & 0xFF);
        
        // Length (8 bytes for header, no data)
        this.Bytes[4] = 0;
        this.Bytes[5] = 8;
        
        // Checksum (initially zero)
        this.Bytes[6] = 0;
        this.Bytes[7] = 0;

        // Calculate checksum
        byte[] pseudoHeader = CreatePseudoHeader(SourceIp, DestinationIp, 8);
        byte[] checksumData = new byte[pseudoHeader.Length + this.Bytes.Length];
        Array.Copy(pseudoHeader, 0, checksumData, 0, pseudoHeader.Length);
        Array.Copy(this.Bytes, 0, checksumData, pseudoHeader.Length, this.Bytes.Length);

        ushort checksum = CalculateChecksum(checksumData, 0, checksumData.Length);
        this.Bytes[6] = (byte)(checksum >> 8);
        this.Bytes[7] = (byte)(checksum & 0xFF);
    }

    private static byte[] CreatePseudoHeader(IPAddress sourceIp, IPAddress destinationIp, int udpLength)
    {
        // Check address family to determine if IPv4 or IPv6
        if (sourceIp.AddressFamily == AddressFamily.InterNetwork)
        {
            // IPv4 pseudo-header (12 bytes)
            byte[] header = new byte[12];
            Array.Copy(sourceIp.GetAddressBytes(), 0, header, 0, 4);
            Array.Copy(destinationIp.GetAddressBytes(), 0, header, 4, 4);
            header[8] = 0; // Zero padding
            header[9] = 17; // Protocol (UDP is 17)
            header[10] = (byte)(udpLength >> 8);    // UDP length (high byte)
            header[11] = (byte)(udpLength & 0xFF);  // UDP length (low byte)
            return header;
        }
        else
        {
            // IPv6 pseudo-header (40 bytes)
            byte[] header = new byte[40];
            byte[] srcBytes = sourceIp.GetAddressBytes();
            byte[] dstBytes = destinationIp.GetAddressBytes();
            
            // Source address (16 bytes)
            Array.Copy(srcBytes, 0, header, 0, 16);
            
            // Destination address (16 bytes)
            Array.Copy(dstBytes, 0, header, 16, 16);
            
            // UDP length (4 bytes, upper 2 bytes are 0)
            header[32] = 0;
            header[33] = 0;
            header[34] = (byte)(udpLength >> 8);
            header[35] = (byte)(udpLength & 0xFF);
            
            // Zeros (3 bytes)
            header[36] = 0;
            header[37] = 0;
            header[38] = 0;
            
            // Next Header (1 byte)
            header[39] = 17; // UDP
            
            return header;
        }
    }

    public static UdpPacket? FromBytes(byte[] packet, IPAddress sourceIp, IPAddress destinationIp)
    {
        if (packet.Length < DEFAULT_IPv4_Length + DEFAULT_UDP_Length)
        {
            Console.WriteLine("Packet too short to parse UDP header.");
            return null;
        }
        
        int udpHeaderOffset = (sourceIp.AddressFamily == AddressFamily.InterNetwork) ? Packet.DEFAULT_IPv4_Length : Packet.DEFAULT_IPv6_Length;
        ushort sourcePort = (ushort)((packet[udpHeaderOffset] << 8) | packet[udpHeaderOffset + 1]);
        ushort destinationPort = (ushort)((packet[udpHeaderOffset + 2] << 8) | packet[udpHeaderOffset + 3]);

        return new UdpPacket(sourceIp, destinationIp, sourcePort, destinationPort);
    }
}