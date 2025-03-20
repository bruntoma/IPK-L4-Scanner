using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Linq;

namespace IPK_L4_Scanner.Packets;

public class IPv4Packet : IPPacket
{
    private const byte DEFAULT_IPv4_Length = 20;

    public IPv4Packet(IPAddress source, IPAddress destination, ProtocolType protocolType) : base(source, destination, protocolType, DEFAULT_IPv4_Length)
    {
        this.Length = 20;
        this.Bytes = new byte[Length];
        this.Bytes[0] = 0x45; // Version and IHL
        this.Bytes[1] = 0x00; // DSCP/ECN
        this.Bytes[2] = 0x00; // Total length - 40
        this.Bytes[3] = 0x28; 
        this.Bytes[4] = 0x00; // Identification
        this.Bytes[5] = 0x00; 
        this.Bytes[6] = 0x40; // Flags and fragment offset
        this.Bytes[7] = 0x00; 
        this.Bytes[8] = 0x40; // TTL (64)
        this.Bytes[9] = (byte)protocolType; // Protocol

        Array.Copy(source.GetAddressBytes(), 0, this.Bytes, 12, 4);
        Array.Copy(destination.GetAddressBytes(), 0, this.Bytes, 16, 4);

        // Calculate checksum.
        ushort checksum = CalculateChecksum(this.Bytes, 0, 20);
        Bytes[10] = (byte)(checksum >> 8);
        Bytes[11] = (byte)(checksum & 0xFF);
    }

    public static IPPacket? FromBytes(byte[] packet)
    {
        byte protocolType = packet[9];
        IPAddress sourceAddress = new IPAddress(new byte[] { packet[12], packet[13], packet[14], packet[15] });
        IPAddress destinationAddress = new IPAddress(new byte[] { packet[16], packet[17], packet[18], packet[19] });
        return new IPv4Packet(sourceAddress, destinationAddress, (ProtocolType)protocolType);
    }
}