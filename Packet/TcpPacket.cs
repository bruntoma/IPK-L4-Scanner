using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace IPK_L4_Scanner.Packet;

[Flags]
public enum TcpFlags
{
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20
}

public class TcpPacket : Packet
{
    public ushort SourcePort { get; private set; }
    public ushort DestinationPort { get; private set; }
    public ushort Checksum { get; private set; }

    public IPPacket IpPacket {get; private set; }

    public TcpFlags Flags {get; private set;} = 0;

    public TcpPacket(IPPacket packet, ushort sourcePort, ushort destinationPort, TcpFlags flags = 0)
    {
        this.Flags = flags;
        this.SourcePort = sourcePort;
        this.DestinationPort = destinationPort;
        this.IpPacket = packet;

        this.Bytes = new byte[20];

        this.Bytes[0] = (byte)(sourcePort >> 8);
        this.Bytes[1] = (byte)(sourcePort & 0xFF);
        this.Bytes[2] = (byte)(destinationPort >> 8);
        this.Bytes[3] = (byte)(destinationPort & 0xFF);

        // Sequence number part 0
        this.Bytes[4] = 0x00;
        this.Bytes[5] = 0x00;
        this.Bytes[6] = 0x00;
        this.Bytes[7] = 0x01;

        // Acknowledgement number
        this.Bytes[8] = 0x00; 
        this.Bytes[9] = 0x00; 
        this.Bytes[10] = 0x00; 
        this.Bytes[11] = 0x00;

        // Data offset, reserved, flags
        this.Bytes[12] = 0b0101_0000; 

        // Flags (SYN)
        this.Bytes[13] = (byte)flags; 

        // Window size
        this.Bytes[14] = 0x00; 
        this.Bytes[15] = 0x00;

        // Checksum (to be calculated)
        this.Bytes[16] = 0x00; 
        this.Bytes[17] = 0x00; 

        // Urgent pointer
        this.Bytes[18] = 0x00; 
        this.Bytes[19] = 0x00;

         // Calculate checksum.
        byte[] pseudoHeader = CreatePseudoHeader(IpPacket.SourceIp, IpPacket.DestinationIp, 20);
        byte[] checksumData = new byte[pseudoHeader.Length + this.Bytes.Length];
        Array.Copy(pseudoHeader, 0, checksumData, 0, pseudoHeader.Length);
        Array.Copy(this.Bytes, 0, checksumData, pseudoHeader.Length, this.Bytes.Length);

        ushort checksum = CalculateChecksum(checksumData, 0, checksumData.Length);
        this.Bytes[16] = (byte)(checksum >> 8);
        this.Bytes[17] = (byte)(checksum & 0xFF);
    }

    private static byte[] CreatePseudoHeader(IPAddress sourceIp, IPAddress destinationIp, int tcpLength)
    {
        byte[] header = new byte[12];
        Array.Copy(sourceIp.GetAddressBytes(), 0, header, 0, 4);
        Array.Copy(destinationIp.GetAddressBytes(), 0, header, 4, 4);
        header[9] = 0x06; // Protocol (TCP)
        header[10] = (byte)(tcpLength >> 8);
        header[11] = (byte)(tcpLength & 0xFF);
        return header;
    }

    public static TcpPacket? FromBytes(byte[] packet, IPPacket ipPacket)
    {
        if (packet.Length < 40)
        {
            Console.WriteLine("Packet too short to parse TCP header.");
            return null;
        }

        int tcpHeaderOffset = 20; // ip header length
        ushort sourcePort = (ushort)((packet[tcpHeaderOffset] << 8) | packet[tcpHeaderOffset + 1]);
        ushort destinationPort = (ushort)((packet[tcpHeaderOffset + 2] << 8) | packet[tcpHeaderOffset + 3]);
        TcpFlags flags = (TcpFlags)packet[tcpHeaderOffset + 13];

        return new TcpPacket(ipPacket, sourcePort, destinationPort, flags);
    }

    public bool IsAck()
    {
        // SYN flag is the second bit (0x02 or 00000010)
        return Flags.HasFlag(TcpFlags.ACK);
    }

    public bool IsReset()
    {
        // RST flag is the fourth bit (0x04 or 00000100)
        return Flags.HasFlag(TcpFlags.RST);
    }
}
